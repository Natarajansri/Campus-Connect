"use strict";

/**
 * Secure item chat.
 *
 * Chat documents are deterministic: chats/{itemId}_{claimantUid}. They are
 * created only by Cloud Functions after a claim is approved, and messages are
 * written only by the sendChatMessage callable so the rate limit, suspension
 * check and debounced push cannot be bypassed by a modified browser.
 *
 * Staff may read a chat for moderation but are not participants: they cannot
 * send messages unless they are the item reporter or the claimant.
 */

const { onCall, HttpsError } = require("firebase-functions/v2/https");

const {
  db,
  FieldValue,
  clampString,
  isSafeId,
  assertVerified,
  getUserProfile,
  consumeRateLimit,
  queueNotification,
  writeAudit,
} = require("./helpers");

const CALLABLE_OPTIONS = {
  // App Check is enforced in production. The emulator sets FUNCTIONS_EMULATOR
  // so local tests can exercise the callable without a real reCAPTCHA token.
  enforceAppCheck: process.env.FUNCTIONS_EMULATOR !== "true",
};

const CHAT_ID_RE = /^[A-Za-z0-9_-]{3,260}$/;
const MAX_CHAT_TEXT = 1000;
const MESSAGE_LIMIT = 10;
const MESSAGE_WINDOW_MS = 60 * 1000;
const PUSH_DEBOUNCE_MS = 2 * 60 * 1000;
const REPORT_LIMIT = 5;
const REPORT_WINDOW_MS = 60 * 60 * 1000;

function chatIdFor(itemId, claimantUid) {
  return `${itemId}_${claimantUid}`;
}

function isParticipant(chat, uid) {
  return Boolean(chat) && (chat.claimantUid === uid || chat.reporterUid === uid);
}

function isStaffToken(request) {
  const role = request.auth && request.auth.token && request.auth.token.role;
  return role === "faculty" || role === "admin";
}

async function loadChat(chatId) {
  if (typeof chatId !== "string" || !CHAT_ID_RE.test(chatId)) {
    throw new HttpsError("invalid-argument", "Invalid chat id.");
  }
  const snap = await db.collection("chats").doc(chatId).get();
  if (!snap.exists) throw new HttpsError("not-found", "Chat not found.");
  return { id: snap.id, data: snap.data() };
}

/**
 * Creates (or returns) the deterministic chat for an approved claim. Shared by
 * the callable and the claim-status trigger.
 */
async function ensureChatForClaim(claimId, claimData) {
  if (!isSafeId(claimId)) throw new HttpsError("invalid-argument", "Invalid claim id.");
  let claim = claimData || null;
  if (!claim) {
    const claimSnap = await db.collection("claims").doc(claimId).get();
    if (!claimSnap.exists) throw new HttpsError("not-found", "Claim not found.");
    claim = claimSnap.data();
  }
  if (claim.status !== "approved") {
    throw new HttpsError("failed-precondition", "Chat opens after the claim is approved.");
  }
  if (!isSafeId(claim.itemId) || !isSafeId(claim.claimantUid)) {
    throw new HttpsError("failed-precondition", "Claim is missing a valid item or claimant.");
  }

  const itemSnap = await db.collection("items").doc(claim.itemId).get();
  if (!itemSnap.exists) throw new HttpsError("not-found", "Item not found.");
  const item = itemSnap.data();
  if (!isSafeId(item.reporterUid)) {
    throw new HttpsError("failed-precondition", "Item has no valid reporter.");
  }

  const chatId = chatIdFor(claim.itemId, claim.claimantUid);
  const ref = db.collection("chats").doc(chatId);

  const created = await db.runTransaction(async (transaction) => {
    const snap = await transaction.get(ref);
    if (snap.exists) {
      // Reopening is allowed until the claim/item is returned, but never let a
      // stale participant list drift from the authoritative claim/item.
      transaction.set(
        ref,
        {
          itemId: claim.itemId,
          itemTitle: clampString(claim.itemTitle || item.title, 100),
          claimantUid: claim.claimantUid,
          reporterUid: item.reporterUid,
          participantUids: [claim.claimantUid, item.reporterUid],
          updatedAt: FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
      return false;
    }
    transaction.set(ref, {
      itemId: claim.itemId,
      itemTitle: clampString(claim.itemTitle || item.title, 100),
      claimantUid: claim.claimantUid,
      reporterUid: item.reporterUid,
      participantUids: [claim.claimantUid, item.reporterUid],
      status: "open",
      lastMessage: "",
      lastMessageAt: null,
      lastSenderUid: "",
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });
    return true;
  });

  if (created) {
    await writeAudit({
      actorUid: claim.claimantUid,
      actorRole: "system",
      action: "chat.created",
      targetType: "chat",
      targetId: chatId,
      details: `Secure chat opened for claim ${claimId}`,
    });
  }

  return { chatId, created };
}

/** Callable used by the client when it opens the chat for an approved claim. */
exports.ensureChat = onCall(CALLABLE_OPTIONS, async (request) => {
  assertVerified(request);
  const claimId = request.data && request.data.claimId;
  if (!isSafeId(claimId)) throw new HttpsError("invalid-argument", "Invalid claim id.");

  const limit = await consumeRateLimit(request.auth.uid, "chat_open", 30, 60 * 1000);
  if (!limit.allowed) {
    throw new HttpsError("resource-exhausted", "Too many chat requests. Try again shortly.");
  }

  const claimSnap = await db.collection("claims").doc(claimId).get();
  if (!claimSnap.exists) throw new HttpsError("not-found", "Claim not found.");
  const claim = claimSnap.data();

  if (claim.claimantUid !== request.auth.uid) {
    const itemSnap = await db.collection("items").doc(claim.itemId || "").get();
    const reporterUid = itemSnap.exists ? itemSnap.data().reporterUid : null;
    if (reporterUid !== request.auth.uid && !isStaffToken(request)) {
      throw new HttpsError("permission-denied", "You are not a participant in this claim.");
    }
  }

  return ensureChatForClaim(claimId, claim);
});

/** Callable-only message write. Direct client creates are denied by rules. */
exports.sendChatMessage = onCall(CALLABLE_OPTIONS, async (request) => {
  assertVerified(request);
  const data = request.data || {};
  const uid = request.auth.uid;
  const text = clampString(data.text, MAX_CHAT_TEXT).trim();

  if (!text) throw new HttpsError("invalid-argument", "Write a message first.");
  if (text.length > MAX_CHAT_TEXT) {
    throw new HttpsError("invalid-argument", "Message is too long.");
  }

  const { id: chatId, data: chat } = await loadChat(data.chatId);
  if (chat.status !== "open") {
    throw new HttpsError("failed-precondition", "This chat is closed.");
  }
  if (!isParticipant(chat, uid)) {
    throw new HttpsError("permission-denied", "Only the claimant and item reporter can send messages.");
  }
  if (!isSafeId(chat.itemId) || !isSafeId(chat.claimantUid)) {
    throw new HttpsError("failed-precondition", "Chat is not linked to a valid claim.");
  }

  const limit = await consumeRateLimit(uid, "chat_message", MESSAGE_LIMIT, MESSAGE_WINDOW_MS);
  if (!limit.allowed) {
    throw new HttpsError("resource-exhausted", "You are sending messages too quickly.");
  }

  const messageRef = db.collection("chats").doc(chatId).collection("messages").doc();
  await messageRef.set({
    senderUid: uid,
    text,
    type: "text",
    createdAt: FieldValue.serverTimestamp(),
  });

  await db.collection("chats").doc(chatId).set(
    {
      lastMessage: clampString(text, 120),
      lastMessageAt: FieldValue.serverTimestamp(),
      lastSenderUid: uid,
      updatedAt: FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  const otherUid = chat.claimantUid === uid ? chat.reporterUid : chat.claimantUid;
  if (otherUid && otherUid !== uid) {
    // Debounce: at most one push per recipient per chat every two minutes.
    const debounce = await consumeRateLimit(
      otherUid,
      `chat_push_${chatId}`,
      1,
      PUSH_DEBOUNCE_MS
    ).catch(() => ({ allowed: false }));
    if (debounce.allowed) {
      const senderProfile = await getUserProfile(uid).catch(() => null);
      const senderName = clampString(
        (senderProfile && senderProfile.name) || "A campus member",
        60
      );
      await queueNotification({
        toUid: otherUid,
        text: `${senderName} sent a message about "${clampString(chat.itemTitle, 80)}".`,
        event: "chatMessage",
        url: "/index.html?view=dashboard&chat=" + encodeURIComponent(chatId),
      });
    }
  }

  return { messageId: messageRef.id, chatId };
});

/** Records a moderation report without copying private chat text. */
exports.reportChatMessage = onCall(CALLABLE_OPTIONS, async (request) => {
  assertVerified(request);
  const data = request.data || {};
  const uid = request.auth.uid;
  const reason = clampString(data.reason, 300).trim();
  const messageId = data.messageId;

  if (!reason) throw new HttpsError("invalid-argument", "Describe the problem first.");
  if (!isSafeId(messageId)) throw new HttpsError("invalid-argument", "Invalid message id.");

  const { id: chatId, data: chat } = await loadChat(data.chatId);
  if (!isParticipant(chat, uid) && !isStaffToken(request)) {
    throw new HttpsError("permission-denied", "You cannot report this message.");
  }

  const messageSnap = await db
    .collection("chats")
    .doc(chatId)
    .collection("messages")
    .doc(messageId)
    .get();
  if (!messageSnap.exists) throw new HttpsError("not-found", "Message not found.");

  const limit = await consumeRateLimit(uid, "chat_report", REPORT_LIMIT, REPORT_WINDOW_MS);
  if (!limit.allowed) {
    throw new HttpsError("resource-exhausted", "Too many reports. Try again later.");
  }

  const reportRef = db.collection("moderation").doc();
  await reportRef.set({
    chatId,
    messageId,
    reportedBy: uid,
    messageSenderUid: clampString(messageSnap.data().senderUid, 128),
    reason,
    status: "open",
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
  });

  await writeAudit({
    actorUid: uid,
    actorRole: request.auth.token.role || "student",
    action: "chat.message_reported",
    targetType: "chat",
    targetId: chatId,
    details: `Message ${messageId} reported for moderation`,
  });

  return { reportId: reportRef.id };
});

/** Closes every open chat for an item (used when an item is returned). */
async function closeChatsForItem(itemId, reason, actorUid) {
  if (!isSafeId(itemId)) return 0;
  const snap = await db.collection("chats").where("itemId", "==", itemId).limit(100).get();
  const open = snap.docs.filter((doc) => (doc.data() || {}).status === "open");
  if (!open.length) return 0;

  const batch = db.batch();
  open.forEach((doc) => {
    batch.set(
      doc.ref,
      {
        status: "closed",
        closedReason: clampString(reason, 80),
        closedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
  });
  await batch.commit();

  await writeAudit({
    actorUid: actorUid || "system",
    actorRole: "system",
    action: "chat.closed",
    targetType: "item",
    targetId: itemId,
    details: `Closed ${open.length} chat(s): ${clampString(reason, 80)}`,
  });
  return open.length;
}

/** Closes one chat by claim (used when a claim is rejected). */
async function closeChatForClaim(itemId, claimantUid, reason, actorUid) {
  if (!isSafeId(itemId) || !isSafeId(claimantUid)) return false;
  const ref = db.collection("chats").doc(chatIdFor(itemId, claimantUid));
  const snap = await ref.get();
  if (!snap.exists || snap.data().status !== "open") return false;
  await ref.set(
    {
      status: "closed",
      closedReason: clampString(reason, 80),
      closedAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    },
    { merge: true }
  );
  await writeAudit({
    actorUid: actorUid || "system",
    actorRole: "system",
    action: "chat.closed",
    targetType: "chat",
    targetId: ref.id,
    details: `Closed chat: ${clampString(reason, 80)}`,
  });
  return true;
}

exports.ensureChatForClaim = ensureChatForClaim;
exports.closeChatsForItem = closeChatsForItem;
exports.closeChatForClaim = closeChatForClaim;
exports.chatIdFor = chatIdFor;
