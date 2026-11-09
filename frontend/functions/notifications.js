"use strict";

/**
 * Push notification fan-out.
 *
 * A Firestore trigger (not a client write) owns delivery so a member can never
 * address a push to another member. Tokens live in users/{uid}/devices and are
 * deleted when FCM reports them as permanently invalid.
 *
 * Messages are data-only: the service worker decides how to render and which
 * same-origin link to open, so a compromised payload cannot inject markup.
 */

const { onDocumentCreated } = require("firebase-functions/v2/firestore");

const {
  admin,
  db,
  FieldValue,
  clampString,
  getNotificationPrefs,
  prefEnabled,
} = require("./helpers");
const { sendNotificationEmail, EMAIL_SECRETS } = require("./email");

const INVALID_TOKEN_CODES = new Set([
  "messaging/registration-token-not-registered",
  "messaging/invalid-registration-token",
  "messaging/invalid-argument",
]);

const MAX_DEVICES = 500;
const BATCH_SIZE = 500;

function safeInternalUrl(url) {
  const value = String(url || "").trim();
  if (!value.startsWith("/") || value.startsWith("//")) {
    return "/index.html?view=dashboard";
  }
  return value;
}

/**
 * Deduplicates at-least-once trigger retries. Writing a marker on the same
 * notification document does not re-run onDocumentCreated.
 */
async function claimDelivery(notifId, channel) {
  const ref = db.collection("notifications").doc(notifId);
  const field = `${channel}AttemptedAt`;
  return db.runTransaction(async (transaction) => {
    const snap = await transaction.get(ref);
    if (!snap.exists) return false;
    const data = snap.data() || {};
    if (data[field]) return false;
    transaction.update(ref, { [field]: FieldValue.serverTimestamp() });
    return true;
  });
}

async function sendPushToUser(uid, notification, notifId) {
  const snapshot = await db
    .collection("users")
    .doc(uid)
    .collection("devices")
    .limit(MAX_DEVICES)
    .get();

  const devices = snapshot.docs.filter((doc) => {
    const data = doc.data() || {};
    return data.enabled !== false && typeof data.token === "string" && data.token.length >= 20;
  });
  if (!devices.length) return { sent: 0, failed: 0, removed: 0 };

  const event = clampString(notification.event || "general", 40);
  const body = clampString(notification.text, 180);
  const data = {
    title: "Campus Connect",
    body: body || "You have a new update.",
    url: safeInternalUrl(notification.url),
    event,
    notifId: clampString(notifId, 180),
  };

  let sent = 0;
  let failed = 0;
  let removed = 0;

  for (let offset = 0; offset < devices.length; offset += BATCH_SIZE) {
    const chunk = devices.slice(offset, offset + BATCH_SIZE);
    const tokens = chunk.map((doc) => doc.data().token);
    let response;
    try {
      response = await admin.messaging().sendEachForMulticast({ tokens, data });
    } catch (error) {
      console.warn("FCM multicast failed:", error.message);
      failed += chunk.length;
      continue;
    }

    sent += response.successCount;
    failed += response.failureCount;

    const invalidRefs = [];
    response.responses.forEach((result, index) => {
      if (result.success) return;
      const code = result.error && result.error.code;
      if (INVALID_TOKEN_CODES.has(code)) invalidRefs.push(chunk[index].ref);
    });

    if (invalidRefs.length) {
      const batch = db.batch();
      invalidRefs.forEach((ref) => batch.delete(ref));
      await batch.commit().catch(() => {});
      removed += invalidRefs.length;
    }
  }

  return { sent, failed, removed };
}

exports.onNotificationCreated = onDocumentCreated(
  { document: "notifications/{notifId}", secrets: EMAIL_SECRETS },
  async (event) => {
    const snapshot = event.data;
    if (!snapshot) return;
    const notification = snapshot.data() || {};
    const toUid = notification.toUid;
    if (!toUid) return;
    const notifId = event.params.notifId;
    const eventName = clampString(notification.event || "general", 40);

    const prefs = await getNotificationPrefs(toUid).catch(() => null);
    if (!prefs) return;

    if (prefEnabled(prefs, eventName, "push")) {
      const alreadyClaimed = await claimDelivery(notifId, "push").catch(() => false);
      if (alreadyClaimed) {
        await sendPushToUser(toUid, notification, notifId).catch((error) => {
          console.warn("Push delivery failed:", error.message);
        });
      }
    }

    if (prefEnabled(prefs, eventName, "email")) {
      const alreadyClaimed = await claimDelivery(notifId, "email").catch(() => false);
      if (alreadyClaimed) {
        await sendNotificationEmail({
          uid: toUid,
          event: eventName,
          text: notification.text,
          url: notification.url,
        }).catch((error) => {
          console.warn("Email delivery failed:", error.message);
        });
      }
    }
  }
);

exports.sendPushToUser = sendPushToUser;
exports._claimDelivery = claimDelivery;
