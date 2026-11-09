"use strict";

/**
 * QR item handover.
 *
 * The QR payload is a bearer token. Only its SHA-256 hash is persisted under
 * claims/{claimId}/private/handover (server-only). The claimant retrieves the
 * plaintext token on demand; issuing a new token rotates and invalidates the
 * previous one. Verification is single-use and happens inside one Firestore
 * transaction that also marks the claim/item returned and writes a receipt.
 *
 * Token format: CC1.<claimId>.<32 random bytes, base64url>
 */

const crypto = require("node:crypto");
const { onCall, HttpsError } = require("firebase-functions/v2/https");

const {
  db,
  FieldValue,
  clampString,
  isSafeId,
  assertVerified,
  assertStaff,
  consumeRateLimit,
  queueNotification,
  writeAudit,
} = require("./helpers");

const CALLABLE_OPTIONS = {
  enforceAppCheck: process.env.FUNCTIONS_EMULATOR !== "true",
};

const TOKEN_RE = /^CC1\.([A-Za-z0-9_-]{1,128})\.([A-Za-z0-9_-]{20,128})$/;
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000;
const ISSUE_LIMIT = 5;
const ISSUE_WINDOW_MS = 60 * 1000;
const VERIFY_LIMIT = 30;
const VERIFY_WINDOW_MS = 60 * 1000;

function hashToken(token) {
  return crypto.createHash("sha256").update(String(token), "utf8").digest("hex");
}

function safeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const left = Buffer.from(a, "hex");
  const right = Buffer.from(b, "hex");
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function receiptCode() {
  return `CC-${crypto.randomBytes(6).toString("hex").toUpperCase()}`;
}

/**
 * Issues (or rotates) the claimant's handover token. The previous token is
 * invalidated because the stored hash is overwritten.
 */
exports.getHandoverToken = onCall(CALLABLE_OPTIONS, async (request) => {
  assertVerified(request);
  const uid = request.auth.uid;
  const claimId = request.data && request.data.claimId;
  if (!isSafeId(claimId)) throw new HttpsError("invalid-argument", "Invalid claim id.");

  const limit = await consumeRateLimit(uid, "handover_issue", ISSUE_LIMIT, ISSUE_WINDOW_MS);
  if (!limit.allowed) {
    throw new HttpsError("resource-exhausted", "Too many code requests. Try again shortly.");
  }

  const claimRef = db.collection("claims").doc(claimId);
  const claimSnap = await claimRef.get();
  if (!claimSnap.exists) throw new HttpsError("not-found", "Claim not found.");
  const claim = claimSnap.data();

  if (claim.claimantUid !== uid) {
    throw new HttpsError("permission-denied", "Only the claimant can show the handover code.");
  }
  if (claim.status !== "approved") {
    throw new HttpsError("failed-precondition", "The claim must be approved first.");
  }
  if (!isSafeId(claim.itemId)) {
    throw new HttpsError("failed-precondition", "Claim is missing a valid item.");
  }

  const itemSnap = await db.collection("items").doc(claim.itemId).get();
  if (!itemSnap.exists) throw new HttpsError("not-found", "Item not found.");
  const item = itemSnap.data();
  if (["returned", "rejected"].includes(String(item.status || "").toLowerCase())) {
    throw new HttpsError("failed-precondition", "This item is no longer awaiting pickup.");
  }

  const secret = crypto.randomBytes(32).toString("base64url");
  const token = `CC1.${claimId}.${secret}`;
  const expiresAt = new Date(Date.now() + TOKEN_TTL_MS);

  await claimRef.collection("private").doc("handover").set({
    tokenHash: hashToken(token),
    issuedTo: uid,
    issuedBy: uid,
    used: false,
    createdAt: FieldValue.serverTimestamp(),
    expiresAt,
    updatedAt: FieldValue.serverTimestamp(),
  });

  await writeAudit({
    actorUid: uid,
    actorRole: request.auth.token.role || "student",
    action: "handover.token_issued",
    targetType: "claim",
    targetId: claimId,
    details: "Issued a new single-use handover token",
  });

  return {
    token,
    claimId,
    itemTitle: clampString(claim.itemTitle || item.title, 100),
    expiresAt: expiresAt.getTime(),
  };
});

/**
 * Staff-only verification. Every failed attempt is audited, but the client
 * always receives the same generic message so a token cannot be probed.
 */
exports.verifyHandover = onCall(CALLABLE_OPTIONS, async (request) => {
  assertStaff(request);
  const staffUid = request.auth.uid;
  const token = typeof (request.data && request.data.token) === "string"
    ? request.data.token.trim()
    : "";

  const limit = await consumeRateLimit(staffUid, "handover_verify", VERIFY_LIMIT, VERIFY_WINDOW_MS);
  if (!limit.allowed) {
    throw new HttpsError("resource-exhausted", "Too many scans. Wait a moment and try again.");
  }

  const match = TOKEN_RE.exec(token);
  const genericFailure = "This handover code is invalid, expired, or already used.";

  if (!match) {
    await writeVerificationFailure(staffUid, "unknown", "malformed-token");
    throw new HttpsError("failed-precondition", genericFailure);
  }

  const claimId = match[1];
  const submittedHash = hashToken(token);
  const claimRef = db.collection("claims").doc(claimId);

  let result;
  try {
    result = await db.runTransaction(async (transaction) => {
      const claimSnap = await transaction.get(claimRef);
      if (!claimSnap.exists) throw new Error("claim-not-found");
      const claim = claimSnap.data();

      const handoverRef = claimRef.collection("private").doc("handover");
      const handoverSnap = await transaction.get(handoverRef);
      if (!handoverSnap.exists) throw new Error("handover-not-issued");
      const handover = handoverSnap.data();

      if (handover.used === true) throw new Error("token-already-used");
      if (handover.issuedTo !== claim.claimantUid) throw new Error("claimant-mismatch");
      const expiry = handover.expiresAt && typeof handover.expiresAt.toMillis === "function"
        ? handover.expiresAt.toMillis()
        : 0;
      if (!expiry || expiry <= Date.now()) throw new Error("token-expired");
      if (!safeEqualHex(handover.tokenHash, submittedHash)) throw new Error("hash-mismatch");
      if (claim.status !== "approved") throw new Error(`claim-status-${claim.status || "unknown"}`);
      if (!isSafeId(claim.itemId)) throw new Error("invalid-item-id");

      const itemRef = db.collection("items").doc(claim.itemId);
      const itemSnap = await transaction.get(itemRef);
      if (!itemSnap.exists) throw new Error("item-not-found");
      const item = itemSnap.data();
      const itemStatus = String(item.status || "").toLowerCase();
      if (!["approved", "claimed"].includes(itemStatus)) {
        throw new Error(`item-status-${itemStatus || "unknown"}`);
      }

      const code = receiptCode();
      transaction.update(handoverRef, {
        used: true,
        usedAt: FieldValue.serverTimestamp(),
        verifiedBy: staffUid,
        updatedAt: FieldValue.serverTimestamp(),
      });
      transaction.update(claimRef, {
        status: "returned",
        returnedAt: FieldValue.serverTimestamp(),
        verifiedBy: staffUid,
        updatedAt: FieldValue.serverTimestamp(),
        updatedBy: staffUid,
      });
      transaction.update(itemRef, {
        status: "returned",
        updatedAt: FieldValue.serverTimestamp(),
        updatedBy: staffUid,
      });
      transaction.set(db.collection("receipts").doc(claimId), {
        claimId,
        itemId: claim.itemId,
        itemTitle: clampString(claim.itemTitle || item.title, 100),
        claimantUid: claim.claimantUid,
        reporterUid: clampString(item.reporterUid, 128),
        verifiedBy: staffUid,
        receiptCode: code,
        returnedAt: FieldValue.serverTimestamp(),
        createdAt: FieldValue.serverTimestamp(),
      });

      return {
        claimId,
        itemId: claim.itemId,
        itemTitle: clampString(claim.itemTitle || item.title, 100),
        claimantUid: claim.claimantUid,
        reporterUid: clampString(item.reporterUid, 128),
        receiptCode: code,
      };
    });
  } catch (error) {
    const reason = clampString(error && error.message ? error.message : "verification-failed", 120);
    await writeVerificationFailure(staffUid, claimId, reason);
    throw new HttpsError("failed-precondition", genericFailure);
  }

  await writeAudit({
    actorUid: staffUid,
    actorRole: request.auth.token.role || "faculty",
    action: "handover.verified",
    targetType: "claim",
    targetId: result.claimId,
    details: `Item "${result.itemTitle}" returned; receipt ${result.receiptCode}`,
  });

  await queueNotification({
    toUid: result.claimantUid,
    text: `Handover confirmed for "${result.itemTitle}". Your return receipt is ${result.receiptCode}.`,
    event: "returnedReceipt",
    url: "/index.html?view=dashboard",
    dedupeKey: `returned_receipt_${result.claimId}`,
  }).catch(() => {});

  if (result.reporterUid && result.reporterUid !== result.claimantUid) {
    await queueNotification({
      toUid: result.reporterUid,
      text: `"${result.itemTitle}" was returned to its verified owner. Receipt ${result.receiptCode}.`,
      event: "returnedReceipt",
      url: "/index.html?view=dashboard",
      dedupeKey: `returned_reporter_${result.claimId}`,
    }).catch(() => {});
  }

  return result;
});

async function writeVerificationFailure(staffUid, claimId, reason) {
  await writeAudit({
    actorUid: staffUid,
    actorRole: "faculty",
    action: "handover.failed",
    targetType: "claim",
    targetId: clampString(claimId, 120),
    details: `Handover verification failed: ${clampString(reason, 120)}`,
  }).catch(() => {});
}

exports.hashToken = hashToken;
exports.TOKEN_TTL_MS = TOKEN_TTL_MS;
