"use strict";

/**
 * Shared helpers for Campus Connect Cloud Functions.
 *
 * The Admin SDK bypasses Security Rules, so every privileged callable must
 * re-check the caller's custom-claim role and validate its input here.
 */

const admin = require("firebase-admin");
const { HttpsError } = require("firebase-functions/v2/https");

if (!admin.apps.length) {
  admin.initializeApp();
}

const db = admin.firestore();
const auth = admin.auth();
const FieldValue = admin.firestore.FieldValue;

const DEFAULT_ALLOWED_DOMAINS = ["campus.edu", "gmail.com"];
const ALLOWED_EMAIL_DOMAINS = String(
  process.env.ALLOWED_EMAIL_DOMAINS || DEFAULT_ALLOWED_DOMAINS.join(",")
)
  .split(",")
  .map((domain) => domain.trim().toLowerCase())
  .filter(Boolean);

const VALID_ROLES = ["student", "faculty", "admin"];
const VALID_USER_STATUSES = ["Active", "Suspended"];
const MAX_TEXT = 500;

/**
 * Notification/email preferences. Only booleans are stored, so a client can
 * never smuggle a role, prompt text or other field into the settings object.
 * Defaults are applied server-side; a missing preferences object is NOT an
 * error and never disables transactional security notices.
 */
const DEFAULT_PREFS = Object.freeze({
  pushEnabled: true,
  emailEnabled: true,
  claimStatus: true,
  matchFound: true,
  chatMessage: true,
  custodyUpdate: true,
  broadcast: true,
  weeklyDigest: false,
});
const PREF_KEYS = Object.keys(DEFAULT_PREFS);

/**
 * Maps internal notification events to the single preference that controls
 * them. Unknown events are always allowed: transactional security notices
 * (for example a suspension warning) must not be silently disabled by a
 * malformed preference object.
 */
const EVENT_PREFS = Object.freeze({
  claimReceived: "claimStatus",
  claimApproved: "claimStatus",
  claimRejected: "claimStatus",
  claimReturned: "claimStatus",
  readyForPickup: "custodyUpdate",
  returnedReceipt: "claimStatus",
  custodyUpdate: "custodyUpdate",
  chatMessage: "chatMessage",
  broadcast: "broadcast",
  matchFound: "matchFound",
  weeklyDigest: "weeklyDigest",
});

/** Events that also have an email template. */
const EMAIL_EVENTS = Object.freeze([
  "claimReceived",
  "claimApproved",
  "claimRejected",
  "claimReturned",
  "readyForPickup",
  "returnedReceipt",
  "custodyUpdate",
  "broadcast",
  "matchFound",
  "weeklyDigest",
]);

/** Coerces arbitrary stored/client data into the known boolean preference set. */
function normalizePrefs(raw) {
  const source = raw && typeof raw === "object" ? raw : {};
  const prefs = { ...DEFAULT_PREFS };
  PREF_KEYS.forEach((key) => {
    if (typeof source[key] === "boolean") prefs[key] = source[key];
  });
  return prefs;
}

/**
 * Checks the channel master switch (push/email) and the event preference.
 * `channel` defaults to push so existing call sites stay safe.
 */
function prefEnabled(prefs, event, channel = "push") {
  const normalized = normalizePrefs(prefs);
  if (channel === "email") {
    if (normalized.emailEnabled === false) return false;
  } else if (normalized.pushEnabled === false) {
    return false;
  }
  const prefKey = EVENT_PREFS[event];
  if (prefKey && normalized[prefKey] === false) return false;
  return true;
}

/** Reads the recipient's preferences, falling back to safe defaults. */
async function getNotificationPrefs(uid) {
  const profile = await getUserProfile(uid);
  return normalizePrefs(profile && profile.prefs);
}

/**
 * Fixed-window per-user rate limit backed by a server-only Firestore document.
 * The Admin SDK bypasses rules, so clients can never reset their counter.
 * Returns { allowed, remaining, retryAfterMs }.
 */
async function consumeRateLimit(uid, action, limit, windowMs) {
  const safeUid = clampString(uid, 128).replace(/[^A-Za-z0-9_-]/g, "_");
  const safeAction = clampString(action, 60).replace(/[^A-Za-z0-9_-]/g, "_");
  const ref = db.collection("rateLimits").doc(`${safeUid}_${safeAction}`);
  const now = Date.now();

  return db.runTransaction(async (transaction) => {
    const snap = await transaction.get(ref);
    const data = snap.exists ? snap.data() : null;
    const windowStart = data && data.windowStart && typeof data.windowStart.toMillis === "function"
      ? data.windowStart.toMillis()
      : 0;
    let count = data && Number.isFinite(data.count) ? data.count : 0;
    let resetAt = windowStart;

    if (!windowStart || now - windowStart >= windowMs) {
      count = 0;
      resetAt = 0;
    }
    if (count >= limit) {
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: Math.max(1000, windowMs - (now - windowStart)),
      };
    }

    count += 1;
    transaction.set(
      ref,
      {
        uid: safeUid,
        action: safeAction,
        count,
        windowStart: resetAt ? data.windowStart : FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
    return { allowed: true, remaining: Math.max(0, limit - count) };
  });
}

/**
 * Daily per-user email quota. Stored in a server-only collection so a client
 * cannot reset its own counter. The window is a UTC calendar day.
 */
async function consumeEmailQuota(uid, dailyCap) {
  const cap = Number.isFinite(dailyCap) && dailyCap > 0
    ? Math.floor(dailyCap)
    : Math.max(1, Number(process.env.EMAIL_DAILY_CAP || 15));
  const safeUid = clampString(uid, 128).replace(/[^A-Za-z0-9_-]/g, "_");
  const day = new Date().toISOString().slice(0, 10);
  const ref = db.collection("emailUsage").doc(safeUid);

  return db.runTransaction(async (transaction) => {
    const snap = await transaction.get(ref);
    const data = snap.exists ? snap.data() : null;
    const storedDay = data && typeof data.day === "string" ? data.day : "";
    const count = storedDay === day && Number.isFinite(data && data.count) ? data.count : 0;
    if (count >= cap) {
      return { allowed: false, remaining: 0, cap, day };
    }
    transaction.set(
      ref,
      {
        uid: safeUid,
        day,
        count: count + 1,
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
    return { allowed: true, remaining: Math.max(0, cap - (count + 1)), cap, day };
  });
}

/** Persists email failures for operators without leaking them to end users. */
async function logEmailFailure({ uid, event, reason }) {
  try {
    await db.collection("emailFailures").add({
      uid: clampString(uid || "unknown", 128),
      event: clampString(event || "unknown", 40),
      reason: clampString(reason || "unknown", 500),
      createdAt: FieldValue.serverTimestamp(),
    });
  } catch (error) {
    console.error("Could not record email failure:", error.message);
  }
}

/**
 * Writes an in-app notification. Cloud Functions use the Admin SDK because a
 * student cannot write another user's notification under the client rules.
 * `dedupeKey` makes Firestore's at-least-once triggers idempotent.
 */
async function queueNotification({ toUid, text, event = "general", url = "/index.html?view=dashboard", dedupeKey }) {
  if (!toUid) return null;
  const safeText = clampString(text, MAX_TEXT).trim();
  if (!safeText) return null;
  const ref = dedupeKey
    ? db.collection("notifications").doc(clampString(dedupeKey, 180))
    : db.collection("notifications").doc();
  await ref.set(
    {
      toUid: clampString(toUid, 128),
      text: safeText,
      read: false,
      event: clampString(event, 40),
      url: typeof url === "string" && url.startsWith("/") && !url.startsWith("//")
        ? clampString(url, 300)
        : "/index.html?view=dashboard",
      createdAt: FieldValue.serverTimestamp(),
    },
    { merge: true }
  );
  return ref.id;
}

function isAllowedEmail(email) {
  const normalized = String(email || "").trim().toLowerCase();
  if (!normalized || normalized.length > 254 || !normalized.includes("@")) {
    return false;
  }
  if (!ALLOWED_EMAIL_DOMAINS.length || ALLOWED_EMAIL_DOMAINS.includes("*")) {
    return true;
  }
  const domain = normalized.split("@").pop();
  return ALLOWED_EMAIL_DOMAINS.some(
    (allowed) => domain === allowed || domain.endsWith(`.${allowed}`)
  );
}

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase().slice(0, 254);
}

function clampString(value, maxLength) {
  return String(value === null || value === undefined ? "" : value).slice(0, maxLength);
}

function cleanName(name, fallback) {
  const cleaned = clampString(name, 80).trim();
  return cleaned || clampString(fallback, 80) || "Campus Member";
}

function isSafeId(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value);
}

function assertAuth(request) {
  if (!request || !request.auth || !request.auth.uid) {
    throw new HttpsError("unauthenticated", "You must be signed in.");
  }
}

function assertVerified(request) {
  assertAuth(request);
  if (request.auth.token.email_verified !== true) {
    throw new HttpsError("failed-precondition", "Verify your college email first.");
  }
  if (request.auth.token.suspended === true) {
    throw new HttpsError("permission-denied", "This account is suspended.");
  }
}

function assertRole(request, roles) {
  assertVerified(request);
  const role = request.auth.token.role;
  if (!roles.includes(role)) {
    throw new HttpsError("permission-denied", "You do not have permission for this action.");
  }
}

function assertAdmin(request) {
  assertRole(request, ["admin"]);
}

function assertStaff(request) {
  assertRole(request, ["faculty", "admin"]);
}

/** Requires a recent sign-in/re-authentication (Firebase auth_time claim). */
function assertRecentAuth(request, maxAgeSeconds = 300) {
  assertVerified(request);
  const authTime = Number(request.auth.token.auth_time || 0);
  const now = Math.floor(Date.now() / 1000);
  if (!authTime || now - authTime > maxAgeSeconds) {
    throw new HttpsError(
      "failed-precondition",
      "Please re-authenticate before performing this sensitive action."
    );
  }
}

/**
 * Append to the authoritative server audit trail. Client logs are useful for UI
 * hints but can be forged; these entries are written with the Admin SDK.
 */
async function writeAudit({
  actorUid,
  actorRole,
  action,
  targetType,
  targetId,
  details,
  source = "function",
}) {
  const safeAction = clampString(action || "unknown", 80);
  const safeDetails = clampString(details, 300);
  await db.collection("logs").add({
    actorUid: clampString(actorUid || "system", 128),
    actorRole: VALID_ROLES.includes(actorRole) ? actorRole : "system",
    action: safeAction,
    targetType: clampString(targetType, 40),
    targetId: clampString(targetId, 120),
    details: safeDetails,
    // The admin UI renders `text`; keep a human-readable summary for both
    // client- and function-written entries.
    text: clampString(safeDetails || safeAction, MAX_TEXT),
    source: source === "client" ? "client" : "function",
    createdAt: FieldValue.serverTimestamp(),
  });
}

async function getUserProfile(uid) {
  const snap = await db.collection("users").doc(uid).get();
  return snap.exists ? snap.data() : null;
}

/** Reads the informational profile role, falling back to student. */
async function getProfileRole(uid) {
  const profile = await getUserProfile(uid);
  return profile && VALID_ROLES.includes(profile.role) ? profile.role : "student";
}

/** Counts enabled admins by custom claim (authoritative), excluding one uid. */
async function countAdmins(excludeUid) {
  let total = 0;
  let pageToken;
  do {
    const page = await auth.listUsers(1000, pageToken);
    page.users.forEach((user) => {
      if (
        user.uid !== excludeUid &&
        !user.disabled &&
        user.customClaims &&
        user.customClaims.role === "admin"
      ) {
        total += 1;
      }
    });
    pageToken = page.pageToken;
  } while (pageToken);
  return total;
}

/**
 * Deletes the Firestore documents and Storage objects owned by a user, but
 * deliberately keeps audit logs for accountability. Other users' claims are
 * not deleted; they are their records, not the deleted user's.
 */
async function deleteUserData(uid) {
  const summary = {
    items: 0,
    claims: 0,
    complaints: 0,
    notifications: 0,
    chats: 0,
    receipts: 0,
    moderation: 0,
    rateLimits: 0,
    profileDeleted: false,
    storageDeleted: false,
  };

  const collections = [
    ["items", "reporterUid", "items"],
    ["claims", "claimantUid", "claims"],
    ["complaints", "reporterUid", "complaints"],
    ["notifications", "toUid", "notifications"],
    ["receipts", "claimantUid", "receipts"],
    ["moderation", "reportedBy", "moderation"],
    ["rateLimits", "uid", "rateLimits"],
  ];

  for (const [collectionName, field, counter] of collections) {
    let query = db.collection(collectionName).where(field, "==", uid);
    // Firestore Admin queries are paginated; deleting while iterating could
    // skip documents, so repeatedly fetch the next page until empty.
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const snap = await query.limit(100).get();
      if (snap.empty) break;
      for (const doc of snap.docs) {
        if (collectionName === "items") {
          const image = doc.data().image;
          await deleteStorageUrl(image).catch(() => {});
        }
        await db.recursiveDelete(doc.ref);
        summary[counter] += 1;
      }
      if (snap.size < 100) break;
    }
  }

  // Chats can list the user as either participant. Delete each unique chat
  // (and its messages/reads subcollections) once.
  const chatIds = new Set();
  for (const field of ["claimantUid", "reporterUid"]) {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      const snap = await db.collection("chats").where(field, "==", uid).limit(100).get();
      if (snap.empty) break;
      snap.docs.forEach((doc) => chatIds.add(doc.ref));
      if (snap.size < 100) break;
    }
  }
  for (const ref of chatIds) {
    await db.recursiveDelete(ref).catch(() => {});
    summary.chats += 1;
  }

  // Remove the entire users/{uid} document including devices/ and prefs.
  await db.recursiveDelete(db.collection("users").doc(uid)).catch(() => {});
  await db.collection("emailUsage").doc(uid).delete().catch(() => {});
  summary.profileDeleted = true;

  try {
    await admin.storage().bucket().deleteFiles({
      prefix: `items/${uid}/`,
      force: true,
    });
    summary.storageDeleted = true;
  } catch (error) {
    // A missing/empty prefix is not an error for the caller.
    summary.storageDeleted = false;
  }

  return summary;
}

function storagePathFromUrl(url) {
  if (!url || typeof url !== "string") return null;
  try {
    const parsed = new URL(url);
    if (
      !/firebasestorage\.googleapis\.com$/i.test(parsed.hostname) &&
      !/\.firebasestorage\.app$/i.test(parsed.hostname)
    ) {
      return null;
    }
    const marker = "/o/";
    const index = parsed.pathname.indexOf(marker);
    if (index === -1) return null;
    const path = decodeURIComponent(parsed.pathname.slice(index + marker.length));
    return path.startsWith("items/") ? path : null;
  } catch (error) {
    return null;
  }
}

async function deleteStorageUrl(url) {
  const path = storagePathFromUrl(url);
  if (!path) return false;
  try {
    await admin.storage().bucket().file(path).delete({ ignoreNotFound: true });
    return true;
  } catch (error) {
    return false;
  }
}

module.exports = {
  admin,
  auth,
  db,
  FieldValue,
  ALLOWED_EMAIL_DOMAINS,
  VALID_ROLES,
  VALID_USER_STATUSES,
  MAX_TEXT,
  DEFAULT_PREFS,
  PREF_KEYS,
  EVENT_PREFS,
  EMAIL_EVENTS,
  normalizePrefs,
  prefEnabled,
  getNotificationPrefs,
  consumeRateLimit,
  consumeEmailQuota,
  logEmailFailure,
  queueNotification,
  isAllowedEmail,
  normalizeEmail,
  clampString,
  cleanName,
  isSafeId,
  assertAuth,
  assertVerified,
  assertRole,
  assertAdmin,
  assertStaff,
  assertRecentAuth,
  writeAudit,
  getUserProfile,
  getProfileRole,
  countAdmins,
  deleteUserData,
  storagePathFromUrl,
  deleteStorageUrl,
};
