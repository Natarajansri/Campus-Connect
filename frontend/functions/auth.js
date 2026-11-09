"use strict";

const { beforeUserCreated, beforeUserSignedIn } = require("firebase-functions/v2/identity");
const functionsV1 = require("firebase-functions/v1");
const { HttpsError } = require("firebase-functions/v2/https");

const {
  auth,
  db,
  FieldValue,
  VALID_ROLES,
  isAllowedEmail,
  normalizeEmail,
  cleanName,
  writeAudit,
} = require("./helpers");

/**
 * Blocking function: rejects sign-ups from outside the configured college
 * domain and forces every new account to start as a student.
 *
 * A client can never choose its own role. Elevation happens only through the
 * admin-only setUserRole callable (which writes a custom claim via Admin SDK).
 */
exports.beforeUserCreated = beforeUserCreated((event) => {
  const user = event.data;
  const email = normalizeEmail(user.email);

  if (!email || !isAllowedEmail(email)) {
    throw new HttpsError(
      "invalid-argument",
      "Only authorized college email addresses may register."
    );
  }

  return {
    displayName: cleanName(user.displayName, email.split("@")[0]),
    // Force a clean claim set. Never copy client/provider supplied claims.
    customClaims: { role: "student" },
  };
});

/**
 * Blocking function: rejects sign-ins from outside the college domain and any
 * account explicitly marked suspended.
 *
 * Email verification is intentionally NOT enforced here. The sign-up flow needs
 * a short-lived session to send the verification email, and Firestore/Storage
 * rules + Cloud Functions still require `email_verified == true` before any
 * protected data is reachable.
 */
exports.beforeUserSignedIn = beforeUserSignedIn((event) => {
  const user = event.data;
  const email = normalizeEmail(user.email);

  if (!email || !isAllowedEmail(email)) {
    throw new HttpsError(
      "permission-denied",
      "Only authorized college email addresses may sign in."
    );
  }
  if (user.disabled) {
    throw new HttpsError("permission-denied", "This account is disabled.");
  }
  if (user.customClaims && user.customClaims.suspended === true) {
    throw new HttpsError("permission-denied", "This account is suspended.");
  }
});

/**
 * Background trigger: creates the informational users/{uid} profile document.
 * It is idempotent so it cannot overwrite a role/profile created by the admin
 * inviteUser callable.
 */
exports.onUserCreated = functionsV1.auth.user().onCreate(async (user) => {
  const uid = user.uid;
  const email = normalizeEmail(user.email);
  const ref = db.collection("users").doc(uid);
  const existing = await ref.get();

  if (existing.exists) {
    // A concurrent inviteUser call already created a richer profile. Do not
    // overwrite its role/status.
    return;
  }

  const claimRole = VALID_ROLES.includes(user.customClaims && user.customClaims.role)
    ? user.customClaims.role
    : "student";

  await ref.set({
    uid,
    name: cleanName(user.displayName, email.split("@")[0] || "Campus Member"),
    email,
    department: "",
    // Informational only. Authorization always uses the custom claim.
    role: claimRole,
    status: "Active",
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
  });

  // Make sure every account has a valid role claim, even if it pre-dates the
  // blocking-function deployment.
  if (!user.customClaims || !VALID_ROLES.includes(user.customClaims.role)) {
    await auth.setCustomUserClaims(uid, {
      ...(user.customClaims || {}),
      role: claimRole,
    });
  }

  await writeAudit({
    actorUid: uid,
    actorRole: claimRole,
    action: "user.created",
    targetType: "user",
    targetId: uid,
    details: `Account created for ${email}`,
  });
});
