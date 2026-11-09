"use strict";

const crypto = require("node:crypto");
const { onCall, HttpsError } = require("firebase-functions/v2/https");

const {
  auth,
  db,
  FieldValue,
  VALID_ROLES,
  VALID_USER_STATUSES,
  normalizeEmail,
  cleanName,
  isSafeId,
  isAllowedEmail,
  assertAuth,
  assertAdmin,
  assertRecentAuth,
  getProfileRole,
  countAdmins,
  deleteUserData,
  writeAudit,
} = require("./helpers");

function validRoleOrThrow(role) {
  if (!VALID_ROLES.includes(role)) {
    throw new HttpsError("invalid-argument", "Invalid role.");
  }
}

function validStatusOrThrow(status) {
  if (!VALID_USER_STATUSES.includes(status)) {
    throw new HttpsError("invalid-argument", "Invalid account status.");
  }
}

/**
 * Admin-only role assignment. Custom claims are the ONLY authoritative role
 * source, so this callable updates both the claim and the informational users
 * document. Refresh tokens are revoked so the target must obtain a fresh token.
 */
exports.setUserRole = onCall(async (request) => {
  assertAdmin(request);
  assertRecentAuth(request, 600);

  const { uid, role } = request.data || {};
  if (!isSafeId(uid)) throw new HttpsError("invalid-argument", "Invalid user id.");
  validRoleOrThrow(role);

  // Prevent an admin locking themselves out or silently demoting themselves.
  if (uid === request.auth.uid && role !== "admin") {
    throw new HttpsError(
      "failed-precondition",
      "Another administrator must change your own role."
    );
  }

  let target;
  try {
    target = await auth.getUser(uid);
  } catch (error) {
    throw new HttpsError("not-found", "User not found.");
  }

  const currentRole = target.customClaims && target.customClaims.role;
  if (currentRole === "admin" && role !== "admin") {
    const remaining = await countAdmins(uid);
    if (remaining < 1) {
      throw new HttpsError(
        "failed-precondition",
        "Cannot remove the last administrator."
      );
    }
  }

  const claims = {
    ...(target.customClaims || {}),
    role,
  };

  await auth.setCustomUserClaims(uid, claims);
  // Existing ID tokens remain valid until expiry; revoking refresh tokens means
  // no new token is issued with the old role.
  await auth.revokeRefreshTokens(uid).catch(() => {});

  const profileRole = await getProfileRole(uid);
  const ref = db.collection("users").doc(uid);
  const snap = await ref.get();
  if (snap.exists) {
    await ref.set(
      { role, updatedAt: FieldValue.serverTimestamp(), updatedBy: request.auth.uid },
      { merge: true }
    );
  } else {
    await ref.set({
      uid,
      name: cleanName(target.displayName, target.email),
      email: normalizeEmail(target.email),
      department: "",
      role,
      status: target.disabled ? "Suspended" : "Active",
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
      updatedBy: request.auth.uid,
    });
  }

  await writeAudit({
    actorUid: request.auth.uid,
    actorRole: request.auth.token.role,
    action: "user.role_changed",
    targetType: "user",
    targetId: uid,
    details: `${target.email || uid}: ${profileRole || "unknown"} -> ${role}`,
  });

  return { uid, role };
});

/**
 * Admin-only suspension. Suspension is enforced in three places:
 *   1. Firebase Auth `disabled` blocks new sign-ins.
 *   2. Refresh tokens are revoked so sessions cannot silently renew.
 *   3. A `suspended` custom claim is added; Security Rules reject it on the
 *      next token refresh. Existing ID tokens expire within one hour.
 */
exports.setUserStatus = onCall(async (request) => {
  assertAdmin(request);
  assertRecentAuth(request, 600);

  const { uid, status } = request.data || {};
  if (!isSafeId(uid)) throw new HttpsError("invalid-argument", "Invalid user id.");
  validStatusOrThrow(status);
  if (uid === request.auth.uid) {
    throw new HttpsError("failed-precondition", "You cannot suspend your own account.");
  }

  let target;
  try {
    target = await auth.getUser(uid);
  } catch (error) {
    throw new HttpsError("not-found", "User not found.");
  }

  const currentRole = target.customClaims && target.customClaims.role;
  if (status === "Suspended" && currentRole === "admin") {
    const remaining = await countAdmins(uid);
    if (remaining < 1) {
      throw new HttpsError(
        "failed-precondition",
        "Cannot suspend the last administrator."
      );
    }
  }

  const suspension = status === "Suspended";
  await auth.updateUser(uid, { disabled: suspension });
  if (suspension) {
    await auth.revokeRefreshTokens(uid).catch(() => {});
  }

  const claims = {
    ...(target.customClaims || {}),
    role: VALID_ROLES.includes(currentRole) ? currentRole : await getProfileRole(uid),
  };
  if (suspension) {
    claims.suspended = true;
  } else {
    delete claims.suspended;
  }
  await auth.setCustomUserClaims(uid, claims);

  await db.collection("users").doc(uid).set(
    {
      status,
      updatedAt: FieldValue.serverTimestamp(),
      updatedBy: request.auth.uid,
    },
    { merge: true }
  );

  await writeAudit({
    actorUid: request.auth.uid,
    actorRole: request.auth.token.role,
    action: suspension ? "user.suspended" : "user.reactivated",
    targetType: "user",
    targetId: uid,
    details: `${target.email || uid} -> ${status}`,
  });

  return { uid, status };
});

/**
 * Admin-only invite. Creates an Auth account with a random unusable password
 * and returns a one-time password-reset link for the admin to share securely.
 * No password is ever chosen in, or sent through, the browser UI.
 */
exports.inviteUser = onCall(async (request) => {
  assertAdmin(request);

  const data = request.data || {};
  const email = normalizeEmail(data.email);
  const role = data.role;
  const name = cleanName(data.name, email.split("@")[0] || "Campus Member");

  if (!email || email.length > 160 || !isAllowedEmail(email)) {
    throw new HttpsError(
      "invalid-argument",
      "Use an authorized college email address."
    );
  }
  validRoleOrThrow(role);

  try {
    await auth.getUserByEmail(email);
    throw new HttpsError(
      "already-exists",
      "An account with that email already exists. Assign a role instead."
    );
  } catch (error) {
    if (error instanceof HttpsError) throw error;
    if (error.code !== "auth/user-not-found") {
      throw new HttpsError("internal", "Could not check the email address.");
    }
  }

  const randomPassword = crypto.randomBytes(48).toString("base64url");
  let user;
  try {
    user = await auth.createUser({
      email,
      password: randomPassword,
      displayName: name,
      emailVerified: false,
      disabled: false,
    });
  } catch (error) {
    throw new HttpsError("internal", "Could not create the invited account.");
  }

  await auth.setCustomUserClaims(user.uid, { role });

  await db.collection("users").doc(user.uid).set({
    uid: user.uid,
    name,
    email,
    department: "",
    role,
    status: "Active",
    invitedBy: request.auth.uid,
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
  });

  let inviteLink = null;
  try {
    inviteLink = await auth.generatePasswordResetLink(email);
  } catch (error) {
    // The account still exists; the user can use "Forgot password?" instead.
    inviteLink = null;
  }

  await writeAudit({
    actorUid: request.auth.uid,
    actorRole: request.auth.token.role,
    action: "user.invited",
    targetType: "user",
    targetId: user.uid,
    details: `Invited ${email} as ${role}`,
  });

  return { uid: user.uid, email, role, inviteLink };
});

/** Any signed-in user can revoke their own refresh tokens. */
exports.revokeSessions = onCall(async (request) => {
  assertAuth(request);
  await auth.revokeRefreshTokens(request.auth.uid);
  await writeAudit({
    actorUid: request.auth.uid,
    actorRole: request.auth.token.role,
    action: "session.revoked",
    targetType: "user",
    targetId: request.auth.uid,
    details: "Revoked all refresh tokens for the current account",
  });
  return { success: true };
});

/** Admin-only account deletion. Requires a recent re-authentication. */
exports.deleteUserAccount = onCall(async (request) => {
  assertAdmin(request);
  assertRecentAuth(request, 600);

  const { uid } = request.data || {};
  if (!isSafeId(uid)) throw new HttpsError("invalid-argument", "Invalid user id.");
  if (uid === request.auth.uid) {
    throw new HttpsError(
      "failed-precondition",
      "Use the self-deletion endpoint for your own account."
    );
  }

  let target;
  try {
    target = await auth.getUser(uid);
  } catch (error) {
    throw new HttpsError("not-found", "User not found.");
  }

  if (target.customClaims && target.customClaims.role === "admin") {
    const remaining = await countAdmins(uid);
    if (remaining < 1) {
      throw new HttpsError(
        "failed-precondition",
        "Cannot delete the last administrator."
      );
    }
  }

  await writeAudit({
    actorUid: request.auth.uid,
    actorRole: request.auth.token.role,
    action: "user.deleted",
    targetType: "user",
    targetId: uid,
    details: `Deleted account ${target.email || uid} and owned data`,
  });

  // Delete Auth first: this immediately stops new sign-ins. Data cleanup is
  // best-effort and reported back so the admin can investigate failures.
  try {
    await auth.deleteUser(uid);
  } catch (error) {
    if (error.code !== "auth/user-not-found") {
      throw new HttpsError("internal", "Could not delete the Auth account.");
    }
  }

  const cleanup = await deleteUserData(uid);
  return { deleted: true, cleanup };
});

/** Self-service deletion for a signed-in user with recent re-authentication. */
exports.deleteOwnAccount = onCall(async (request) => {
  assertAuth(request);
  assertRecentAuth(request, 300);

  const uid = request.auth.uid;
  if (request.auth.token.role === "admin") {
    const remaining = await countAdmins(uid);
    if (remaining < 1) {
      throw new HttpsError(
        "failed-precondition",
        "Cannot delete the last administrator."
      );
    }
  }

  await writeAudit({
    actorUid: uid,
    actorRole: request.auth.token.role,
    action: "user.self_deleted",
    targetType: "user",
    targetId: uid,
    details: "User deleted their own account and owned data",
  });

  try {
    await auth.deleteUser(uid);
  } catch (error) {
    if (error.code !== "auth/user-not-found") {
      throw new HttpsError("internal", "Could not delete the account.");
    }
  }

  const cleanup = await deleteUserData(uid);
  return { deleted: true, cleanup };
});

/**
 * Admin-only campus notification dispatch. Writes one notification per active
 * user in bounded batches; the Admin SDK bypasses client notification rules.
 */
exports.sendNotification = onCall(async (request) => {
  assertAdmin(request);

  const data = request.data || {};
  const audience = data.audience;
  const message = String(data.message || "").trim().slice(0, 500);

  if (!["all", "student", "faculty"].includes(audience)) {
    throw new HttpsError("invalid-argument", "Invalid audience.");
  }
  if (!message) {
    throw new HttpsError("invalid-argument", "A notification message is required.");
  }

  let query = db.collection("users");
  if (audience !== "all") {
    query = query.where("role", "==", audience);
  }

  const snap = await query.get();
  const recipients = snap.docs.filter((doc) => {
    const status = doc.data().status || "Active";
    return status === "Active";
  });

  let sent = 0;
  const chunkSize = 400;
  for (let index = 0; index < recipients.length; index += chunkSize) {
    const batch = db.batch();
    recipients.slice(index, index + chunkSize).forEach((doc) => {
      const ref = db.collection("notifications").doc();
      batch.set(ref, {
        toUid: doc.id,
        text: message,
        read: false,
        event: "broadcast",
        url: "/index.html?view=dashboard",
        audience,
        sentBy: request.auth.uid,
        createdAt: FieldValue.serverTimestamp(),
      });
      sent += 1;
    });
    await batch.commit();
  }

  await writeAudit({
    actorUid: request.auth.uid,
    actorRole: request.auth.token.role,
    action: "notification.dispatched",
    targetType: "audience",
    targetId: audience,
    details: `Sent "${message.slice(0, 80)}" to ${sent} active user(s)`,
  });

  return { audience, sent };
});
