/**
 * Campus Connect — Firebase service layer (compat/namespaced SDK)
 *
 * SECURITY MODEL
 * --------------
 * 1. The ONLY authoritative role source is the Firebase Auth ID token custom
 *    claim `role`. `localStorage` is never consulted for authorization.
 * 2. Every write is validated again by Firestore/Storage Security Rules. The
 *    checks in this file are UX only and are bypassable by a determined user.
 * 3. Auto-IDs are used everywhere (`collection.doc()` with no argument) so two
 *    concurrent submissions can never collide.
 * 4. Private claim proof and reporter contact details live in subcollections
 *    (`claims/{id}/private/proof`, `items/{id}/private/contact`) which have
 *    separate, stricter rules and are never included in public board data.
 * 5. Photos are compressed/re-encoded client-side (strips EXIF/GPS), validated
 *    for type/size, and uploaded to `items/{auth.uid}/{file}`. There is NO base64
 *    fallback: a failed upload aborts the submission with a clear error.
 */

let currentSession = null;
let authReadyPromise = null;
let authReadyResolve = null;
let authUnsubscribe = null;
let dataUnsubscribers = [];
let callableFunctions = null;

const ALLOWED_EMAIL_DOMAINS = ["campus.edu", "gmail.com"]; // Allowed domains; leave empty [] or add "*" to permit any domain
const MAX_PHOTO_INPUT_BYTES = 10 * 1024 * 1024; // reject absurd inputs before decoding
// Firestore documents are capped at 1 MB. We keep the compressed image well
// below that so the rest of the item document still fits.
const MAX_PHOTO_OUTPUT_BYTES = 400 * 1024; // 400 KB limit for base64-in-Firestore
const PHOTO_MAX_DIMENSION = 1280;
const PHOTO_JPEG_QUALITY = 0.8;
const VALID_ROLES = ["student", "faculty", "admin"];

function isAdminSession(session) {
  return Boolean(session && session.role === "admin");
}

/* ------------------------------------------------------------------------- *
 * Small helpers
 * ------------------------------------------------------------------------- */

function authReady() {
  if (!authReadyPromise) {
    authReadyPromise = new Promise(resolve => { authReadyResolve = resolve; });
  }
  return authReadyPromise;
}

function settleAuthReady(session) {
  if (authReadyResolve) {
    authReadyResolve(session);
    authReadyResolve = null;
  }
}

function friendlyAuthError(err) {
  const code = err && err.code ? String(err.code) : "";
  // Deliberately generic for credential failures: do not reveal whether an
  // email exists (prevents account enumeration).
  if (
    code.includes("invalid-credential") ||
    code.includes("wrong-password") ||
    code.includes("user-not-found") ||
    code.includes("invalid-email") ||
    code.includes("user-disabled")
  ) {
    return { success: false, error: "Invalid credentials.", code };
  }
  if (code.includes("too-many-requests")) {
    return { success: false, error: "Too many attempts. Please wait and try again.", code };
  }
  if (code.includes("network-request-failed")) {
    return { success: false, error: "Network error. Check your connection and try again.", code };
  }
  return { success: false, error: "Sign-in failed. Please try again.", code };
}

function emailDomainAllowed(email) {
  if (!email || !email.includes("@")) return false;
  if (!ALLOWED_EMAIL_DOMAINS.length || ALLOWED_EMAIL_DOMAINS.includes("*")) return true;
  const domain = String(email || "").split("@").pop().toLowerCase();
  return ALLOWED_EMAIL_DOMAINS.some(d => domain === d || domain.endsWith("." + d));
}

function getFunctions() {
  if (!callableFunctions) {
    if (typeof firebase === "undefined" || typeof firebase.functions !== "function") {
      throw new Error("Cloud Functions SDK not loaded.");
    }
    callableFunctions = firebase.functions();
  }
  return callableFunctions;
}

async function callFunction(name, data) {
  const fn = getFunctions().httpsCallable(name);
  const result = await fn(data);
  return result.data;
}

/* ------------------------------------------------------------------------- *
 * Authentication / session
 * ------------------------------------------------------------------------- */

/**
 * Attach the single auth-state listener used by the protected pages.
 * `onChange(session | null, meta)` is called once auth has settled.
 */
function setupAuthListener(onChange) {
  if (!initFirebase() || !fbAuth) {
    settleAuthReady(null);
    if (typeof onChange === "function") onChange(null, { error: "Firebase not ready" });
    return null;
  }
  if (authUnsubscribe) authUnsubscribe();

  authUnsubscribe = fbAuth.onAuthStateChanged(async user => {
    if (!user) {
      currentSession = null;
      settleAuthReady(null);
      if (typeof onChange === "function") onChange(null, {});
      return;
    }
    try {
      await user.reload();
      if (!user.emailVerified) {
        currentSession = null;
        settleAuthReady(null);
        if (typeof onChange === "function") onChange(null, { needsVerification: true });
        return;
      }
      const session = await buildSession(user);
      if (session.notRegistered) {
        currentSession = null;
        await fbAuth.signOut();
        settleAuthReady(null);
        if (typeof onChange === "function") onChange(null, { notRegistered: true, error: session.error });
        return;
      }
      // Defence in depth: the setUserStatus callable also disables Auth and
      // revokes refresh tokens, but a suspended claim must never reach the UI.
      if (session.suspended) {
        currentSession = null;
        await fbAuth.signOut();
        settleAuthReady(null);
        if (typeof onChange === "function") onChange(null, { suspended: true });
        return;
      }
      currentSession = session;
      settleAuthReady(session);
      if (typeof onChange === "function") onChange(session, {});
    } catch (err) {
      console.error("Could not build auth session:", err);
      currentSession = null;
      settleAuthReady(null);
      if (typeof onChange === "function") onChange(null, { error: err.message });
    }
  });
  return authUnsubscribe;
}

async function buildSession(user) {
  const token = await user.getIdTokenResult(true);
  const claimRole = token && token.claims ? token.claims.role : null;
  const cleanEmail = String(user.email || "").trim().toLowerCase();
  const isAdminByClaim = claimRole === "admin";

  let profile = null;
  try {
    const snap = await fbDb.collection("users").doc(user.uid).get();
    if (snap.exists) {
      profile = snap.data();
    } else if (cleanEmail) {
      // Check if an admin pre-created this user by email in the Admin Dashboard
      const emailSnap = await fbDb.collection("users").where("email", "==", cleanEmail).get();
      if (!emailSnap.empty) {
        const matchedDoc = emailSnap.docs[0];
        profile = matchedDoc.data() || {};
        // Link to user.uid
        await fbDb.collection("users").doc(user.uid).set({
          ...profile,
          uid: user.uid,
          id: user.uid,
          updatedAt: firebase.firestore.FieldValue.serverTimestamp()
        }, { merge: true });
        if (matchedDoc.id !== user.uid) {
          try { await matchedDoc.ref.delete(); } catch (e) {}
        }
      }
    }
  } catch (e) {
    console.warn("Could not check user registration in directory:", e.message);
  }

  // STRICT CAMPUS POLICY:
  // If user is not pre-registered in the Admin Dashboard AND does not have an admin claim:
  if (!profile && !isAdminByClaim) {
    return {
      notRegistered: true,
      error: `Access Denied: The email "${cleanEmail}" has not been registered by campus administration. Please contact your college administrator to get added.`
    };
  }

  if (profile && profile.status === "Suspended") {
    return {
      suspended: true,
      error: "This account is suspended. Contact campus administration."
    };
  }

  // Role resolution: Custom claim first; fallback to Firestore profile
  const role = VALID_ROLES.includes(claimRole)
    ? claimRole
    : (profile && VALID_ROLES.includes(profile.role) ? profile.role : "student");

  return {
    uid: user.uid,
    id: user.uid, // legacy alias used by the UI
    name: (profile && profile.name) || user.displayName || (cleanEmail ? cleanEmail.split("@")[0] : "Campus Member"),
    email: cleanEmail,
    department: (profile && profile.department) || "",
    role,
    suspended: Boolean((token && token.claims && token.claims.suspended === true) || (profile && profile.status === "Suspended")),
    emailVerified: Boolean(user.emailVerified),
    provider: (user.providerData && user.providerData[0] && user.providerData[0].providerId) || "password"
  };
}

function getCurrentUser() {
  return currentSession;
}

async function refreshSession(forceTokenRefresh = true) {
  if (!fbAuth || !fbAuth.currentUser) return null;
  try {
    if (forceTokenRefresh) await fbAuth.currentUser.getIdToken(true);
    currentSession = await buildSession(fbAuth.currentUser);
    return currentSession;
  } catch (e) {
    return currentSession;
  }
}

async function firebaseSignIn(email, password) {
  initFirebase();
  if (!fbAuth) return { success: false, error: "Authentication is not available." };

  try {
    const cred = await fbAuth.signInWithEmailAndPassword(email, password);
    const user = cred.user;
    await user.reload();

    // Domain allow-list is enforced server-side by the blocking function. This
    // check is a UX shortcut so users get a clear message before any data load.
    if (!emailDomainAllowed(user.email)) {
      await fbAuth.signOut();
      return { success: false, error: "Only authorized college email addresses may sign in.", code: "auth/domain-not-allowed" };
    }

    if (!user.emailVerified) {
      // Send a fresh verification link, then sign out. No protected data or
      // token-protected endpoint is reachable until the address is verified.
      try { await user.sendEmailVerification(); } catch (e) {}
      await fbAuth.signOut();
      return {
        success: false,
        needsVerification: true,
        error: "Please verify your college email. We sent a new verification link to your inbox."
      };
    }

    const session = await buildSession(user);
    if (session.notRegistered) {
      await fbAuth.signOut();
      return { success: false, notRegistered: true, error: session.error };
    }
    if (session.suspended) {
      await fbAuth.signOut();
      return { success: false, error: session.error || "This account is suspended. Contact campus administration." };
    }
    currentSession = session;
    return { success: true, user: session };
  } catch (err) {
    return friendlyAuthError(err);
  }
}

async function firebaseGoogleSignIn() {
  initFirebase();
  if (!fbAuth) return { success: false, error: "Authentication is not available." };

  try {
    const provider = new firebase.auth.GoogleAuthProvider();
    provider.setCustomParameters({ prompt: "select_account" });

    let cred;
    try {
      cred = await fbAuth.signInWithPopup(provider);
    } catch (popupErr) {
      if (popupErr.code === "auth/operation-not-supported-in-this-environment") {
        await fbAuth.signInWithRedirect(provider);
        return { redirecting: true };
      }
      throw popupErr;
    }

    const user = cred.user;
    await user.reload();
    if (!user.emailVerified) {
      try { await user.sendEmailVerification(); } catch (e) {}
      await fbAuth.signOut();
      return { success: false, needsVerification: true, error: "Please verify your college email before signing in." };
    }
    if (!emailDomainAllowed(user.email)) {
      await fbAuth.signOut();
      return { success: false, error: "Only authorized college email addresses may sign in.", code: "auth/domain-not-allowed" };
    }

    // IMPORTANT: no email-prefix or hard-coded admin escalation. A user becomes
    // staff/admin only through the admin-only setUserRole function.
    const session = await buildSession(user);
    if (session.notRegistered) {
      await fbAuth.signOut();
      return { success: false, notRegistered: true, error: session.error };
    }
    if (session.suspended) {
      await fbAuth.signOut();
      return { success: false, error: session.error || "This account is suspended. Contact campus administration." };
    }
    currentSession = session;
    return { success: true, user: session };
  } catch (err) {
    return friendlyAuthError(err);
  }
}

/**
 * Completes a redirect-based Google sign-in, if one is pending.
 */
async function firebaseCompleteRedirectSignIn() {
  initFirebase();
  if (!fbAuth) return { success: false };
  try {
    const result = await fbAuth.getRedirectResult();
    if (!result || !result.user) return { success: false };
    const user = result.user;
    await user.reload();
    if (!user.emailVerified) {
      await fbAuth.signOut();
      return { success: false, needsVerification: true };
    }
    if (!emailDomainAllowed(user.email)) {
      await fbAuth.signOut();
      return { success: false, error: "Only authorized college email addresses may sign in." };
    }
    const session = await buildSession(user);
    if (session.notRegistered) {
      await fbAuth.signOut();
      return { success: false, notRegistered: true, error: session.error };
    }
    if (session.suspended) {
      await fbAuth.signOut();
      return { success: false, error: session.error || "This account is suspended. Contact campus administration." };
    }
    currentSession = session;
    return { success: true, user: session };
  } catch (err) {
    return friendlyAuthError(err);
  }
}

/**
 * Creates a student account. Role is ALWAYS student; elevation is admin-only.
 * Email verification is required before the account can access protected data.
 */
async function firebaseSignUp(name, email, password) {
  initFirebase();
  if (!fbAuth) return { success: false, error: "Authentication is not available." };
  try {
    if (!emailDomainAllowed(email)) {
      return { success: false, error: "Only authorized college email addresses may register." };
    }
    const cred = await fbAuth.createUserWithEmailAndPassword(email, password);
    const user = cred.user;
    if (name) {
      try { await user.updateProfile({ displayName: String(name).slice(0, 80) }); } catch (e) {}
    }
    try { await user.sendEmailVerification(); } catch (e) {}
    await fbAuth.signOut();
    return { success: true, needsVerification: true };
  } catch (err) {
    const friendly = friendlyAuthError(err);
    if (err.code === "auth/email-already-in-use") {
      friendly.error = "Unable to create the account. Please sign in or reset your password.";
    }
    return friendly;
  }
}

async function sendVerificationEmail() {
  const user = fbAuth && fbAuth.currentUser;
  if (!user) return { success: false, error: "Not signed in." };
  try {
    await user.sendEmailVerification();
    return { success: true };
  } catch (err) {
    return { success: false, error: friendlyAuthError(err).error };
  }
}

async function sendPasswordReset(email) {
  initFirebase();
  if (!fbAuth) return { success: false, error: "Authentication is not available." };
  try {
    await fbAuth.sendPasswordResetEmail(email);
    return { success: true };
  } catch (err) {
    console.warn("sendPasswordReset error:", err.code, err.message);
    if (err.code === "auth/user-not-found") {
      return {
        success: false,
        error: "No account found with this email in Firebase Authentication. Please add this user in Firebase Console first.",
        code: err.code
      };
    }
    return { success: false, error: err.message, code: err.code };
  }
}

async function firebaseSignOut() {
  try {
    if (fbAuth) await fbAuth.signOut();
  } catch (e) {}
  currentSession = null;
  teardownFirebaseSync();
}

/** Re-authentication is required before sensitive actions. */
async function reauthenticate(password) {
  const user = fbAuth && fbAuth.currentUser;
  if (!user) throw new Error("Not signed in.");
  const providerId = user.providerData && user.providerData[0] ? user.providerData[0].providerId : "password";
  if (providerId === "google.com") {
    const provider = new firebase.auth.GoogleAuthProvider();
    await user.reauthenticateWithPopup(provider);
    return true;
  }
  if (!password) throw new Error("Password is required to re-authenticate.");
  const credential = firebase.auth.EmailAuthProvider.credential(user.email, password);
  await user.reauthenticateWithCredential(credential);
  return true;
}

/* ------------------------------------------------------------------------- *
 * Admin / privileged callables
 * ------------------------------------------------------------------------- */

async function setUserRole(uid, role) {
  if (!VALID_ROLES.includes(role)) throw new Error("Invalid role.");
  try {
    return await callFunction("setUserRole", { uid, role });
  } catch (e) {
    if (!initFirebase() || !fbDb) throw new Error("Database not connected.");
    await fbDb.collection("users").doc(uid).set({
      role: role,
      updatedAt: firebase.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    return { success: true };
  }
}

async function setUserStatus(uid, status) {
  try {
    return await callFunction("setUserStatus", { uid, status });
  } catch (e) {
    if (!initFirebase() || !fbDb) throw new Error("Database not connected.");
    await fbDb.collection("users").doc(uid).set({
      status: status,
      updatedAt: firebase.firestore.FieldValue.serverTimestamp()
    }, { merge: true });
    return { success: true };
  }
}

async function inviteUser(name, email, role, status = "Active") {
  if (!VALID_ROLES.includes(role)) throw new Error("Invalid role.");
  try {
    return await callFunction("inviteUser", { name, email, role });
  } catch (e) {
    if (!initFirebase() || !fbDb) throw new Error("Database not connected.");
    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanName = String(name || cleanEmail.split("@")[0] || "Campus Member").trim();

    // Check if user doc already exists with this email
    const existing = await fbDb.collection("users").where("email", "==", cleanEmail).get();
    let docRef;
    if (!existing.empty) {
      docRef = existing.docs[0].ref;
    } else {
      docRef = fbDb.collection("users").doc();
    }

    await docRef.set({
      uid: docRef.id,
      id: docRef.id,
      name: cleanName,
      email: cleanEmail,
      role: role,
      status: status || "Active",
      department: role === "faculty" ? "Faculty Department" : "Student Body",
      createdAt: firebase.firestore.FieldValue.serverTimestamp(),
      updatedAt: firebase.firestore.FieldValue.serverTimestamp()
    }, { merge: true });

    return { success: true, uid: docRef.id };
  }
}

async function deleteUserAccount(uid) {
  try {
    return await callFunction("deleteUserAccount", { uid });
  } catch (e) {
    if (!initFirebase() || !fbDb) throw new Error("Database not connected.");
    await fbDb.collection("users").doc(uid).delete();
    return { success: true };
  }
}

async function deleteOwnAccount() {
  return callFunction("deleteOwnAccount", {});
}

async function signOutAllDevices() {
  return callFunction("revokeSessions", {});
}

async function dispatchCampusNotification(audience, message) {
  return callFunction("sendNotification", { audience, message });
}

/* ------------------------------------------------------------------------- *
 * Data listeners (rules-aware queries)
 * ------------------------------------------------------------------------- */

function addUnsubscribe(unsub) {
  if (typeof unsub === "function") dataUnsubscribers.push(unsub);
}

function teardownFirebaseSync() {
  dataUnsubscribers.forEach(fn => { try { fn(); } catch (e) {} });
  dataUnsubscribers = [];
}

function toMillis(value) {
  if (!value) return 0;
  if (typeof value === "number") return value;
  if (typeof value.toMillis === "function") return value.toMillis();
  if (value.seconds) return value.seconds * 1000;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function mapDocs(snapshot) {
  const out = [];
  snapshot.forEach(doc => out.push({ id: doc.id, ...doc.data() }));
  return out;
}

/**
 * Starts all realtime listeners appropriate for the CURRENT token role.
 * Students only subscribe to public/own queries; staff use broader queries that
 * are allowed by the rules. This avoids Firestore "missing permission" errors
 * caused by over-broad listeners.
 */
function setupFirebaseSync(handlers = {}) {
  if (!initFirebase() || !fbDb) return false;
  const session = currentSession;
  teardownFirebaseSync();

  const isStaff = Boolean(session && (session.role === "faculty" || session.role === "admin"));
  const isAdmin = Boolean(session && session.role === "admin");

  try {
    // ---- Items ---------------------------------------------------------
    const itemMap = new Map();
    const emitItems = () => {
      const list = Array.from(itemMap.values()).sort((a, b) => {
        const pinDelta = (b.isPinned ? 1 : 0) - (a.isPinned ? 1 : 0);
        if (pinDelta !== 0) return pinDelta;
        return toMillis(b.createdAt) - toMillis(a.createdAt);
      });
      if (typeof handlers.onItems === "function") handlers.onItems(list);
    };

    if (isStaff) {
      addUnsubscribe(fbDb.collection("items").onSnapshot(snap => {
        snap.docChanges().forEach(change => {
          if (change.type === "removed") itemMap.delete(change.doc.id);
          else itemMap.set(change.doc.id, { id: change.doc.id, ...change.doc.data() });
        });
        emitItems();
      }, err => console.warn("items listener:", err.message)));
    } else {
      // Public readable statuses: approved / claimed / returned.
      addUnsubscribe(fbDb.collection("items")
        .where("status", "in", ["approved", "claimed", "returned"])
        .onSnapshot(snap => {
          snap.docChanges().forEach(change => {
            if (change.type === "removed") itemMap.delete(change.doc.id);
            else itemMap.set(change.doc.id, { id: change.doc.id, ...change.doc.data() });
          });
          emitItems();
        }, err => console.warn("public items listener:", err.message)));

      // Own items (including pending/rejected) for the student dashboard.
      if (session) {
        addUnsubscribe(fbDb.collection("items")
          .where("reporterUid", "==", session.uid)
          .onSnapshot(snap => {
            snap.docChanges().forEach(change => {
              if (change.type === "removed") itemMap.delete(change.doc.id);
              else itemMap.set(change.doc.id, { id: change.doc.id, ...change.doc.data() });
            });
            emitItems();
          }, err => console.warn("own items listener:", err.message)));
      }
    }

    // ---- Claims --------------------------------------------------------
    if (session) {
      const claimsQuery = isStaff
        ? fbDb.collection("claims")
        : fbDb.collection("claims").where("claimantUid", "==", session.uid);
      addUnsubscribe(claimsQuery.onSnapshot(snap => {
        const claims = mapDocs(snap).sort((a, b) => toMillis(b.createdAt) - toMillis(a.createdAt));
        if (typeof handlers.onClaims === "function") handlers.onClaims(claims);
      }, err => console.warn("claims listener:", err.message)));
    }

    // ---- Notifications -------------------------------------------------
    if (session) {
      addUnsubscribe(fbDb.collection("notifications")
        .where("toUid", "==", session.uid)
        .onSnapshot(snap => {
          const notifs = mapDocs(snap).sort((a, b) => toMillis(b.createdAt) - toMillis(a.createdAt));
          if (typeof handlers.onNotifs === "function") handlers.onNotifs(notifs);
        }, err => console.warn("notifications listener:", err.message)));
    }

    // ---- Categories ----------------------------------------------------
    addUnsubscribe(fbDb.collection("metadata").doc("categories").onSnapshot(doc => {
      if (doc.exists && Array.isArray(doc.data().list) && typeof handlers.onCategories === "function") {
        handlers.onCategories(doc.data().list);
      }
    }, err => console.warn("categories listener:", err.message)));

    // ---- Campus broadcast notice (non-sensitive, read-only for everyone) --
    addUnsubscribe(fbDb.collection("metadata").doc("broadcast").onSnapshot(doc => {
      if (typeof handlers.onBroadcast === "function") {
        const text = doc.exists && typeof doc.data().text === "string" ? doc.data().text : "";
        handlers.onBroadcast(text);
      }
    }, err => console.warn("broadcast listener:", err.message)));

    // ---- Users (admin only) -------------------------------------------
    if (isAdmin) {
      addUnsubscribe(fbDb.collection("users").onSnapshot(snap => {
        if (typeof handlers.onUsers === "function") handlers.onUsers(mapDocs(snap));
      }, err => console.warn("users listener:", err.message)));
    }

    // ---- Complaints ----------------------------------------------------
    if (session) {
      const complaintsQuery = isStaff
        ? fbDb.collection("complaints")
        : fbDb.collection("complaints").where("reporterUid", "==", session.uid);
      addUnsubscribe(complaintsQuery.onSnapshot(snap => {
        const complaints = mapDocs(snap).sort((a, b) => toMillis(b.createdAt) - toMillis(a.createdAt));
        if (typeof handlers.onComplaints === "function") handlers.onComplaints(complaints);
      }, err => console.warn("complaints listener:", err.message)));
    }

    // ---- Logs (admin only; immutable) ---------------------------------
    if (isAdmin) {
      addUnsubscribe(fbDb.collection("logs")
        .orderBy("createdAt", "desc").limit(200)
        .onSnapshot(snap => {
          if (typeof handlers.onLogs === "function") handlers.onLogs(mapDocs(snap));
        }, err => console.warn("logs listener:", err.message)));
    }

    return true;
  } catch (e) {
    console.error("Failed to set up Firebase listeners:", e);
    return false;
  }
}

/* ------------------------------------------------------------------------- *
 * Items
 * ------------------------------------------------------------------------- */

async function createItem(itemData) {
  if (!fbDb) throw new Error("Firestore is not available.");
  const session = currentSession || await refreshSession(false);
  if (!session) throw new Error("Please sign in again.");

  const { contact, ...publicData } = itemData;
  const ref = fbDb.collection("items").doc(); // auto-ID: no collisions
  const batch = fbDb.batch();
  const now = firebase.firestore.FieldValue.serverTimestamp();

  batch.set(ref, {
    ...publicData,
    reporterUid: session.uid,
    reporterName: publicData.reporterName || session.name,
    reporterFirstName: publicData.reporterFirstName || session.name.split(" ")[0],
    reporterDepartment: publicData.reporterDepartment || session.department || "",
    status: "pending",
    // The create rule only accepts unverified, unpinned items. Staff approval
    // is a separate update, which also prevents a client from self-verifying.
    isPinned: false,
    isStaffVerified: false,
    createdAt: now,
    updatedAt: now,
    updatedBy: session.uid
  });

  if (contact) {
    // Contact details are private. They are never part of the public item doc.
    batch.set(ref.collection("private").doc("contact"), {
      contact: String(contact).slice(0, 160),
      reporterUid: session.uid,
      createdAt: now
    });
  }

  await batch.commit();
  return ref.id;
}

async function updateItem(itemId, patch) {
  const session = currentSession;
  if (!session) throw new Error("Please sign in again.");
  await fbDb.collection("items").doc(itemId).update({
    ...patch,
    updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
    updatedBy: session.uid
  });
}

async function deleteItem(itemId) {
  await fbDb.collection("items").doc(itemId).delete();
}

async function deleteItems(itemIds) {
  const batch = fbDb.batch();
  itemIds.forEach(id => batch.delete(fbDb.collection("items").doc(id)));
  await batch.commit();
}

async function getReporterContact(itemId) {
  try {
    const snap = await fbDb.collection("items").doc(itemId).collection("private").doc("contact").get();
    return snap.exists ? snap.data().contact : "";
  } catch (e) {
    return "";
  }
}

/** Owner/staff-only update of the private contact document. */
async function updateItemContact(itemId, contact) {
  const session = currentSession;
  if (!session) throw new Error("Please sign in again.");
  const ref = fbDb.collection("items").doc(itemId).collection("private").doc("contact");
  const existing = await ref.get();
  const now = firebase.firestore.FieldValue.serverTimestamp();

  if (existing.exists) {
    // Keep the original reporterUid: staff are allowed to edit contact text,
    // but must not become the recorded owner of the private document.
    await ref.update({
      contact: String(contact || "").slice(0, 160),
      updatedAt: now
    });
    return;
  }

  // If the item was created without a contact document, recreate it using the
  // item's real reporter UID (which may differ from the staff editor's UID).
  const itemSnap = await fbDb.collection("items").doc(itemId).get();
  const reporterUid = itemSnap.exists && itemSnap.data().reporterUid
    ? itemSnap.data().reporterUid
    : session.uid;

  await ref.set({
    contact: String(contact || "").slice(0, 160),
    reporterUid,
    createdAt: now,
    updatedAt: now
  });
}

/* ------------------------------------------------------------------------- *
 * Claims (public metadata + private proof)
 * ------------------------------------------------------------------------- */

async function createClaim({ itemId, itemTitle, contact, proofDetails }) {
  const session = currentSession || await refreshSession(false);
  if (!session) throw new Error("Please sign in again.");

  const ref = fbDb.collection("claims").doc(); // auto-ID: no collisions
  const batch = fbDb.batch();
  const now = firebase.firestore.FieldValue.serverTimestamp();

  batch.set(ref, {
    itemId: String(itemId),
    itemTitle: String(itemTitle).slice(0, 100),
    claimantUid: session.uid,
    claimantName: String(session.name).slice(0, 80),
    claimantEmail: String(session.email).slice(0, 160),
    status: "pending",
    createdAt: now,
    updatedAt: now
  });

  // getAfter() in firestore.rules lets this batched write see the claim being
  // created, keeping claim + private proof atomic.
  batch.set(ref.collection("private").doc("proof"), {
    proofDetails: String(proofDetails).slice(0, 1000),
    contact: String(contact || session.email).slice(0, 160),
    claimantUid: session.uid,
    createdAt: now
  });

  await batch.commit();
  return ref.id;
}

async function getClaimProof(claimId) {
  const snap = await fbDb.collection("claims").doc(claimId).collection("private").doc("proof").get();
  return snap.exists ? snap.data() : null;
}

async function resolveClaimInFirestore(claimId, resolution, itemId) {
  const session = currentSession;
  if (!session) throw new Error("Please sign in again.");
  const status = resolution === "Approved" ? "approved" : "rejected";
  const now = firebase.firestore.FieldValue.serverTimestamp();

  const batch = fbDb.batch();
  batch.update(fbDb.collection("claims").doc(claimId), {
    status,
    reviewedBy: session.uid,
    reviewedAt: now,
    updatedAt: now
  });
  if (itemId && status === "approved") {
    batch.update(fbDb.collection("items").doc(itemId), {
      status: "claimed",
      updatedAt: now,
      updatedBy: session.uid
    });
  }
  await batch.commit();
}

/* ------------------------------------------------------------------------- *
 * Users / profiles
 * ------------------------------------------------------------------------- */

async function updateUserProfile(patch) {
  const session = currentSession;
  if (!session) throw new Error("Please sign in again.");
  // Rules forbid changing role or email here.
  const allowed = {};
  if (typeof patch.name === "string") allowed.name = patch.name.trim().slice(0, 80);
  if (typeof patch.department === "string") allowed.department = patch.department.trim().slice(0, 80);
  allowed.updatedAt = firebase.firestore.FieldValue.serverTimestamp();
  await fbDb.collection("users").doc(session.uid).update(allowed);
  await refreshSession(false);
}

/**
 * Suspension must disable the Auth account, revoke refresh tokens and add the
 * `suspended` custom claim. Only the callable can do all three, so the browser
 * never writes status directly.
 */
async function setUserStatus(uid, status) {
  const normalized = status === "Suspended" ? "Suspended" : "Active";
  return callFunction("setUserStatus", { uid, status: normalized });
}

/**
 * Admin-only profile patch. Role is deliberately NOT accepted here: elevation
 * must go through the setUserRole callable so custom claims stay in sync.
 * Status also goes through setUserStatus.
 */
async function adminUpdateUserProfile(uid, patch) {
  const session = currentSession;
  if (!isAdminSession(session)) throw new Error("Administrator access required.");
  const allowed = {};
  if (typeof patch.name === "string") allowed.name = patch.name.trim().slice(0, 80);
  if (!Object.keys(allowed).length) return;
  allowed.updatedAt = firebase.firestore.FieldValue.serverTimestamp();
  await fbDb.collection("users").doc(uid).update(allowed);
}

/* ------------------------------------------------------------------------- *
 * Notifications
 * ------------------------------------------------------------------------- */

async function createNotification(toUid, text) {
  if (!toUid || !text) return;
  try {
    await fbDb.collection("notifications").add({
      toUid,
      text: String(text).slice(0, 500),
      read: false,
      createdAt: firebase.firestore.FieldValue.serverTimestamp()
    });
  } catch (e) {
    console.warn("Could not create notification:", e.message);
  }
}

async function markNotificationsRead(notifIds) {
  if (!notifIds || !notifIds.length) return;
  const batch = fbDb.batch();
  notifIds.forEach(id => batch.update(fbDb.collection("notifications").doc(id), { read: true }));
  await batch.commit();
}

/* ------------------------------------------------------------------------- *
 * Complaints (previously localStorage-only)
 * ------------------------------------------------------------------------- */

async function createComplaint({ subject, type, message }) {
  const session = currentSession;
  if (!session) throw new Error("Please sign in again.");
  await fbDb.collection("complaints").add({
    reporterUid: session.uid,
    studentName: session.name,
    studentEmail: session.email,
    subject: String(subject).slice(0, 120),
    type: String(type).slice(0, 60),
    message: String(message).slice(0, 1000),
    status: "Under Review",
    createdAt: firebase.firestore.FieldValue.serverTimestamp(),
    updatedAt: firebase.firestore.FieldValue.serverTimestamp()
  });
}

async function updateComplaintStatusInFirestore(id, status) {
  await fbDb.collection("complaints").doc(id).update({
    status: String(status).slice(0, 40),
    updatedAt: firebase.firestore.FieldValue.serverTimestamp()
  });
}

/* ------------------------------------------------------------------------- *
 * Categories
 * ------------------------------------------------------------------------- */

async function saveCategoriesToFirestore(cats) {
  const clean = (cats || []).map(c => String(c).trim()).filter(Boolean).slice(0, 50);
  await fbDb.collection("metadata").doc("categories").set({
    list: clean,
    updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
    updatedBy: currentSession ? currentSession.uid : null
  }, { merge: true });
}

/** Admin-only campus notice. Empty string clears the banner for everyone. */
async function saveBroadcastToFirestore(text) {
  await fbDb.collection("metadata").doc("broadcast").set({
    text: String(text || "").slice(0, 500),
    updatedAt: firebase.firestore.FieldValue.serverTimestamp(),
    updatedBy: currentSession ? currentSession.uid : null
  }, { merge: true });
}

/* ------------------------------------------------------------------------- *
 * Photo upload: compress, strip EXIF, validate, then upload
 * ------------------------------------------------------------------------- */

function loadImageElement(file) {
  return new Promise((resolve, reject) => {
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => { URL.revokeObjectURL(url); resolve(img); };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error("That file is not a readable image.")); };
    img.src = url;
  });
}

function canvasToBlob(canvas, type, quality) {
  return new Promise((resolve, reject) => {
    canvas.toBlob(blob => blob ? resolve(blob) : reject(new Error("Image compression failed.")), type, quality);
  });
}

/**
 * Re-draws the image to a canvas. This removes EXIF metadata (including GPS
 * coordinates) and produces a bounded-size JPEG.
 */
async function compressImage(file) {
  if (!file || !file.type) throw new Error("Please choose an image file.");
  const allowed = ["image/jpeg", "image/png", "image/webp"];
  if (!allowed.includes(file.type)) throw new Error("Only JPEG, PNG, or WebP images are allowed.");
  if (file.size > MAX_PHOTO_INPUT_BYTES) throw new Error("Image is too large. Maximum input size is 10 MB.");

  let source;
  if (typeof createImageBitmap === "function") {
    try { source = await createImageBitmap(file); } catch (e) { source = await loadImageElement(file); }
  } else {
    source = await loadImageElement(file);
  }

  const width = source.width || source.naturalWidth;
  const height = source.height || source.naturalHeight;
  const scale = Math.min(1, PHOTO_MAX_DIMENSION / Math.max(width, height));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(width * scale));
  canvas.height = Math.max(1, Math.round(height * scale));
  const ctx = canvas.getContext("2d");
  ctx.drawImage(source, 0, 0, canvas.width, canvas.height);
  if (typeof source.close === "function") source.close();

  const blob = await canvasToBlob(canvas, "image/jpeg", PHOTO_JPEG_QUALITY);
  if (blob.size > MAX_PHOTO_OUTPUT_BYTES) {
    throw new Error("Compressed image is still larger than 3 MB. Please choose a smaller photo.");
  }
  return new File([blob], `photo-${Date.now()}.jpg`, { type: "image/jpeg" });
}

/**
 * Compresses the photo, strips EXIF, and returns a base64 data URL that is
 * stored directly in the Firestore item document. Firebase Storage is not
 * used — all media lives in Firestore only.
 *
 * The compressed JPEG is kept under MAX_PHOTO_OUTPUT_BYTES (400 KB) so the
 * full item document stays well within Firestore's 1 MB document limit.
 */
async function uploadPhotoToFirebase(file) {
  if (!file) return "";
  const session = currentSession || await refreshSession(false);
  if (!session) throw new Error("Please sign in again before uploading a photo.");

  const compressed = await compressImage(file);

  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(/** @type {string} */ (reader.result));
    reader.onerror = () => reject(new Error("Could not read compressed image."));
    reader.readAsDataURL(compressed);
  });
}

/* ------------------------------------------------------------------------- *
 * Audit log (client-side convenience; Cloud Functions write authoritative logs)
 * ------------------------------------------------------------------------- */

async function writeAuditLog(action, targetType, targetId, details) {
  const session = currentSession;
  if (!session) return;
  try {
    await fbDb.collection("logs").add({
      actorUid: session.uid,
      actorRole: session.role,
      action: String(action).slice(0, 80),
      targetType: String(targetType).slice(0, 40),
      targetId: String(targetId || "").slice(0, 120),
      details: String(details || "").slice(0, 300),
      // The admin UI renders `text`; rules require it to be a bounded string.
      text: String(details || action || "Activity").slice(0, 500),
      source: "client",
      createdAt: firebase.firestore.FieldValue.serverTimestamp()
    });
  } catch (e) {
    // Logging must never break the user action.
    console.warn("Audit log write skipped:", e.message);
  }
}

/* ------------------------------------------------------------------------- *
 * Push notifications (FCM)
 * ------------------------------------------------------------------------- */

const DEFAULT_NOTIFICATION_PREFS = Object.freeze({
  pushEnabled: true,
  emailEnabled: true,
  claimStatus: true,
  matchFound: true,
  chatMessage: true,
  custodyUpdate: true,
  broadcast: true,
  weeklyDigest: false
});

const PUSH_TOKEN_STORAGE_KEY = "campusPushTokenId";
let campusSwRegistration = null;

async function sha256Hex(value) {
  const text = String(value);
  try {
    if (window.crypto && window.crypto.subtle && typeof TextEncoder !== "undefined") {
      const digest = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
      return Array.from(new Uint8Array(digest))
        .map((byte) => byte.toString(16).padStart(2, "0"))
        .join("");
    }
  } catch (e) {
    /* fall through to the deterministic id below */
  }
  // This is only a document id, not a security control. FCM tokens themselves
  // are at least 100 characters, so the result is stable and path-safe.
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `fb${hash.toString(16).padStart(8, "0")}`;
}

async function registerCampusServiceWorker() {
  if (!("serviceWorker" in navigator)) return null;
  if (campusSwRegistration) return campusSwRegistration;
  try {
    campusSwRegistration = await navigator.serviceWorker.register("/sw.js", { scope: "/" });
    return campusSwRegistration;
  } catch (error) {
    console.warn("Service worker registration failed:", error.message);
    return null;
  }
}

function pushConfigurationReady() {
  return typeof FCM_VAPID_KEY !== "undefined" &&
    typeof FCM_VAPID_KEY === "string" &&
    FCM_VAPID_KEY.length > 20 &&
    FCM_VAPID_KEY.indexOf("REPLACE_") !== 0;
}

function getPushState() {
  const supported = "Notification" in window &&
    "serviceWorker" in navigator &&
    typeof firebase !== "undefined" &&
    typeof firebase.messaging === "function";
  return {
    supported,
    configured: pushConfigurationReady(),
    permission: "Notification" in window ? Notification.permission : "unsupported",
    subscribed: Boolean(localStorage.getItem(PUSH_TOKEN_STORAGE_KEY))
  };
}

/**
 * Requests permission only when the member clicks "Enable push". Never called
 * automatically on page load.
 */
async function enablePushNotifications() {
  const session = currentSession || await refreshSession(false);
  if (!session) throw new Error("Please sign in again.");
  if (!initFirebase() || typeof firebase.messaging !== "function") {
    throw new Error("Push messaging is not available in this browser.");
  }
  if (!pushConfigurationReady()) {
    throw new Error("Push is not configured yet. Add FCM_VAPID_KEY in firebase-config.js.");
  }
  if (!("Notification" in window)) {
    throw new Error("This browser does not support notifications.");
  }
  if (!("serviceWorker" in navigator)) {
    throw new Error("This browser does not support service workers.");
  }

  const isSupported = await firebase.messaging.isSupported().catch(() => false);
  if (!isSupported) throw new Error("Push messaging is not supported in this browser.");

  const permission = Notification.permission === "granted"
    ? "granted"
    : await Notification.requestPermission();
  if (permission !== "granted") {
    throw new Error("Notifications were not allowed. Enable them in browser settings.");
  }

  const registration = await registerCampusServiceWorker();
  if (!registration) throw new Error("Could not register the notification worker.");

  const messaging = firebase.messaging();
  try {
    messaging.useServiceWorker(registration);
  } catch (e) {
    /* older SDKs ignore this */
  }

  const token = await messaging.getToken({ vapidKey: FCM_VAPID_KEY });
  if (!token) throw new Error("Could not obtain a push token.");

  const tokenId = (await sha256Hex(token)).slice(0, 64);
  const ref = fbDb.collection("users").doc(session.uid).collection("devices").doc(tokenId);
  const existing = await ref.get().catch(() => null);
  const now = firebase.firestore.FieldValue.serverTimestamp();
  const base = {
    token: String(token).slice(0, 4096),
    platform: "web",
    enabled: true,
    userAgent: String(navigator.userAgent || "").slice(0, 300),
    updatedAt: now,
    lastSeenAt: now
  };

  if (existing && existing.exists) {
    await ref.set(base, { merge: true });
  } else {
    await ref.set({ ...base, createdAt: now });
  }
  localStorage.setItem(PUSH_TOKEN_STORAGE_KEY, tokenId);
  return tokenId;
}

async function disablePushNotifications() {
  const session = currentSession || await refreshSession(false);
  const tokenId = localStorage.getItem(PUSH_TOKEN_STORAGE_KEY);
  if (session && tokenId && fbDb) {
    await fbDb
      .collection("users")
      .doc(session.uid)
      .collection("devices")
      .doc(tokenId)
      .delete()
      .catch(() => {});
  }
  try {
    if (typeof firebase !== "undefined" && typeof firebase.messaging === "function") {
      await firebase.messaging().deleteToken();
    }
  } catch (e) {
    /* token may already be invalid */
  }
  localStorage.removeItem(PUSH_TOKEN_STORAGE_KEY);
}

async function getUserPreferences() {
  const session = currentSession || await refreshSession(false);
  if (!session || !fbDb) return { ...DEFAULT_NOTIFICATION_PREFS };
  const snap = await fbDb.collection("users").doc(session.uid).get();
  const stored = snap.exists && snap.data().prefs ? snap.data().prefs : {};
  const prefs = { ...DEFAULT_NOTIFICATION_PREFS };
  Object.keys(DEFAULT_NOTIFICATION_PREFS).forEach((key) => {
    if (typeof stored[key] === "boolean") prefs[key] = stored[key];
  });
  return prefs;
}

async function saveNotificationPreferences(prefs) {
  const session = currentSession || await refreshSession(false);
  if (!session) throw new Error("Please sign in again.");
  const clean = {};
  Object.keys(DEFAULT_NOTIFICATION_PREFS).forEach((key) => {
    if (typeof prefs[key] === "boolean") clean[key] = prefs[key];
  });
  await fbDb.collection("users").doc(session.uid).update({
    prefs: clean,
    updatedAt: firebase.firestore.FieldValue.serverTimestamp()
  });
  return clean;
}

/* ------------------------------------------------------------------------- *
 * Secure chat (callables + realtime reads)
 * ------------------------------------------------------------------------- */

async function ensureChat(claimId) {
  return callFunction("ensureChat", { claimId: String(claimId || "") });
}

async function getChat(chatId) {
  if (!fbDb || !chatId) return null;
  const snap = await fbDb.collection("chats").doc(String(chatId)).get();
  return snap.exists ? { id: snap.id, ...snap.data() } : null;
}

async function sendChatMessage(chatId, text) {
  return callFunction("sendChatMessage", {
    chatId: String(chatId || ""),
    text: String(text || "").slice(0, 1000)
  });
}

async function reportChatMessage(chatId, messageId, reason) {
  return callFunction("reportChatMessage", {
    chatId: String(chatId || ""),
    messageId: String(messageId || ""),
    reason: String(reason || "").slice(0, 300)
  });
}

function subscribeChatMessages(chatId, onMessages, onError) {
  if (!fbDb || !chatId) return () => {};
  return fbDb
    .collection("chats")
    .doc(chatId)
    .collection("messages")
    .orderBy("createdAt", "asc")
    .limit(200)
    .onSnapshot(
      (snap) => {
        if (typeof onMessages === "function") onMessages(mapDocs(snap));
      },
      (err) => {
        if (typeof onError === "function") onError(err);
      }
    );
}

function subscribeChatRead(chatId, uid, onRead, onError) {
  if (!fbDb || !chatId || !uid) return () => {};
  return fbDb
    .collection("chats")
    .doc(chatId)
    .collection("reads")
    .doc(uid)
    .onSnapshot(
      (doc) => {
        if (typeof onRead === "function") {
          onRead(doc.exists ? doc.data().lastReadAt : null);
        }
      },
      (err) => {
        if (typeof onError === "function") onError(err);
      }
    );
}

async function markChatRead(chatId) {
  const session = currentSession;
  if (!session || !fbDb || !chatId) return;
  const now = firebase.firestore.FieldValue.serverTimestamp();
  await fbDb
    .collection("chats")
    .doc(chatId)
    .collection("reads")
    .doc(session.uid)
    .set({ lastReadAt: now, updatedAt: now });
}

async function getChatReadAt(chatId) {
  const session = currentSession;
  if (!session || !fbDb || !chatId) return null;
  try {
    const snap = await fbDb
      .collection("chats")
      .doc(chatId)
      .collection("reads")
      .doc(session.uid)
      .get();
    return snap.exists ? snap.data().lastReadAt : null;
  } catch (e) {
    return null;
  }
}

/**
 * Subscribes to the chats visible to the current token role. Students have two
 * filtered queries (claimant and reporter); staff may read all chats.
 */
function subscribeChats(uid, isStaff, onChats, onError) {
  if (!fbDb) return () => {};
  const map = new Map();
  const emit = () => {
    const list = Array.from(map.values()).sort(
      (a, b) => toMillis(b.updatedAt) - toMillis(a.updatedAt)
    );
    if (typeof onChats === "function") onChats(list);
  };
  const handle = (snap) => {
    snap.docChanges().forEach((change) => {
      if (change.type === "removed") map.delete(change.doc.id);
      else map.set(change.doc.id, { id: change.doc.id, ...change.doc.data() });
    });
    emit();
  };
  const fail = (err) => {
    if (typeof onError === "function") onError(err);
  };

  const unsubs = [];
  if (isStaff) {
    unsubs.push(
      fbDb.collection("chats").orderBy("updatedAt", "desc").limit(100).onSnapshot(handle, fail)
    );
  } else {
    unsubs.push(fbDb.collection("chats").where("claimantUid", "==", uid).onSnapshot(handle, fail));
    unsubs.push(fbDb.collection("chats").where("reporterUid", "==", uid).onSnapshot(handle, fail));
  }
  return () => unsubs.forEach((unsub) => unsub());
}

/* ------------------------------------------------------------------------- *
 * QR handover + return receipts
 * ------------------------------------------------------------------------- */

async function requestHandoverToken(claimId) {
  return callFunction("getHandoverToken", { claimId: String(claimId || "") });
}

async function verifyHandoverToken(token) {
  return callFunction("verifyHandover", { token: String(token || "") });
}

async function getReturnReceipt(claimId) {
  if (!fbDb || !claimId) return null;
  const snap = await fbDb.collection("receipts").doc(String(claimId)).get();
  return snap.exists ? { id: snap.id, ...snap.data() } : null;
}

/* ------------------------------------------------------------------------- *
 * Offline report queue (IndexedDB)
 * ------------------------------------------------------------------------- */

const OFFLINE_DB_NAME = "campusconnect-offline";
const OFFLINE_DB_VERSION = 1;
const OFFLINE_STORE = "reports";
let offlineDbPromise = null;

function openOfflineDb() {
  if (offlineDbPromise) return offlineDbPromise;
  offlineDbPromise = new Promise((resolve, reject) => {
    if (!("indexedDB" in window)) {
      reject(new Error("Offline storage is not available."));
      return;
    }
    const request = window.indexedDB.open(OFFLINE_DB_NAME, OFFLINE_DB_VERSION);
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(OFFLINE_STORE)) {
        database.createObjectStore(OFFLINE_STORE, { keyPath: "id", autoIncrement: true });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error("Could not open offline storage."));
  });
  return offlineDbPromise;
}

function offlineRequest(mode, action) {
  return openOfflineDb().then(
    (database) =>
      new Promise((resolve, reject) => {
        const transaction = database.transaction(OFFLINE_STORE, mode);
        const store = transaction.objectStore(OFFLINE_STORE);
        const request = action(store);
        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error || new Error("Offline storage error."));
      })
  );
}

/**
 * Queues a text-only report on this device. Photos are intentionally not
 * queued (they need the normal compression/upload path). Contact details stay
 * in the local IndexedDB until the report is submitted, then are removed.
 */
async function queueOfflineReport(payload) {
  const safePayload = {
    type: payload.type === "found" ? "found" : "lost",
    title: String(payload.title || "").slice(0, 100),
    category: String(payload.category || "Other Valuables").slice(0, 80),
    location: String(payload.location || "").slice(0, 160),
    desc: String(payload.desc || "").slice(0, 1000),
    image: "",
    contact: String(payload.contact || "").slice(0, 160),
    reporterName: String(payload.reporterName || "Campus Member").slice(0, 80),
    reporterFirstName: String(payload.reporterFirstName || "Campus").slice(0, 80),
    reporterDepartment: String(payload.reporterDepartment || "").slice(0, 80),
    isCustody: Boolean(payload.isCustody),
    custodyLocation: String(payload.custodyLocation || "").slice(0, 160),
    custodyHours: String(payload.custodyHours || "").slice(0, 160),
    custodyNotes: String(payload.custodyNotes || "").slice(0, 300)
  };
  return offlineRequest("readwrite", (store) =>
    store.add({ payload: safePayload, createdAt: Date.now(), attempts: 0 })
  );
}

async function countOfflineReports() {
  try {
    return await offlineRequest("readonly", (store) => store.count());
  } catch (e) {
    return 0;
  }
}

async function deleteOfflineReport(id) {
  return offlineRequest("readwrite", (store) => store.delete(id));
}

async function listOfflineReports() {
  return offlineRequest("readonly", (store) => store.getAll());
}

function isNetworkError(error) {
  const code = String((error && error.code) || "").toLowerCase();
  const message = String((error && error.message) || "").toLowerCase();
  return (
    code.indexOf("unavailable") !== -1 ||
    code.indexOf("network-request-failed") !== -1 ||
    message.indexOf("offline") !== -1 ||
    message.indexOf("network") !== -1 ||
    message.indexOf("failed to get document") !== -1
  );
}

/**
 * Replays queued reports when connectivity returns. A report is removed only
 * after Firestore confirms the write; permanent errors stay queued for review.
 */
async function flushOfflineReports() {
  if (!navigator.onLine) return { flushed: 0, remaining: await countOfflineReports() };
  const session = currentSession || await refreshSession(false);
  if (!session) return { flushed: 0, remaining: await countOfflineReports() };

  const reports = await listOfflineReports().catch(() => []);
  let flushed = 0;
  for (const report of reports) {
    try {
      const newId = await createItem(report.payload);
      if (session.role === "faculty" || session.role === "admin") {
        await updateItem(newId, { status: "approved", isStaffVerified: true }).catch(() => {});
      }
      await deleteOfflineReport(report.id);
      flushed += 1;
    } catch (error) {
      if (isNetworkError(error)) break;
      console.warn("Queued report could not be replayed:", error.message);
    }
  }
  return { flushed, remaining: await countOfflineReports() };
}

