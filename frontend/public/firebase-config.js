/**
 * Campus Connect — Firebase bootstrap (compat/namespaced SDK)
 * Project: campusconnect-bc130
 *
 * SECURITY NOTES
 * --------------
 * - The web API key below is a PUBLIC client identifier, not a service-account
 *   secret. It MUST still be restricted in Google Cloud Console (HTTP referrer +
 *   Google Identity Toolkit / Firestore / Storage APIs). See SECURITY.md.
 * - Roles are NEVER read from this file, localStorage, or the users document.
 *   The only authoritative role source is the Firebase Auth ID token custom
 *   claim `role` (see firebase-service.js).
 * - App Check is initialized with reCAPTCHA v3. Replace the placeholder site key
 *   before production. During local emulator work you may set
 *   APP_CHECK_DEBUG_TOKEN in the browser console BEFORE loading the page, e.g.
 *   localStorage.setItem("campusAppCheckDebugToken", "...") — never commit one.
 */

const firebaseConfig = {
  apiKey: "AIzaSyBHxwjckZaVhHt9l_2vNTmFT9lVpBJmNdg",
  authDomain: "campusconnect-bc130.firebaseapp.com",
  projectId: "campusconnect-bc130",
  storageBucket: "campusconnect-bc130.firebasestorage.app",
  messagingSenderId: "743796614325",
  appId: "1:743796614325:web:1376909590b5ab996bcafc",
  measurementId: "G-0BJEQDD4LC"
};

/**
 * reCAPTCHA v3 / Enterprise site key (public, but rotate/restrict it).
 * Keep the "REPLACE_" prefix until you have created the App Check provider so
 * the app can still be opened locally without an App Check token.
 */
const APP_CHECK_SITE_KEY = "REPLACE_WITH_RECAPTCHA_V3_SITE_KEY";

/**
 * Web Push certificate (VAPID) public key from Firebase Console →
 * Project settings → Cloud Messaging → Web configuration.
 * Public by design; keep the placeholder until it is configured.
 */
const FCM_VAPID_KEY = "REPLACE_WITH_FCM_VAPID_KEY";

/**
 * Emulator Suite switch.
 * - Set to `true` when running `firebase emulators:start` locally.
 * - Set to `false` to connect directly to the live Firebase project (campusconnect-bc130).
 */
const USE_FIREBASE_EMULATORS = false;

// Firebase service instances (namespaced/compat API)
let fbApp = null;
let fbAuth = null;
let fbDb = null;
// fbStorage removed — photos stored as base64 in Firestore (Storage not used)
let fbAppCheck = null;
let isFirebaseReady = false;

function initFirebase() {
  if (typeof firebase === "undefined") {
    console.warn("Firebase SDK scripts not loaded. Running without cloud sync.");
    return false;
  }

  try {
    if (!firebase.apps || !firebase.apps.length) {
      fbApp = firebase.initializeApp(firebaseConfig);
    } else {
      fbApp = firebase.app();
    }

    fbAuth = firebase.auth();
    fbDb = firebase.firestore();

    // Offline persistence is a convenience cache only. It never authorizes
    // writes: Firestore Security Rules are evaluated server-side on every write.
    try {
      fbDb.enablePersistence({ synchronizeTabs: true }).catch(() => {});
    } catch (e) {
      /* persistence is unsupported in some browsers */
    }

    // Firebase Storage is not used — photos are stored as base64 in Firestore.

    // ---- Emulator Suite ---------------------------------------------------
    // SECURITY: hard-coded to localhost only. Never enable this based on a
    // query string or localStorage value that an attacker could control.
    if (USE_FIREBASE_EMULATORS) {
      try {
        fbAuth.useEmulator("http://localhost:9099");
        fbDb.useEmulator("localhost", 8080);
        if (firebase.functions) firebase.functions().useEmulator("localhost", 5001);
        console.info("Firebase Emulator Suite connected (localhost only).");
      } catch (e) {
        console.warn("Could not connect to Firebase emulators:", e.message);
      }
    }

    // ---- App Check (reCAPTCHA v3) ------------------------------------------
    // App Check proves requests come from our web app and blocks scripted abuse.
    // It is intentionally skipped while the site key is a placeholder so local
    // development/emulator runs are not broken. Production MUST replace it.
    try {
      if (firebase.appCheck && APP_CHECK_SITE_KEY.indexOf("REPLACE_") !== 0) {
        fbAppCheck = firebase.appCheck();
        const providerFactory = firebase.appCheck.ReCaptchaV3Provider;
        const provider = typeof providerFactory === "function"
          ? new providerFactory(APP_CHECK_SITE_KEY)
          : APP_CHECK_SITE_KEY;
        fbAppCheck.activate(provider, true);
        console.info("App Check enabled (reCAPTCHA v3).");
      } else {
        console.info(
          "App Check NOT enabled: set APP_CHECK_SITE_KEY in firebase-config.js. " +
          "Then enforce App Check for Firestore, Storage, Auth and Functions."
        );
      }
    } catch (e) {
      console.warn("App Check initialization skipped:", e.message);
    }

    isFirebaseReady = true;
    console.log("Firebase connected to project:", firebaseConfig.projectId);
    return true;
  } catch (err) {
    console.error("Firebase initialization failed:", err);
    isFirebaseReady = false;
    return false;
  }
}

// Exposed for the root service worker (sw.js). These values are public client
// identifiers, never credentials.
if (typeof self !== "undefined") {
  self.CAMPUS_FIREBASE_CONFIG = firebaseConfig;
}
