/**
 * clean-firebase.js — One-off script to delete ALL mock users and mock
 * Firestore data from the live campusconnect-bc130 project.
 *
 * Usage (from the frontend/ directory):
 *   node scripts/clean-firebase.js            # dry-run: shows what would be deleted
 *   node scripts/clean-firebase.js --apply    # live delete
 *
 * Requires:
 *   - firebase-admin (already in devDependencies)
 *   - Application Default Credentials auto-detected from %APPDATA%\firebase\
 */

"use strict";

const { initializeApp, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore } = require("firebase-admin/firestore");
const { credential } = require("firebase-admin/app");
const admin = require("firebase-admin");
const path = require("path");
const fs = require("fs");

// ── ADC auto-detect ───────────────────────────────────────────────────────────
function autoDetectCredentials() {
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) return;
  const firebaseDir = path.join(process.env.APPDATA || "", "firebase");
  if (!fs.existsSync(firebaseDir)) return;
  const files = fs.readdirSync(firebaseDir).filter(
    (f) => f.endsWith("_application_default_credentials.json")
  );
  if (files.length) {
    process.env.GOOGLE_APPLICATION_CREDENTIALS = path.join(firebaseDir, files[0]);
    console.log(`[ADC] Using credentials: ${files[0]}`);
  }
}

autoDetectCredentials();

// ── Init Firebase Admin ───────────────────────────────────────────────────────
if (!getApps().length) {
  admin.initializeApp({ projectId: "campusconnect-bc130" });
}
const auth = getAuth();
const db = getFirestore();

const DRY_RUN = !process.argv.includes("--apply");
if (DRY_RUN) {
  console.log("\n🔍 DRY-RUN mode — no changes will be made. Pass --apply to execute.\n");
} else {
  console.log("\n🔥 LIVE mode — changes WILL be applied to campusconnect-bc130.\n");
}

// ── Known mock user emails ────────────────────────────────────────────────────
const MOCK_EMAILS = [
  "priya.k@campus.edu",
  "faculty.smith@campus.edu",
  "admin@campus.edu",
];

// ── Collections to fully wipe (except metadata) ──────────────────────────────
// These collections are assumed to contain only mock/seed data since the app
// is brand new and no real users have signed up yet.
const COLLECTIONS_TO_WIPE = [
  "users",
  "items",
  "claims",
  "notifications",
  "complaints",
  "logs",
];

// ── Helper: delete all docs in a collection ───────────────────────────────────
async function wipeCollection(colName) {
  const snap = await db.collection(colName).get();
  if (snap.empty) {
    console.log(`  [${colName}] Empty — nothing to delete.`);
    return 0;
  }
  console.log(`  [${colName}] Found ${snap.size} document(s):`);
  snap.forEach((doc) => console.log(`    - ${doc.id}`));
  if (!DRY_RUN) {
    const batch = db.batch();
    snap.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();
    console.log(`  [${colName}] ✅ Deleted ${snap.size} document(s).`);
  }
  return snap.size;
}

// ── Helper: delete a Firebase Auth user by email ─────────────────────────────
async function deleteAuthUser(email) {
  try {
    const user = await auth.getUserByEmail(email);
    console.log(`  [Auth] Found ${email} (uid: ${user.uid})`);
    if (!DRY_RUN) {
      await auth.deleteUser(user.uid);
      console.log(`  [Auth] ✅ Deleted ${email}`);
    }
    return true;
  } catch (err) {
    if (err.code === "auth/user-not-found") {
      console.log(`  [Auth] ${email} — not found (already deleted or never existed).`);
      return false;
    }
    throw err;
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  let totalDocs = 0;

  // 1. Wipe Firestore collections
  console.log("── Firestore Collections ─────────────────────────────────────");
  for (const col of COLLECTIONS_TO_WIPE) {
    totalDocs += await wipeCollection(col);
  }

  // 2. Delete mock Auth users
  console.log("\n── Firebase Auth Users ───────────────────────────────────────");
  for (const email of MOCK_EMAILS) {
    await deleteAuthUser(email);
  }

  // 3. Summary
  console.log("\n── Summary ───────────────────────────────────────────────────");
  if (DRY_RUN) {
    console.log(`Would delete ${totalDocs} Firestore doc(s) and up to ${MOCK_EMAILS.length} Auth user(s).`);
    console.log('Run with --apply to execute.');
  } else {
    console.log(`✅ Cleaned up ${totalDocs} Firestore doc(s) and ${MOCK_EMAILS.length} Auth user(s) (if they existed).`);
    console.log("🎉 Firebase is clean and ready for real users.");
  }
}

main().catch((err) => {
  console.error("❌ Error:", err.message || err);
  process.exit(1);
});

