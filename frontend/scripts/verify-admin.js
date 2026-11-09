"use strict";

const { initializeApp, getApps } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const path = require("path");
const fs = require("fs");

// Auto-detect ADC credentials
if (!process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  const firebaseDir = path.join(process.env.APPDATA || "", "firebase");
  if (fs.existsSync(firebaseDir)) {
    const files = fs.readdirSync(firebaseDir).filter(f => f.endsWith("_application_default_credentials.json"));
    if (files.length) {
      process.env.GOOGLE_APPLICATION_CREDENTIALS = path.join(firebaseDir, files[0]);
    }
  }
}

if (!getApps().length) {
  initializeApp({ projectId: "campusconnect-bc130" });
}

const auth = getAuth();
const db = getFirestore();

async function run() {
  const email = process.argv[2] || "admin@campus.edu";
  console.log(`Setting up admin: ${email}`);

  let user;
  try {
    user = await auth.getUserByEmail(email);
  } catch (err) {
    console.error(`User ${email} not found in Firebase Auth!`);
    process.exit(1);
  }

  // 1. Mark email as verified
  await auth.updateUser(user.uid, {
    emailVerified: true,
    displayName: user.displayName || "Campus Administrator"
  });
  console.log(`[Auth] emailVerified set to true for ${email}`);

  // 2. Set custom claims role = 'admin'
  await auth.setCustomUserClaims(user.uid, {
    role: "admin"
  });
  console.log(`[Auth] Custom claims set: { role: 'admin' } for ${email}`);

  // 3. Create profile document in Firestore
  await db.collection("users").doc(user.uid).set({
    name: user.displayName || "Campus Administrator",
    email: email,
    role: "admin",
    department: "Administration",
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp()
  }, { merge: true });
  console.log(`[Firestore] Profile document created in users/${user.uid}`);

  // Verify
  const fresh = await auth.getUser(user.uid);
  console.log("\nSuccess! Verification report:");
  console.log({
    uid: fresh.uid,
    email: fresh.email,
    displayName: fresh.displayName,
    emailVerified: fresh.emailVerified,
    customClaims: fresh.customClaims
  });
}

run().catch(err => {
  console.error("Error:", err);
  process.exit(1);
});

