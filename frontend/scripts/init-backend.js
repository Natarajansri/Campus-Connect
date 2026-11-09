#!/usr/bin/env node
"use strict";

/**
 * Campus Connect — Live Firebase Backend Initializer & Seeder
 *
 * Sets up the essential collections and documents in your live Firestore database:
 *   1. metadata/categories (initializes category list for items)
 *   2. metadata/broadcast (default campus announcement)
 *   3. Optionally elevates an administrator account (--email admin@campus.edu)
 *
 * Usage:
 *   node scripts/init-backend.js
 *   node scripts/init-backend.js --email yourname@gmail.com
 */

const fs = require("node:fs");
const path = require("node:path");
const { getApps, initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const { getAuth } = require("firebase-admin/auth");

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--email") args.email = argv[++i];
    else if (token === "--project") args.project = argv[++i];
    else if (token === "--help" || token === "-h") args.help = true;
  }
  return args;
}

function defaultProject() {
  if (process.env.FIREBASE_PROJECT_ID) return process.env.FIREBASE_PROJECT_ID;
  if (process.env.GCLOUD_PROJECT) return process.env.GCLOUD_PROJECT;
  try {
    const rc = JSON.parse(fs.readFileSync(path.join(__dirname, "..", ".firebaserc"), "utf8"));
    return rc.projects && rc.projects.default;
  } catch (error) {
    return "campusconnect-bc130";
  }
}

// Auto-detect Firebase CLI credentials if not explicitly set
if (!process.env.GOOGLE_APPLICATION_CREDENTIALS && process.env.APPDATA) {
  const firebaseDir = path.join(process.env.APPDATA, "firebase");
  if (fs.existsSync(firebaseDir)) {
    const files = fs.readdirSync(firebaseDir);
    const adcFile = files.find(f => f.endsWith("_application_default_credentials.json"));
    if (adcFile) {
      process.env.GOOGLE_APPLICATION_CREDENTIALS = path.join(firebaseDir, adcFile);
      console.log(`Using Firebase CLI credentials: ${adcFile}`);
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log("Usage: node scripts/init-backend.js [--email <admin-email>] [--project <project-id>]");
    process.exit(0);
  }

  const projectId = args.project || defaultProject();
  console.log(`Connecting to Firebase project: ${projectId}...`);

  const apps = getApps();
  const app = apps.length ? apps[0] : initializeApp({ projectId });

  const db = getFirestore(app);
  const auth = getAuth(app);

  console.log("\n1. Initializing metadata/categories in Firestore...");
  const categoriesRef = db.collection("metadata").doc("categories");
  const categoriesSnap = await categoriesRef.get();
  if (!categoriesSnap.exists) {
    const defaultCategories = [
      "Electronics",
      "Student IDs & Cards",
      "Keys & Wallets",
      "Books & Notes",
      "Bags & Backpacks",
      "Clothing & Accessories",
      "Other"
    ];
    await categoriesRef.set({
      list: defaultCategories,
      updatedAt: FieldValue.serverTimestamp()
    });
    console.log("   ✔ Created metadata/categories with 7 standard categories.");
  } else {
    console.log("   ℹ metadata/categories already exists in Firestore.");
  }

  console.log("\n2. Initializing metadata/broadcast announcement in Firestore...");
  const broadcastRef = db.collection("metadata").doc("broadcast");
  const broadcastSnap = await broadcastRef.get();
  if (!broadcastSnap.exists) {
    await broadcastRef.set({
      text: "Welcome to Campus Connect Lost & Found portal! Report any lost items or claim items you have found.",
      active: true,
      updatedAt: FieldValue.serverTimestamp()
    });
    console.log("   ✔ Created metadata/broadcast with welcome announcement.");
  } else {
    console.log("   ℹ metadata/broadcast already exists in Firestore.");
  }

  const targetEmail = args.email || "neccampusconnect@gmail.com";
  console.log(`\n3. Setting up administrator account for: ${targetEmail}...`);
  try {
    const user = await auth.getUserByEmail(targetEmail);
    const existingClaims = user.customClaims || {};
    await auth.setCustomUserClaims(user.uid, { ...existingClaims, role: "admin" });
    
    await db.collection("users").doc(user.uid).set(
      {
        uid: user.uid,
        email: user.email,
        role: "admin",
        name: user.displayName || user.email.split("@")[0],
        status: "Active",
        updatedAt: FieldValue.serverTimestamp()
      },
      { merge: true }
    );
    console.log(`   ✔ Successfully granted 'admin' role to ${user.email} (UID: ${user.uid}) in Firebase Auth & Firestore.`);
  } catch (err) {
    console.log(`   ℹ Note for ${targetEmail}: ${err.message}`);
    console.log(`     If this user hasn't signed up yet, sign in via Google SSO or Create Account on the portal first, then re-run to make them admin.`);
  }

  console.log("\n=================================================");
  console.log("  Live Firebase Backend initialization complete!");
  console.log("=================================================\n");
}

main().catch((err) => {
  console.error("\n❌ Initialization error:", err.message);
  process.exit(1);
});
