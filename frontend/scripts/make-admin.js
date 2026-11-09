#!/usr/bin/env node
"use strict";

/**
 * Bootstrap or repair a Campus Connect role custom claim.
 *
 * SECURITY
 * --------
 * - Uses Application Default Credentials (ADC). Never commit a service-account
 *   JSON file and never accept a private key on the command line.
 * - Dry-run by default. Nothing is written until `--apply` is supplied.
 * - Preserves unrelated custom claims and updates the informational users/{uid}
 *   document so the admin console shows the same role.
 * - Refuses to demote the last enabled administrator.
 *
 * Usage (local emulator):
 *   $env:FIREBASE_AUTH_EMULATOR_HOST="127.0.0.1:9099"
 *   $env:FIRESTORE_EMULATOR_HOST="127.0.0.1:8080"
 *   node scripts/make-admin.js --email admin@campus.edu --apply
 *
 * Usage (production, after `gcloud auth application-default login`):
 *   node scripts/make-admin.js --email admin@campus.edu
 *   node scripts/make-admin.js --email admin@campus.edu --apply
 */

const fs = require("node:fs");
const path = require("node:path");
const admin = require("firebase-admin");

const VALID_ROLES = ["student", "faculty", "admin"];

function parseArgs(argv) {
  const args = { apply: false };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--apply") args.apply = true;
    else if (token === "--help" || token === "-h") args.help = true;
    else if (token === "--email") args.email = argv[++i];
    else if (token === "--uid") args.uid = argv[++i];
    else if (token === "--role") args.role = argv[++i];
    else if (token === "--project") args.project = argv[++i];
    else throw new Error(`Unknown argument: ${token}`);
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
    return undefined;
  }
}

async function countAdmins(excludeUid) {
  let total = 0;
  let pageToken;
  do {
    const page = await admin.auth().listUsers(1000, pageToken);
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

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log("Usage: node scripts/make-admin.js (--email <email> | --uid <uid>) [--role admin|faculty|student] [--project <id>] [--apply]");
    return;
  }

  const role = args.role || "admin";
  if (!VALID_ROLES.includes(role)) throw new Error(`Invalid role: ${role}`);
  if (!args.email && !args.uid) throw new Error("Provide --email or --uid.");
  if (args.email && args.uid) throw new Error("Provide only one of --email or --uid.");

  const projectId = args.project || defaultProject();
  if (!projectId) throw new Error("No project id. Pass --project or set FIREBASE_PROJECT_ID.");
  if (!admin.apps.length) admin.initializeApp({ projectId });

  let user;
  try {
    user = args.uid
      ? await admin.auth().getUser(args.uid)
      : await admin.auth().getUserByEmail(String(args.email).trim().toLowerCase());
  } catch (error) {
    throw new Error(`User not found: ${args.email || args.uid}`);
  }

  const existingClaims = user.customClaims || {};
  const currentRole = VALID_ROLES.includes(existingClaims.role) ? existingClaims.role : "student";

  if (currentRole === "admin" && role !== "admin") {
    const remaining = await countAdmins(user.uid);
    if (remaining < 1) {
      throw new Error("Refusing to remove the last enabled administrator.");
    }
  }

  const nextClaims = { ...existingClaims, role };
  // A role change must not also clear a suspension flag. Suspension is managed by
  // the setUserStatus Cloud Function; this script only changes the role.
  if (existingClaims.suspended === true) nextClaims.suspended = true;

  console.log(`Project: ${projectId}`);
  console.log(`User:    ${user.email || user.uid} (${user.uid})`);
  console.log(`Role:    ${currentRole} -> ${role}`);
  console.log(`Claims:  ${JSON.stringify(existingClaims)} -> ${JSON.stringify(nextClaims)}`);

  if (!args.apply) {
    console.log("\nDRY RUN. Re-run with --apply to write the custom claim and profile.");
    return;
  }

  await admin.auth().setCustomUserClaims(user.uid, nextClaims);

  // Force a fresh token. Existing ID tokens can otherwise keep the old role for
  // up to one hour.
  await admin.auth().revokeRefreshTokens(user.uid).catch(() => {});

  const db = admin.firestore();
  const ref = db.collection("users").doc(user.uid);
  const snap = await ref.get();
  if (snap.exists) {
    await ref.set(
      {
        role,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        updatedBy: "script:make-admin",
      },
      { merge: true }
    );
  } else {
    await ref.set({
      uid: user.uid,
      name: String(user.displayName || (user.email || "").split("@")[0] || "Campus Member").slice(0, 80),
      email: String(user.email || "").toLowerCase().slice(0, 160),
      department: "",
      role,
      status: user.disabled ? "Suspended" : "Active",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: "script:make-admin",
    });
  }

  await db.collection("logs").add({
    actorUid: "script:make-admin",
    actorRole: "system",
    action: "user.role_changed",
    targetType: "user",
    targetId: user.uid,
    details: `${user.email || user.uid}: ${currentRole} -> ${role}`,
    text: `Role changed by bootstrap script: ${user.email || user.uid} ${currentRole} -> ${role}`,
    source: "function",
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
  });

  console.log("\nApplied. The affected user must sign out and sign in again (refresh tokens revoked).");
}

main().catch((error) => {
  console.error(`ERROR: ${error.message}`);
  process.exitCode = 1;
});
