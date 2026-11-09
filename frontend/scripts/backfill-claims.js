#!/usr/bin/env node
"use strict";

/**
 * Backfill Firebase Auth custom claims for existing accounts.
 *
 * SECURITY
 * --------
 * - The authoritative role is the `role` custom claim. This script repairs
 *   accounts that predate the hardening work.
 * - Missing/invalid roles become `student` by default. Using the informational
 *   users/{uid} document as a role source requires the explicit
 *   `--from-profiles` flag and is only intended for a one-off migration. After
 *   this runs, the users document is informational only.
 * - Suspended accounts (Auth disabled or users.status === "Suspended") get the
 *   `suspended` claim so Security Rules reject them immediately after refresh.
 * - Dry-run by default. `--apply` is required to write.
 */

const fs = require("node:fs");
const path = require("node:path");
const { getApps, initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

const VALID_ROLES = ["student", "faculty", "admin"];

function parseArgs(argv) {
  const args = { apply: false, fromProfiles: false, revoke: false };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--apply") args.apply = true;
    else if (token === "--from-profiles") args.fromProfiles = true;
    else if (token === "--revoke") args.revoke = true;
    else if (token === "--help" || token === "-h") args.help = true;
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

async function profileRole(uid) {
  const snap = await getFirestore().collection("users").doc(uid).get();
  if (!snap.exists) return null;
  const profile = snap.data() || {};
  return {
    role: VALID_ROLES.includes(profile.role) ? profile.role : null,
    suspended: profile.status === "Suspended",
  };
}

// Auto-detect Firebase CLI credentials if not explicitly set
if (!process.env.GOOGLE_APPLICATION_CREDENTIALS && process.env.APPDATA) {
  const firebaseDir = path.join(process.env.APPDATA, "firebase");
  if (fs.existsSync(firebaseDir)) {
    const files = fs.readdirSync(firebaseDir);
    const adcFile = files.find(f => f.endsWith("_application_default_credentials.json"));
    if (adcFile) {
      process.env.GOOGLE_APPLICATION_CREDENTIALS = path.join(firebaseDir, adcFile);
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log("Usage: node scripts/backfill-claims.js [--from-profiles] [--revoke] [--project <id>] [--apply]");
    console.log("  --from-profiles  Use users/{uid}.role for accounts with no role claim (one-off migration only).");
    console.log("  --revoke         Revoke refresh tokens for accounts whose claims changed.");
    return;
  }

  const projectId = args.project || defaultProject();
  if (!projectId) throw new Error("No project id. Pass --project or set FIREBASE_PROJECT_ID.");
  const apps = getApps();
  const app = apps.length ? apps[0] : initializeApp({ projectId });

  const auth = getAuth(app);
  const db = getFirestore(app);
  const changes = [];
  let scanned = 0;
  let pageToken;

  do {
    const page = await auth.listUsers(1000, pageToken);
    for (const user of page.users) {
      scanned += 1;
      const existing = user.customClaims || {};
      let role = VALID_ROLES.includes(existing.role) ? existing.role : null;
      let suspended = user.disabled === true || existing.suspended === true;

      if (!role && args.fromProfiles) {
        const profile = await profileRole(user.uid);
        if (profile) {
          role = profile.role;
          suspended = suspended || profile.suspended;
        }
      }
      if (!role) role = "student";

      const next = { ...existing, role };
      if (suspended) next.suspended = true;
      else delete next.suspended;

      const roleChanged = existing.role !== role;
      const suspensionChanged = Boolean(existing.suspended) !== Boolean(suspended);
      if (!roleChanged && !suspensionChanged) continue;

      changes.push({
        uid: user.uid,
        email: user.email || "",
        previousRole: existing.role || "(none)",
        role,
        suspended,
        next,
      });
    }
    pageToken = page.pageToken;
  } while (pageToken);

  console.log(`Project: ${projectId}`);
  console.log(`Scanned ${scanned} account(s). ${changes.length} need claim updates.`);
  changes.slice(0, 25).forEach((change) => {
    console.log(
      `  ${change.email || change.uid}: ${change.previousRole} -> ${change.role}${change.suspended ? " [suspended]" : ""}`
    );
  });
  if (changes.length > 25) console.log(`  ... and ${changes.length - 25} more`);

  if (!changes.length) return;
  if (!args.apply) {
    console.log("\nDRY RUN. Re-run with --apply to write custom claims.");
    return;
  }

  for (const change of changes) {
    await auth.setCustomUserClaims(change.uid, change.next);
    if (args.revoke) await auth.revokeRefreshTokens(change.uid).catch(() => {});
    await db.collection("logs").add({
      actorUid: "script:backfill-claims",
      actorRole: "system",
      action: "user.claims_backfilled",
      targetType: "user",
      targetId: change.uid,
      details: `${change.email || change.uid}: role ${change.previousRole} -> ${change.role}${change.suspended ? " (suspended)" : ""}`,
      text: `Claims backfilled for ${change.email || change.uid}`,
      source: "function",
      createdAt: FieldValue.serverTimestamp(),
    });
  }

  console.log(`\nApplied ${changes.length} claim update(s).`);
  if (!args.revoke) {
    console.log("Existing ID tokens may retain the old claims until they expire (up to one hour).");
    console.log("Use --revoke to force refresh-token revocation for changed accounts.");
  }
}

main().catch((error) => {
  console.error(`ERROR: ${error.message}`);
  process.exitCode = 1;
});
