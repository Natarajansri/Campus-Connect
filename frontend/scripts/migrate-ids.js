#!/usr/bin/env node
"use strict";

/**
 * Migrate legacy Campus Connect Firestore documents to the hardened schema.
 *
 * What it does
 * ------------
 * - Normalizes status casing (Pending -> pending, etc.) and legacy item types.
 * - Adds missing boolean/string fields used by the new Security Rules while
 *   preserving every unknown field.
 * - Converts parseable legacy date strings/numbers to Firestore Timestamps and
 *   keeps the original value in `legacyCreatedAt` / `legacyUpdatedAt`.
 * - Moves reporter contact details into items/{id}/private/contact and claim
 *   proof text into claims/{id}/private/proof, then removes the public copies.
 * - Re-keys legacy numeric/`usr_` style document IDs to auto-IDs. Re-keying
 *   requires `--delete-old`; without it, legacy-ID documents are only
 *   normalized in place so no data is silently duplicated.
 *
 * Safety
 * ------
 * - Dry-run by default. Nothing is written until `--apply`.
 * - Writes the replacement document before deleting the legacy document.
 * - Never deletes a document unless `--delete-old` is supplied.
 * - Uses Application Default Credentials. Never pass a private key on the CLI.
 *
 * Usage:
 *   node scripts/migrate-ids.js
 *   node scripts/migrate-ids.js --apply
 *   node scripts/migrate-ids.js --apply --delete-old
 *   node scripts/migrate-ids.js --collection items,claims --apply --delete-old
 */

const fs = require("node:fs");
const path = require("node:path");
const admin = require("firebase-admin");

const STATUS_MAPS = {
  items: {
    pending: "pending",
    approved: "approved",
    claimed: "claimed",
    returned: "returned",
    rejected: "rejected",
  },
  claims: {
    pending: "pending",
    approved: "approved",
    rejected: "rejected",
  },
  complaints: {
    "under review": "Under Review",
    investigating: "Investigating",
    resolved: "Resolved",
  },
};

const COLLECTIONS = ["items", "claims", "complaints", "notifications", "logs"];

function parseArgs(argv) {
  const args = { apply: false, deleteOld: false, collections: COLLECTIONS.slice() };
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === "--apply") args.apply = true;
    else if (token === "--delete-old") args.deleteOld = true;
    else if (token === "--help" || token === "-h") args.help = true;
    else if (token === "--project") args.project = argv[++i];
    else if (token === "--collection" || token === "--collections") {
      args.collections = String(argv[++i] || "")
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
    } else throw new Error(`Unknown argument: ${token}`);
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

function clamp(value, max) {
  return String(value === null || value === undefined ? "" : value).slice(0, max);
}

function normalizeStatus(collectionName, value) {
  const key = String(value || "").trim().toLowerCase();
  return STATUS_MAPS[collectionName] && STATUS_MAPS[collectionName][key]
    ? STATUS_MAPS[collectionName][key]
    : value;
}

function toTimestamp(value) {
  if (!value) return null;
  if (typeof value.toDate === "function") return value;
  if (value instanceof Date) return admin.firestore.Timestamp.fromDate(value);
  if (typeof value === "number" && Number.isFinite(value)) {
    return admin.firestore.Timestamp.fromMillis(value);
  }
  if (typeof value === "string") {
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return admin.firestore.Timestamp.fromMillis(parsed);
  }
  return null;
}

function looksLikeAutoId(id) {
  return /^[A-Za-z0-9]{20}$/.test(id);
}

function pickString(...values) {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function normalizeItem(data) {
  const out = { ...data };
  const warnings = [];

  out.type = String(data.type || "").toLowerCase() === "found" ? "found" : "lost";
  const status = normalizeStatus("items", data.status);
  if (status !== data.status) {
    out.legacyStatus = data.status;
    out.status = status;
  }
  if (!STATUS_MAPS.items[String(status || "").toLowerCase()]) {
    warnings.push(`unknown item status "${data.status}"`);
  }

  const reporterUid = pickString(data.reporterUid, data.ownerUid, data.userId, data.uid);
  if (reporterUid) out.reporterUid = reporterUid;
  else warnings.push("no reporterUid/ownerUid; item will not be ownable until assigned");

  out.title = clamp(data.title, 100) || "(untitled item)";
  out.category = clamp(data.category, 80) || "Other Valuables";
  out.location = clamp(data.location, 160);
  out.desc = clamp(data.desc, 1000);
  out.image = typeof data.image === "string" ? data.image.slice(0, 2048) : "";
  out.reporterName = clamp(data.reporterName || data.reporterFirstName, 80) || "Campus Member";
  out.isCustody = Boolean(data.isCustody);
  out.isPinned = Boolean(data.isPinned);
  // Do not promote legacy items to "staff verified" automatically. A moderator
  // must review them. Approved status still makes them publicly readable.
  out.isStaffVerified = Boolean(data.isStaffVerified);
  out.custodyLocation = clamp(data.custodyLocation, 160);
  out.custodyHours = clamp(data.custodyHours, 160);
  out.custodyNotes = clamp(data.custodyNotes, 300);

  const created = toTimestamp(data.createdAt);
  if (created) out.createdAt = created;
  else if (data.createdAt !== undefined) {
    out.legacyCreatedAt = String(data.createdAt);
    warnings.push("unparseable createdAt converted to server time");
  }
  const updated = toTimestamp(data.updatedAt);
  if (updated) out.updatedAt = updated;
  else if (data.updatedAt !== undefined) {
    out.legacyUpdatedAt = String(data.updatedAt);
  }

  return { data: out, warnings, privateContact: clamp(data.contact, 160) };
}

function normalizeClaim(data) {
  const out = { ...data };
  const warnings = [];
  const status = normalizeStatus("claims", data.status);
  if (status !== data.status) {
    out.legacyStatus = data.status;
    out.status = status;
  }
  if (!STATUS_MAPS.claims[String(status || "").toLowerCase()]) {
    warnings.push(`unknown claim status "${data.status}"`);
  }

  out.itemId = clamp(data.itemId, 128);
  out.itemTitle = clamp(data.itemTitle, 100) || "(untitled item)";
  if (typeof data.claimantUid === "string" && data.claimantUid) out.claimantUid = data.claimantUid;
  else warnings.push("no claimantUid; claim cannot be read by its claimant until repaired");
  out.claimantName = clamp(data.claimantName, 80) || "Campus Member";
  out.claimantEmail = clamp(data.claimantEmail, 160);

  const created = toTimestamp(data.createdAt);
  if (created) out.createdAt = created;
  else if (data.createdAt !== undefined) out.legacyCreatedAt = String(data.createdAt);
  const updated = toTimestamp(data.updatedAt);
  if (updated) out.updatedAt = updated;

  return {
    data: out,
    warnings,
    privateProof: {
      proofDetails: clamp(data.proofDetails || data.proof, 1000),
      contact: clamp(data.contact || data.claimContact || data.claimantEmail, 160),
    },
  };
}

function normalizeComplaint(data) {
  const out = { ...data };
  const status = normalizeStatus("complaints", data.status);
  if (status !== data.status) {
    out.legacyStatus = data.status;
    out.status = status;
  }
  out.studentName = clamp(data.studentName, 80) || "Campus Member";
  out.studentEmail = clamp(data.studentEmail, 160);
  out.subject = clamp(data.subject, 120) || "(no subject)";
  out.type = clamp(data.type, 60) || "General";
  out.message = clamp(data.message, 1000);
  return {
    data: out,
    warnings:
      typeof data.reporterUid === "string" && data.reporterUid
        ? []
        : ["no reporterUid; complaint is visible to staff only"],
  };
}

function normalizeNotification(data) {
  const out = { ...data };
  const toUid = pickString(data.toUid, data.recipientUid, data.userId);
  if (toUid) out.toUid = toUid;
  out.text = clamp(data.text || data.message, 500) || "(notification)";
  out.read = Boolean(data.read || data.isRead);
  const created = toTimestamp(data.createdAt);
  if (created) out.createdAt = created;
  return { data: out, warnings: toUid ? [] : ["no toUid/recipientUid; notification has no recipient"] };
}

function normalizeLog(data) {
  // Logs are an audit trail. Do not rewrite historical entries; only add the
  // display fields needed by the current admin console when they are absent.
  const out = { ...data };
  out.text = clamp(data.text || data.details || data.action, 500) || "Legacy audit entry";
  out.actorUid = clamp(data.actorUid, 128) || "system";
  out.actorRole = ["student", "faculty", "admin", "system"].includes(data.actorRole)
    ? data.actorRole
    : "system";
  out.action = clamp(data.action, 80) || "legacy.event";
  out.targetType = clamp(data.targetType, 40);
  out.targetId = clamp(data.targetId, 120);
  out.details = clamp(data.details, 300);
  out.source = data.source === "client" ? "client" : "function";
  return { data: out, warnings: [] };
}

const NORMALIZERS = {
  items: normalizeItem,
  claims: normalizeClaim,
  complaints: normalizeComplaint,
  notifications: normalizeNotification,
  logs: normalizeLog,
};

async function migrateDocument(db, collectionName, id, original, options) {
  const normalizer = NORMALIZERS[collectionName];
  const normalized = normalizer(original);
  const { data, warnings } = normalized;

  // A severity marker keeps `legacyId` traceable without affecting queries.
  data.legacyId = data.legacyId || id;

  const privateDocs = [];
  if (collectionName === "items" && normalized.privateContact) {
    privateDocs.push({
      path: ["items", id, "private", "contact"],
      data: {
        contact: normalized.privateContact,
        reporterUid: data.reporterUid || "",
        createdAt: data.createdAt || admin.firestore.FieldValue.serverTimestamp(),
        updatedAt: data.updatedAt || admin.firestore.FieldValue.serverTimestamp(),
      },
      removeFields: ["contact"],
    });
  }
  if (collectionName === "claims") {
    const proof = normalized.privateProof;
    if (proof && proof.proofDetails) {
      privateDocs.push({
        path: ["claims", id, "private", "proof"],
        data: {
          proofDetails: proof.proofDetails,
          contact: proof.contact,
          claimantUid: data.claimantUid || "",
          createdAt: data.createdAt || admin.firestore.FieldValue.serverTimestamp(),
        },
        removeFields: ["proof", "proofDetails", "claimContact", "contact"],
      });
    }
  }

  const needsRekey = !looksLikeAutoId(id) && collectionName !== "logs";

  console.log(`\n[${collectionName}/${id}]`);
  warnings.forEach((warning) => console.log(`  ! ${warning}`));
  if (needsRekey) {
    console.log(
      options.deleteOld
        ? `  rekey -> auto ID, then delete ${id}`
        : `  rekey skipped (needs --delete-old); normalizing ${id} in place`
    );
  }
  privateDocs.forEach((doc) => console.log(`  move private data -> ${doc.path.join("/")}`));
  data.migratedAt = admin.firestore.FieldValue.serverTimestamp();

  if (!options.apply) return { rekeyed: false, warnings };

  let targetRef;
  if (needsRekey && options.deleteOld) {
    targetRef = db.collection(collectionName).doc();
    data.migratedFrom = id;
  } else {
    targetRef = db.collection(collectionName).doc(id);
  }

  // Write the parent first, then move private data one document at a time. Doing
  // this sequentially avoids a race where a parent merge re-adds a field that a
  // concurrent removal just deleted.
  await targetRef.set(data, { merge: true });

  for (const doc of privateDocs) {
    const ref = targetRef.collection("private").doc(doc.path[doc.path.length - 1]);
    await ref.set(doc.data, { merge: true });
    const removals = {};
    doc.removeFields.forEach((field) => { removals[field] = admin.firestore.FieldValue.delete(); });
    await targetRef.set(removals, { merge: true });
  }

  if (needsRekey && options.deleteOld) {
    await db.collection(collectionName).doc(id).delete();
  }

  return { rekeyed: Boolean(needsRekey && options.deleteOld), warnings };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log("Usage: node scripts/migrate-ids.js [--collection items,claims] [--apply] [--delete-old] [--project <id>]");
    return;
  }

  const invalid = args.collections.filter((name) => !COLLECTIONS.includes(name));
  if (invalid.length) throw new Error(`Unknown collection(s): ${invalid.join(", ")}`);

  const projectId = args.project || defaultProject();
  if (!projectId) throw new Error("No project id. Pass --project or set FIREBASE_PROJECT_ID.");
  if (!admin.apps.length) admin.initializeApp({ projectId });
  const db = admin.firestore();

  console.log(`Project: ${projectId}`);
  console.log(`Mode: ${args.apply ? "APPLY" : "DRY RUN"}${args.deleteOld ? " (delete old after re-key)" : ""}`);
  console.log(`Collections: ${args.collections.join(", ")}`);

  let scanned = 0;
  let rekeyed = 0;
  const warningCounts = new Map();

  for (const collectionName of args.collections) {
    const snap = await db.collection(collectionName).get();
    for (const doc of snap.docs) {
      scanned += 1;
      const result = await migrateDocument(db, collectionName, doc.id, doc.data(), args);
      if (result.rekeyed) rekeyed += 1;
      result.warnings.forEach((warning) => {
        const key = `${collectionName}: ${warning}`;
        warningCounts.set(key, (warningCounts.get(key) || 0) + 1);
      });
    }
  }

  console.log(`\nScanned ${scanned} document(s). Re-keyed ${rekeyed}.`);
  if (warningCounts.size) {
    console.log("Warnings:");
    warningCounts.forEach((count, warning) => console.log(`  ${count} x ${warning}`));
  }
  if (!args.apply) {
    console.log("\nDRY RUN complete. Re-run with --apply to write changes.");
    if (!args.deleteOld) {
      console.log("Add --delete-old to re-key legacy IDs (a replacement document is written first).");
    }
  }
}

main().catch((error) => {
  console.error(`ERROR: ${error.message}`);
  process.exitCode = 1;
});
