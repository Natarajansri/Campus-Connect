#!/usr/bin/env node
"use strict";

/**
 * Campus Connect — Firestore + Storage Security Rules test suite.
 *
 * Run through the Firebase Emulator Suite:
 *   npm run test:rules
 *
 * The suite is intentionally explicit: every test seeds its own data so tests
 * can run in any order and a failure pinpoints the exact rule being exercised.
 */

const fs = require("node:fs");
const path = require("node:path");
const {
  initializeTestEnvironment,
  assertFails,
  assertSucceeds,
} = require("@firebase/rules-unit-testing");
const firebase = require("firebase/compat/app");
require("firebase/compat/firestore");
require("firebase/compat/storage");

const PROJECT_ID = "demo-campusconnect";
const ROOT = path.join(__dirname, "..", "..");
const FieldValue = firebase.firestore.FieldValue;
const Timestamp = firebase.firestore.Timestamp;

let testEnv;
let passed = 0;
let failed = 0;
const failures = [];

function context(uid, claims = {}) {
  return testEnv.authenticatedContext(uid, {
    email: claims.email || `${uid}@campus.edu`,
    email_verified: true,
    ...claims,
  });
}

function dbFor(uid, claims) {
  return context(uid, claims).firestore();
}

function unauthenticatedDb() {
  return testEnv.unauthenticatedContext().firestore();
}

async function seedDoc(docPath, data) {
  await testEnv.withSecurityRulesDisabled(async (ctx) => {
    await ctx.firestore().doc(docPath).set(data);
  });
}

function baseItem(owner, overrides = {}) {
  const now = Timestamp.now();
  return {
    type: "lost",
    title: "Blue backpack",
    category: "Bags",
    location: "Main Library",
    desc: "Blue backpack with a laptop sleeve.",
    image: "",
    reporterUid: owner,
    reporterName: "Test Reporter",
    reporterFirstName: "Test",
    reporterDepartment: "Computer Science",
    status: "approved",
    isCustody: false,
    custodyLocation: "",
    custodyHours: "",
    custodyNotes: "",
    isPinned: false,
    isStaffVerified: true,
    createdAt: now,
    updatedAt: now,
    updatedBy: owner,
    ...overrides,
  };
}

function newItem(owner, overrides = {}) {
  const now = FieldValue.serverTimestamp();
  return {
    type: "lost",
    title: "New wallet",
    category: "Wallets",
    location: "Cafeteria",
    desc: "Brown leather wallet.",
    image: "",
    reporterUid: owner,
    reporterName: "Test Reporter",
    reporterFirstName: "Test",
    reporterDepartment: "Computer Science",
    status: "pending",
    isCustody: false,
    custodyLocation: "",
    custodyHours: "",
    custodyNotes: "",
    isPinned: false,
    isStaffVerified: false,
    createdAt: now,
    updatedAt: now,
    updatedBy: owner,
    ...overrides,
  };
}

function baseUser(uid, overrides = {}) {
  const now = Timestamp.now();
  return {
    uid,
    name: "Test User",
    email: `${uid}@campus.edu`,
    department: "Computer Science",
    role: "student",
    status: "Active",
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

function baseClaim(claimantUid, itemId, overrides = {}) {
  const now = Timestamp.now();
  return {
    itemId,
    itemTitle: "Blue backpack",
    claimantUid,
    claimantName: "Claimant",
    claimantEmail: `${claimantUid}@campus.edu`,
    status: "pending",
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

function baseDevice(overrides = {}) {
  const now = Timestamp.now();
  return {
    token: "fcm-token-abcdefghijklmnopqrstuvwxyz",
    platform: "web",
    enabled: true,
    userAgent: "Test browser",
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    ...overrides,
  };
}

function newDevice(overrides = {}) {
  const now = FieldValue.serverTimestamp();
  return {
    token: "fcm-token-abcdefghijklmnopqrstuvwxyz",
    platform: "web",
    enabled: true,
    userAgent: "Test browser",
    createdAt: now,
    updatedAt: now,
    lastSeenAt: now,
    ...overrides,
  };
}

function baseChat(overrides = {}) {
  const now = Timestamp.now();
  return {
    itemId: "item-x",
    itemTitle: "Blue backpack",
    claimId: "claim-x",
    claimantUid: "alice",
    reporterUid: "bob",
    status: "open",
    lastMessage: "Hello",
    lastSenderUid: "alice",
    lastMessageAt: now,
    createdAt: now,
    updatedAt: now,
    ...overrides,
  };
}

async function test(name, fn) {
  try {
    // Every test gets a clean database and bucket so tests are independent.
    await testEnv.clearFirestore();
    await testEnv.clearStorage();
    await fn();
    passed += 1;
    console.log(`  PASS  ${name}`);
  } catch (error) {
    failed += 1;
    failures.push({ name, error });
    console.error(`  FAIL  ${name}`);
    console.error(`        ${String(error && error.message ? error.message : error).split("\n")[0]}`);
  }
}

async function run() {
  const rules = {
    firestore: fs.readFileSync(path.join(ROOT, "firestore.rules"), "utf8"),
    storage: fs.readFileSync(path.join(ROOT, "storage.rules"), "utf8"),
  };

  testEnv = await initializeTestEnvironment({
    projectId: PROJECT_ID,
    firestore: { host: "127.0.0.1", port: 8080, rules: rules.firestore },
    storage: { host: "127.0.0.1", port: 9199, rules: rules.storage },
  });

  console.log(`\nFirestore rules: ${path.relative(ROOT, path.join(ROOT, "firestore.rules"))}`);
  console.log(`Storage rules:   ${path.relative(ROOT, path.join(ROOT, "storage.rules"))}`);
  console.log(`Project:         ${PROJECT_ID}\n`);

  /* ------------------------------------------------------------------ */
  console.log("Authentication and session claims");
  await test("unauthenticated clients cannot read items", async () => {
    await seedDoc("items/item-public", baseItem("alice"));
    await assertFails(unauthenticatedDb().doc("items/item-public").get());
  });
  await test("unverified accounts cannot read items", async () => {
    await seedDoc("items/item-public", baseItem("alice"));
    const db = dbFor("bob", { email_verified: false });
    await assertFails(db.doc("items/item-public").get());
  });
  await test("suspended accounts cannot read items", async () => {
    await seedDoc("items/item-public", baseItem("alice"));
    const db = dbFor("bob", { suspended: true });
    await assertFails(db.doc("items/item-public").get());
  });
  await test("verified students can read approved items", async () => {
    await seedDoc("items/item-public", baseItem("alice"));
    await assertSucceeds(dbFor("bob").doc("items/item-public").get());
  });
  await test("verified students cannot read another user's pending item", async () => {
    await seedDoc("items/item-pending", baseItem("alice", { status: "pending", isStaffVerified: false }));
    await assertFails(dbFor("bob").doc("items/item-pending").get());
  });
  await test("owners can read their own pending item", async () => {
    await seedDoc("items/item-pending", baseItem("alice", { status: "pending", isStaffVerified: false }));
    await assertSucceeds(dbFor("alice").doc("items/item-pending").get());
  });

  /* ------------------------------------------------------------------ */
  console.log("\nItems");
  await test("student can create a pending item and private contact atomically", async () => {
    const db = dbFor("alice");
    const batch = db.batch();
    batch.set(db.collection("items").doc("item-new"), newItem("alice"));
    batch.set(db.collection("items").doc("item-new").collection("private").doc("contact"), {
      contact: "alice@campus.edu",
      reporterUid: "alice",
      createdAt: FieldValue.serverTimestamp(),
    });
    await assertSucceeds(batch.commit());
  });
  await test("student cannot create an already-approved item", async () => {
    const db = dbFor("alice");
    await assertFails(
      db.collection("items").doc("item-self-approved").set(newItem("alice", { status: "approved" }))
    );
  });
  await test("student cannot create a pinned or staff-verified item", async () => {
    const db = dbFor("alice");
    await assertFails(
      db.collection("items").doc("item-pinned").set(newItem("alice", { isPinned: true }))
    );
    await assertFails(
      db.collection("items").doc("item-verified").set(newItem("alice", { isStaffVerified: true }))
    );
  });
  await test("student cannot create an item on behalf of another user", async () => {
    const db = dbFor("alice");
    await assertFails(
      db.collection("items").doc("item-forged").set(newItem("alice", { reporterUid: "bob" }))
    );
  });
  await test("owner can edit descriptive fields", async () => {
    await seedDoc("items/item-edit", baseItem("alice"));
    const db = dbFor("alice");
    await assertSucceeds(
      db.doc("items/item-edit").update({
        title: "Updated title",
        updatedAt: FieldValue.serverTimestamp(),
        updatedBy: "alice",
      })
    );
  });
  await test("owner cannot self-approve a pending item", async () => {
    await seedDoc("items/item-pending", baseItem("alice", { status: "pending", isStaffVerified: false }));
    const db = dbFor("alice");
    await assertFails(
      db.doc("items/item-pending").update({
        status: "approved",
        updatedAt: FieldValue.serverTimestamp(),
        updatedBy: "alice",
      })
    );
  });
  await test("owner can mark an approved item returned and reopen it", async () => {
    await seedDoc("items/item-return", baseItem("alice", { status: "approved" }));
    const db = dbFor("alice");
    await assertSucceeds(
      db.doc("items/item-return").update({
        status: "returned",
        updatedAt: FieldValue.serverTimestamp(),
        updatedBy: "alice",
      })
    );
    await assertSucceeds(
      db.doc("items/item-return").update({
        status: "approved",
        updatedAt: FieldValue.serverTimestamp(),
        updatedBy: "alice",
      })
    );
  });
  await test("owner cannot reassign or pin their item", async () => {
    await seedDoc("items/item-owner-fields", baseItem("alice"));
    const db = dbFor("alice");
    await assertFails(
      db.doc("items/item-owner-fields").update({
        reporterUid: "bob",
        updatedAt: FieldValue.serverTimestamp(),
        updatedBy: "alice",
      })
    );
    await assertFails(
      db.doc("items/item-owner-fields").update({
        isPinned: true,
        updatedAt: FieldValue.serverTimestamp(),
        updatedBy: "alice",
      })
    );
  });
  await test("staff can approve a pending item", async () => {
    await seedDoc("items/item-pending", baseItem("alice", { status: "pending", isStaffVerified: false }));
    const db = dbFor("faculty1", { role: "faculty" });
    await assertSucceeds(
      db.doc("items/item-pending").update({
        status: "approved",
        isStaffVerified: true,
        updatedAt: FieldValue.serverTimestamp(),
        updatedBy: "faculty1",
      })
    );
  });
  await test("students cannot moderate other users' items", async () => {
    await seedDoc("items/item-pending", baseItem("alice", { status: "pending", isStaffVerified: false }));
    const db = dbFor("bob");
    await assertFails(
      db.doc("items/item-pending").update({
        status: "approved",
        isStaffVerified: true,
        updatedAt: FieldValue.serverTimestamp(),
        updatedBy: "bob",
      })
    );
  });
  await test("staff cannot change item ownership or creation time", async () => {
    const created = Timestamp.now();
    await seedDoc("items/item-staff", baseItem("alice", { createdAt: created }));
    const db = dbFor("faculty1", { role: "faculty" });
    await assertFails(
      db.doc("items/item-staff").update({
        reporterUid: "faculty1",
        updatedAt: FieldValue.serverTimestamp(),
        updatedBy: "faculty1",
      })
    );
    await assertFails(
      db.doc("items/item-staff").update({
        createdAt: Timestamp.now(),
        updatedAt: FieldValue.serverTimestamp(),
        updatedBy: "faculty1",
      })
    );
  });
  await test("owner and admin can delete items, other students cannot", async () => {
    await seedDoc("items/item-del-owner", baseItem("alice"));
    await seedDoc("items/item-del-other", baseItem("bob"));
    await seedDoc("items/item-del-admin", baseItem("alice"));
    await assertSucceeds(dbFor("alice").doc("items/item-del-owner").delete());
    await assertFails(dbFor("alice").doc("items/item-del-other").delete());
    await assertSucceeds(dbFor("admin1", { role: "admin" }).doc("items/item-del-admin").delete());
  });

  /* ------------------------------------------------------------------ */
  console.log("\nPrivate item contact");
  await test("owner can read their private contact", async () => {
    await seedDoc("items/item-contact", baseItem("alice"));
    await seedDoc("items/item-contact/private/contact", {
      contact: "private@campus.edu",
      reporterUid: "alice",
      createdAt: Timestamp.now(),
    });
    await assertSucceeds(dbFor("alice").doc("items/item-contact/private/contact").get());
  });
  await test("other students cannot read a private contact", async () => {
    await seedDoc("items/item-contact", baseItem("alice"));
    await seedDoc("items/item-contact/private/contact", {
      contact: "private@campus.edu",
      reporterUid: "alice",
      createdAt: Timestamp.now(),
    });
    await assertFails(dbFor("bob").doc("items/item-contact/private/contact").get());
  });
  await test("staff can read and update a private contact without changing its owner", async () => {
    await seedDoc("items/item-contact", baseItem("alice"));
    await seedDoc("items/item-contact/private/contact", {
      contact: "private@campus.edu",
      reporterUid: "alice",
      createdAt: Timestamp.now(),
    });
    const db = dbFor("faculty1", { role: "faculty" });
    await assertSucceeds(db.doc("items/item-contact/private/contact").get());
    await assertSucceeds(
      db.doc("items/item-contact/private/contact").update({
        contact: "updated@campus.edu",
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      db.doc("items/item-contact/private/contact").update({
        reporterUid: "faculty1",
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
  });

  /* ------------------------------------------------------------------ */
  console.log("\nClaims and private proof");
  await test("student can claim an approved item with private proof atomically", async () => {
    await seedDoc("items/item-claimable", baseItem("alice"));
    const db = dbFor("bob");
    const batch = db.batch();
    batch.set(db.collection("claims").doc("claim-new"), {
      itemId: "item-claimable",
      itemTitle: "Blue backpack",
      claimantUid: "bob",
      claimantName: "Bob",
      claimantEmail: "bob@campus.edu",
      status: "pending",
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });
    batch.set(db.collection("claims").doc("claim-new").collection("private").doc("proof"), {
      proofDetails: "There is a scratch on the left strap.",
      contact: "bob@campus.edu",
      claimantUid: "bob",
      createdAt: FieldValue.serverTimestamp(),
    });
    await assertSucceeds(batch.commit());
  });
  await test("student cannot claim their own item", async () => {
    await seedDoc("items/item-own", baseItem("bob"));
    const db = dbFor("bob");
    await assertFails(
      db.collection("claims").doc("claim-own").set({
        itemId: "item-own",
        itemTitle: "Blue backpack",
        claimantUid: "bob",
        claimantName: "Bob",
        claimantEmail: "bob@campus.edu",
        status: "pending",
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
  });
  await test("student cannot claim a pending item", async () => {
    await seedDoc("items/item-pending", baseItem("alice", { status: "pending", isStaffVerified: false }));
    const db = dbFor("bob");
    await assertFails(
      db.collection("claims").doc("claim-pending").set({
        itemId: "item-pending",
        itemTitle: "Blue backpack",
        claimantUid: "bob",
        claimantName: "Bob",
        claimantEmail: "bob@campus.edu",
        status: "pending",
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
  });
  await test("claimants and staff can read claims, other students cannot", async () => {
    await seedDoc("claims/claim-read", baseClaim("alice", "item-x"));
    await assertSucceeds(dbFor("alice").doc("claims/claim-read").get());
    await assertFails(dbFor("bob").doc("claims/claim-read").get());
    await assertSucceeds(dbFor("faculty1", { role: "faculty" }).doc("claims/claim-read").get());
  });
  await test("claim proof is private to the claimant and staff", async () => {
    await seedDoc("claims/claim-proof", baseClaim("alice", "item-x"));
    await seedDoc("claims/claim-proof/private/proof", {
      proofDetails: "Serial number ends in 42.",
      contact: "alice@campus.edu",
      claimantUid: "alice",
      createdAt: Timestamp.now(),
    });
    await assertSucceeds(dbFor("alice").doc("claims/claim-proof/private/proof").get());
    await assertFails(dbFor("bob").doc("claims/claim-proof/private/proof").get());
    await assertSucceeds(dbFor("faculty1", { role: "faculty" }).doc("claims/claim-proof/private/proof").get());
  });
  await test("staff can resolve a pending claim, students cannot", async () => {
    await seedDoc("claims/claim-resolve", baseClaim("alice", "item-x"));
    await assertFails(
      dbFor("bob").doc("claims/claim-resolve").update({
        status: "approved",
        reviewedBy: "bob",
        reviewedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertSucceeds(
      dbFor("faculty1", { role: "faculty" }).doc("claims/claim-resolve").update({
        status: "approved",
        reviewedBy: "faculty1",
        reviewedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
  });
  await test("claims cannot be edited after resolution and are admin-deletable", async () => {
    await seedDoc("claims/claim-resolved", baseClaim("alice", "item-x", { status: "approved" }));
    await assertFails(
      dbFor("faculty1", { role: "faculty" }).doc("claims/claim-resolved").update({
        status: "rejected",
        reviewedBy: "faculty1",
        reviewedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertSucceeds(dbFor("admin1", { role: "admin" }).doc("claims/claim-resolved").delete());
  });

  /* ------------------------------------------------------------------ */
  console.log("\nUsers and roles");
  await test("student can create only their own student profile", async () => {
    const db = dbFor("alice");
    await assertSucceeds(db.doc("users/alice").set(baseUser("alice")));
    await assertFails(db.doc("users/bob").set(baseUser("bob")));
  });
  await test("student cannot self-provision an admin or suspended profile", async () => {
    const db = dbFor("alice");
    await assertFails(db.doc("users/alice").set(baseUser("alice", { role: "admin" })));
    await assertFails(db.doc("users/alice").set(baseUser("alice", { status: "Suspended" })));
  });
  await test("user can update their own name and department only", async () => {
    await seedDoc("users/alice", baseUser("alice"));
    const db = dbFor("alice");
    await assertSucceeds(
      db.doc("users/alice").update({
        name: "Alice Updated",
        department: "Physics",
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      db.doc("users/alice").update({
        role: "admin",
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      db.doc("users/alice").update({
        status: "Suspended",
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
  });
  await test("students cannot read other profiles, admins can", async () => {
    await seedDoc("users/alice", baseUser("alice"));
    await assertFails(dbFor("bob").doc("users/alice").get());
    await assertSucceeds(dbFor("admin1", { role: "admin" }).doc("users/alice").get());
  });
  await test("admin can edit a display name but not role, status or email", async () => {
    await seedDoc("users/alice", baseUser("alice"));
    const db = dbFor("admin1", { role: "admin" });
    await assertSucceeds(
      db.doc("users/alice").update({
        name: "Alice Admin Edited",
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      db.doc("users/alice").update({
        role: "faculty",
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      db.doc("users/alice").update({
        email: "attacker@campus.edu",
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      db.doc("users/alice").update({
        status: "Suspended",
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
  });
  await test("client-side profile deletion is denied even for admins", async () => {
    await seedDoc("users/alice", baseUser("alice"));
    await assertFails(dbFor("alice").doc("users/alice").delete());
    await assertFails(dbFor("admin1", { role: "admin" }).doc("users/alice").delete());
  });

  /* ------------------------------------------------------------------ */
  console.log("\nNotifications");
  await test("students can notify themselves but not other users", async () => {
    const db = dbFor("alice");
    await assertSucceeds(
      db.collection("notifications").doc("notif-self").set({
        toUid: "alice",
        text: "Your report was submitted.",
        read: false,
        createdAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      db.collection("notifications").doc("notif-other").set({
        toUid: "bob",
        text: "Fake notification.",
        read: false,
        createdAt: FieldValue.serverTimestamp(),
      })
    );
  });
  await test("staff can notify another user about a moderation result", async () => {
    const db = dbFor("faculty1", { role: "faculty" });
    await assertSucceeds(
      db.collection("notifications").doc("notif-staff").set({
        toUid: "alice",
        text: "Your report was approved.",
        read: false,
        createdAt: FieldValue.serverTimestamp(),
      })
    );
  });
  await test("recipients can only flip the read flag", async () => {
    await seedDoc("notifications/notif-read", {
      toUid: "alice",
      text: "Hello",
      read: false,
      createdAt: Timestamp.now(),
    });
    const db = dbFor("alice");
    await assertSucceeds(db.doc("notifications/notif-read").update({ read: true }));
    await assertFails(db.doc("notifications/notif-read").update({ text: "Changed" }));
    await assertFails(dbFor("bob").doc("notifications/notif-read").update({ read: true }));
  });
  await test("recipients can delete their notification, others cannot", async () => {
    await seedDoc("notifications/notif-del", {
      toUid: "alice",
      text: "Hello",
      read: false,
      createdAt: Timestamp.now(),
    });
    await assertFails(dbFor("bob").doc("notifications/notif-del").delete());
    await assertSucceeds(dbFor("alice").doc("notifications/notif-del").delete());
  });
  await test("notification deep-link URLs must be same-origin paths", async () => {
    const db = dbFor("alice");
    await assertSucceeds(
      db.collection("notifications").doc("notif-url-ok").set({
        toUid: "alice",
        text: "Open your dashboard",
        read: false,
        event: "claim_status",
        url: "/index.html?view=dashboard",
        createdAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      db.collection("notifications").doc("notif-url-bad").set({
        toUid: "alice",
        text: "Open a phishing page",
        read: false,
        url: "//evil.example/steal",
        createdAt: FieldValue.serverTimestamp(),
      })
    );
  });

  /* ------------------------------------------------------------------ */
  console.log("\nLevel 2: devices and notification preferences");
  await test("a user can register a push device and only they can read it", async () => {
    const db = dbFor("alice");
    await assertSucceeds(db.doc("users/alice/devices/web-1").set(newDevice()));
    await assertSucceeds(dbFor("alice").doc("users/alice/devices/web-1").get());
    await assertFails(dbFor("bob").doc("users/alice/devices/web-1").get());
    await assertFails(dbFor("faculty1", { role: "faculty" }).doc("users/alice/devices/web-1").get());
  });
  await test("a user cannot register a device for another account", async () => {
    await assertFails(dbFor("bob").doc("users/alice/devices/web-2").set(newDevice()));
  });
  await test("device documents reject invalid platforms, short tokens and extra fields", async () => {
    const db = dbFor("alice");
    await assertFails(db.doc("users/alice/devices/bad-platform").set(newDevice({ platform: "desktop" })));
    await assertFails(db.doc("users/alice/devices/short-token").set(newDevice({ token: "too-short" })));
    await assertFails(
      db.doc("users/alice/devices/extra-field").set(newDevice({ role: "admin" }))
    );
  });
  await test("a user can rotate/disable and delete their own device token", async () => {
    await seedDoc("users/alice/devices/web-3", baseDevice());
    const db = dbFor("alice");
    await assertSucceeds(
      db.doc("users/alice/devices/web-3").update({
        token: "fcm-token-rotated-abcdefghijklmnop",
        enabled: false,
        updatedAt: FieldValue.serverTimestamp(),
        lastSeenAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(dbFor("bob").doc("users/alice/devices/web-3").delete());
    await assertSucceeds(db.doc("users/alice/devices/web-3").delete());
  });
  await test("a user can save a valid preference map", async () => {
    await seedDoc("users/alice", baseUser("alice"));
    const db = dbFor("alice");
    await assertSucceeds(
      db.doc("users/alice").update({
        prefs: {
          pushEnabled: true,
          emailEnabled: false,
          claimStatus: true,
          matchFound: false,
          chatMessage: true,
          custodyUpdate: true,
          broadcast: true,
          weeklyDigest: false,
        },
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
  });
  await test("preference maps reject unknown keys and non-boolean values", async () => {
    await seedDoc("users/alice", baseUser("alice"));
    const db = dbFor("alice");
    await assertFails(
      db.doc("users/alice").update({
        prefs: { pushEnabled: true, role: "admin" },
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      db.doc("users/alice").update({
        prefs: { pushEnabled: "yes" },
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      dbFor("bob").doc("users/alice").update({
        prefs: { pushEnabled: false },
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
  });

  /* ------------------------------------------------------------------ */
  console.log("\nLevel 2: chats, messages and read markers");
  await test("only chat participants and staff can read a chat", async () => {
    await seedDoc("chats/chat-pair", baseChat());
    await assertSucceeds(dbFor("alice").doc("chats/chat-pair").get());
    await assertSucceeds(dbFor("bob").doc("chats/chat-pair").get());
    await assertSucceeds(dbFor("faculty1", { role: "faculty" }).doc("chats/chat-pair").get());
    await assertFails(dbFor("carol").doc("chats/chat-pair").get());
    await assertFails(unauthenticatedDb().doc("chats/chat-pair").get());
  });
  await test("clients cannot create, edit or delete chats", async () => {
    await seedDoc("chats/chat-pair", baseChat());
    const db = dbFor("alice");
    await assertFails(db.collection("chats").doc("chat-forged").set(baseChat()));
    await assertFails(db.doc("chats/chat-pair").update({ status: "closed" }));
    await assertFails(db.doc("chats/chat-pair").delete());
  });
  await test("participants and staff can read messages, outsiders cannot", async () => {
    await seedDoc("chats/chat-pair", baseChat());
    await seedDoc("chats/chat-pair/messages/msg-1", {
      senderUid: "alice",
      senderRole: "student",
      text: "Hello, is this my bag?",
      createdAt: Timestamp.now(),
    });
    await assertSucceeds(dbFor("alice").doc("chats/chat-pair/messages/msg-1").get());
    await assertSucceeds(dbFor("bob").doc("chats/chat-pair/messages/msg-1").get());
    await assertSucceeds(
      dbFor("faculty1", { role: "faculty" }).doc("chats/chat-pair/messages/msg-1").get()
    );
    await assertFails(dbFor("carol").doc("chats/chat-pair/messages/msg-1").get());
  });
  await test("clients cannot write chat messages directly", async () => {
    await seedDoc("chats/chat-pair", baseChat());
    const db = dbFor("alice");
    await assertFails(
      db.collection("chats").doc("chat-pair").collection("messages").doc("msg-forged").set({
        senderUid: "alice",
        text: "Bypassing the callable",
        createdAt: FieldValue.serverTimestamp(),
      })
    );
    await seedDoc("chats/chat-pair/messages/msg-1", {
      senderUid: "alice",
      text: "Hello",
      createdAt: Timestamp.now(),
    });
    await assertFails(
      db.doc("chats/chat-pair/messages/msg-1").update({ text: "Edited" })
    );
    await assertFails(db.doc("chats/chat-pair/messages/msg-1").delete());
  });
  await test("participants can write only their own read marker", async () => {
    await seedDoc("chats/chat-pair", baseChat());
    const alice = dbFor("alice");
    await assertSucceeds(
      alice.doc("chats/chat-pair/reads/alice").set({
        lastReadAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      dbFor("bob").doc("chats/chat-pair/reads/alice").set({
        lastReadAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      dbFor("carol").doc("chats/chat-pair/reads/carol").set({
        lastReadAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      alice.doc("chats/chat-pair/reads/alice").set({
        lastReadAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
        extra: true,
      })
    );
    await assertSucceeds(alice.doc("chats/chat-pair/reads/alice").get());
    await assertSucceeds(
      dbFor("faculty1", { role: "faculty" }).doc("chats/chat-pair/reads/alice").get()
    );
    await assertFails(dbFor("bob").doc("chats/chat-pair/reads/alice").get());
    await assertFails(alice.doc("chats/chat-pair/reads/alice").delete());
  });

  /* ------------------------------------------------------------------ */
  console.log("\nLevel 2: moderation, receipts and handover secrets");
  await test("moderation reports are visible to the reporter and staff only", async () => {
    await seedDoc("moderation/mod-1", {
      reportedBy: "alice",
      reportedUid: "bob",
      chatId: "chat-pair",
      messageId: "msg-1",
      reason: "Harassment",
      status: "open",
      createdAt: Timestamp.now(),
    });
    await assertSucceeds(dbFor("alice").doc("moderation/mod-1").get());
    await assertFails(dbFor("bob").doc("moderation/mod-1").get());
    await assertFails(dbFor("carol").doc("moderation/mod-1").get());
    await assertSucceeds(dbFor("faculty1", { role: "faculty" }).doc("moderation/mod-1").get());
  });
  await test("clients cannot create or delete moderation reports", async () => {
    await seedDoc("moderation/mod-1", {
      reportedBy: "alice",
      reportedUid: "bob",
      chatId: "chat-pair",
      messageId: "msg-1",
      reason: "Harassment",
      status: "open",
      createdAt: Timestamp.now(),
    });
    await assertFails(
      dbFor("alice").collection("moderation").doc("mod-forged").set({
        reportedBy: "alice",
        reportedUid: "bob",
        reason: "Forged",
        status: "open",
        createdAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(dbFor("alice").doc("moderation/mod-1").delete());
    await assertFails(dbFor("faculty1", { role: "faculty" }).doc("moderation/mod-1").delete());
  });
  await test("staff can review a moderation report, students cannot", async () => {
    await seedDoc("moderation/mod-1", {
      reportedBy: "alice",
      reportedUid: "bob",
      chatId: "chat-pair",
      messageId: "msg-1",
      reason: "Harassment",
      status: "open",
      createdAt: Timestamp.now(),
    });
    await assertFails(
      dbFor("alice").doc("moderation/mod-1").update({
        status: "reviewed",
        reviewedBy: "alice",
        reviewedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertSucceeds(
      dbFor("faculty1", { role: "faculty" }).doc("moderation/mod-1").update({
        status: "reviewed",
        reviewedBy: "faculty1",
        reviewedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
  });
  await test("return receipts are readable by the two parties and staff, never writable", async () => {
    await seedDoc("receipts/claim-x", {
      claimId: "claim-x",
      itemId: "item-x",
      itemTitle: "Blue backpack",
      claimantUid: "alice",
      reporterUid: "bob",
      receiptCode: "CC-RCPT-123456",
      returnedAt: Timestamp.now(),
      createdAt: Timestamp.now(),
    });
    await assertSucceeds(dbFor("alice").doc("receipts/claim-x").get());
    await assertSucceeds(dbFor("bob").doc("receipts/claim-x").get());
    await assertSucceeds(dbFor("faculty1", { role: "faculty" }).doc("receipts/claim-x").get());
    await assertFails(dbFor("carol").doc("receipts/claim-x").get());
    await assertFails(
      dbFor("alice").collection("receipts").doc("receipt-forged").set({
        claimantUid: "alice",
        receiptCode: "FORGED",
        returnedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      dbFor("faculty1", { role: "faculty" }).doc("receipts/claim-x").update({ receiptCode: "FORGED" })
    );
    await assertFails(dbFor("admin1", { role: "admin" }).doc("receipts/claim-x").delete());
  });
  await test("handover token documents are server-only", async () => {
    await seedDoc("claims/claim-x", baseClaim("alice", "item-x", { status: "approved" }));
    await seedDoc("claims/claim-x/private/handover", {
      tokenHash: "a".repeat(64),
      expiresAt: Timestamp.now(),
      used: false,
      createdAt: Timestamp.now(),
    });
    await assertFails(dbFor("alice").doc("claims/claim-x/private/handover").get());
    await assertFails(
      dbFor("faculty1", { role: "faculty" }).doc("claims/claim-x/private/handover").get()
    );
    await assertFails(
      dbFor("admin1", { role: "admin" }).doc("claims/claim-x/private/handover").get()
    );
    await assertFails(
      dbFor("alice").doc("claims/claim-x/private/handover").set({
        tokenHash: "b".repeat(64),
        used: false,
      })
    );
  });
  await test("staff cannot resolve a claim directly to returned", async () => {
    await seedDoc("claims/claim-return", baseClaim("alice", "item-x", { status: "pending" }));
    await assertFails(
      dbFor("faculty1", { role: "faculty" }).doc("claims/claim-return").update({
        status: "returned",
        reviewedBy: "faculty1",
        reviewedAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
  });
  await test("server bookkeeping collections deny client reads and writes", async () => {
    await seedDoc("rateLimits/rl-1", { count: 1, windowStart: Timestamp.now() });
    await seedDoc("emailUsage/alice", { count: 2, day: "2026-01-01" });
    await seedDoc("emailFailures/fail-1", { uid: "alice", category: "temporary", createdAt: Timestamp.now() });

    await assertFails(dbFor("alice").doc("rateLimits/rl-1").get());
    await assertFails(dbFor("admin1", { role: "admin" }).doc("rateLimits/rl-1").get());
    await assertFails(
      dbFor("admin1", { role: "admin" }).doc("rateLimits/rl-1").set({ count: 0 })
    );
    await assertFails(dbFor("alice").doc("emailUsage/alice").get());
    await assertFails(dbFor("admin1", { role: "admin" }).doc("emailUsage/alice").get());
    await assertFails(
      dbFor("alice").doc("emailUsage/alice").set({ count: 0, day: "2026-01-01" })
    );
    await assertFails(dbFor("alice").doc("emailFailures/fail-1").get());
    await assertSucceeds(dbFor("admin1", { role: "admin" }).doc("emailFailures/fail-1").get());
    await assertFails(
      dbFor("admin1", { role: "admin" }).doc("emailFailures/fail-1").set({ uid: "alice" })
    );
  });

  /* ------------------------------------------------------------------ */
  console.log("\nComplaints");
  await test("student can create their own complaint", async () => {
    const db = dbFor("alice");
    await assertSucceeds(
      db.collection("complaints").doc("complaint-new").set({
        reporterUid: "alice",
        studentName: "Alice",
        studentEmail: "alice@campus.edu",
        subject: "Disputed claim",
        type: "Disputed Claim",
        message: "Please verify ownership records.",
        status: "Under Review",
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      db.collection("complaints").doc("complaint-forged").set({
        reporterUid: "bob",
        studentName: "Bob",
        studentEmail: "alice@campus.edu",
        subject: "Forged",
        type: "Disputed Claim",
        message: "Forged complaint.",
        status: "Under Review",
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
  });
  await test("complaints are private to the reporter and staff", async () => {
    await seedDoc("complaints/complaint-read", {
      reporterUid: "alice",
      studentName: "Alice",
      studentEmail: "alice@campus.edu",
      subject: "Disputed claim",
      type: "Disputed Claim",
      message: "Please verify ownership records.",
      status: "Under Review",
      createdAt: Timestamp.now(),
      updatedAt: Timestamp.now(),
    });
    await assertSucceeds(dbFor("alice").doc("complaints/complaint-read").get());
    await assertFails(dbFor("bob").doc("complaints/complaint-read").get());
    await assertSucceeds(dbFor("faculty1", { role: "faculty" }).doc("complaints/complaint-read").get());
  });
  await test("staff can update complaint status, students cannot", async () => {
    await seedDoc("complaints/complaint-status", {
      reporterUid: "alice",
      studentName: "Alice",
      studentEmail: "alice@campus.edu",
      subject: "Disputed claim",
      type: "Disputed Claim",
      message: "Please verify ownership records.",
      status: "Under Review",
      createdAt: Timestamp.now(),
      updatedAt: Timestamp.now(),
    });
    await assertFails(
      dbFor("alice").doc("complaints/complaint-status").update({
        status: "Resolved",
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
    await assertSucceeds(
      dbFor("faculty1", { role: "faculty" }).doc("complaints/complaint-status").update({
        status: "Investigating",
        updatedAt: FieldValue.serverTimestamp(),
      })
    );
  });

  /* ------------------------------------------------------------------ */
  console.log("\nMetadata and audit logs");
  await test("verified users can read metadata but only admins can write", async () => {
    await seedDoc("metadata/categories", { list: ["Bags"] });
    await assertSucceeds(dbFor("alice").doc("metadata/categories").get());
    await assertFails(dbFor("alice").doc("metadata/broadcast").set({ text: "Fake notice" }));
    await assertSucceeds(
      dbFor("admin1", { role: "admin" }).doc("metadata/broadcast").set({ text: "Real notice" })
    );
  });
  await test("client audit entries must match the caller's real role", async () => {
    const studentDb = dbFor("alice");
    await assertSucceeds(
      studentDb.collection("logs").doc("log-ok").set({
        actorUid: "alice",
        actorRole: "student",
        action: "client.ui_event",
        targetType: "ui",
        targetId: "",
        details: "Opened the board",
        text: "Opened the board",
        source: "client",
        createdAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      studentDb.collection("logs").doc("log-forged").set({
        actorUid: "alice",
        actorRole: "admin",
        action: "client.ui_event",
        targetType: "ui",
        targetId: "",
        details: "Forged role",
        text: "Forged role",
        source: "client",
        createdAt: FieldValue.serverTimestamp(),
      })
    );
    await assertFails(
      studentDb.collection("logs").doc("log-other").set({
        actorUid: "bob",
        actorRole: "student",
        action: "client.ui_event",
        targetType: "ui",
        targetId: "",
        details: "Forged actor",
        text: "Forged actor",
        source: "client",
        createdAt: FieldValue.serverTimestamp(),
      })
    );
  });
  await test("audit logs are append-only and readable only by admins", async () => {
    await seedDoc("logs/log-seed", {
      actorUid: "system",
      actorRole: "system",
      action: "item.created",
      targetType: "item",
      targetId: "item-1",
      details: "Created item",
      text: "Created item",
      source: "function",
      createdAt: Timestamp.now(),
    });
    await assertFails(dbFor("alice").doc("logs/log-seed").update({ text: "Changed" }));
    await assertFails(dbFor("alice").doc("logs/log-seed").delete());
    await assertFails(dbFor("alice").doc("logs/log-seed").get());
    await assertSucceeds(dbFor("admin1", { role: "admin" }).doc("logs/log-seed").get());
  });

  /* ------------------------------------------------------------------ */
  console.log("\nCloud Storage");
  await test("verified owner can upload a JPEG to their own folder", async () => {
    const storage = context("alice").storage();
    await assertSucceeds(
      storage.ref("items/alice/photo.jpg").put(new Uint8Array(1024), { contentType: "image/jpeg" })
    );
  });
  await test("unverified and suspended accounts cannot upload", async () => {
    const unverified = context("alice", { email_verified: false }).storage();
    await assertFails(
      unverified.ref("items/alice/photo.jpg").put(new Uint8Array(16), { contentType: "image/jpeg" })
    );
    const suspended = context("alice", { suspended: true }).storage();
    await assertFails(
      suspended.ref("items/alice/photo.jpg").put(new Uint8Array(16), { contentType: "image/jpeg" })
    );
  });
  await test("students cannot write into another user's folder", async () => {
    const storage = context("bob").storage();
    await assertFails(
      storage.ref("items/alice/photo.jpg").put(new Uint8Array(16), { contentType: "image/jpeg" })
    );
  });
  await test("non-image content types and bad file names are rejected", async () => {
    const storage = context("alice").storage();
    await assertFails(
      storage.ref("items/alice/photo.gif").put(new Uint8Array(16), { contentType: "image/gif" })
    );
    await assertFails(
      storage.ref("items/alice/malware.exe").put(new Uint8Array(16), { contentType: "image/jpeg" })
    );
  });
  await test("uploads larger than 3 MB are rejected", async () => {
    const storage = context("alice").storage();
    await assertFails(
      storage
        .ref("items/alice/huge.jpg")
        .put(new Uint8Array(3 * 1024 * 1024 + 1), { contentType: "image/jpeg" })
    );
  });
  await test("only verified signed-in users can read board photos", async () => {
    const alice = context("alice").storage();
    await assertSucceeds(
      alice.ref("items/alice/readable.jpg").put(new Uint8Array(32), { contentType: "image/jpeg" })
    );
    await assertFails(
      testEnv.unauthenticatedContext().storage().ref("items/alice/readable.jpg").getDownloadURL()
    );
    await assertSucceeds(context("bob").storage().ref("items/alice/readable.jpg").getDownloadURL());
  });
  await test("owners and admins can delete photos, other students cannot", async () => {
    const alice = context("alice").storage();
    await alice.ref("items/alice/owner-delete.jpg").put(new Uint8Array(16), { contentType: "image/jpeg" });
    await alice.ref("items/alice/admin-delete.jpg").put(new Uint8Array(16), { contentType: "image/jpeg" });
    await alice.ref("items/alice/other-delete.jpg").put(new Uint8Array(16), { contentType: "image/jpeg" });

    await assertSucceeds(alice.ref("items/alice/owner-delete.jpg").delete());
    await assertFails(context("bob").storage().ref("items/alice/other-delete.jpg").delete());
    await assertSucceeds(
      context("admin1", { role: "admin" }).storage().ref("items/alice/admin-delete.jpg").delete()
    );
  });

  await testEnv.cleanup();

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed) {
    console.error("\nFailures:");
    failures.forEach(({ name }) => console.error(` - ${name}`));
    process.exitCode = 1;
  }
}

run().catch(async (error) => {
  console.error("\nTest harness failed:", error);
  try {
    if (testEnv) await testEnv.cleanup();
  } catch (cleanupError) {
    // Ignore cleanup errors.
  }
  process.exitCode = 1;
});
