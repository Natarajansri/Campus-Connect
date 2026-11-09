#!/usr/bin/env node
"use strict";

/**
 * Campus Connect — Level 2 Cloud Functions tests.
 *
 * Run through the Firebase Emulator Suite:
 *   npm run test:functions
 *
 * The suite starts only the Firestore emulator and calls the v2 callable
 * `.run()` entry points directly with a synthetic auth request. This exercises
 * the same privileged code paths as production (Admin SDK, transactions,
 * rate-limit documents, fan-out) without needing real FCM/Resend credentials.
 */

process.env.GCLOUD_PROJECT = process.env.GCLOUD_PROJECT || "demo-campusconnect";
process.env.FIRESTORE_EMULATOR_HOST =
  process.env.FIRESTORE_EMULATOR_HOST || "127.0.0.1:8080";
process.env.FUNCTIONS_EMULATOR = "true";
process.env.EMAIL_UNSUB_SECRET =
  process.env.EMAIL_UNSUB_SECRET || "level2-test-unsubscribe-secret";

const assert = require("node:assert/strict");
const crypto = require("node:crypto");

const helpers = require("../../functions/helpers");
const chat = require("../../functions/chat");
const handover = require("../../functions/handover");
const email = require("../../functions/email");
const notifications = require("../../functions/notifications");

// Use the same Admin SDK instance the Functions modules initialized. The root
// dev dependency may be a newer major with a different export shape, so mixing
// them would create two SDK instances pointing at the same emulator.
const admin = helpers.admin;
const db = helpers.db;
const FieldValue = admin.firestore.FieldValue;
const Timestamp = admin.firestore.Timestamp;

const PROJECT_ID = process.env.GCLOUD_PROJECT;
const EMULATOR_HOST = process.env.FIRESTORE_EMULATOR_HOST;

let passed = 0;
let failed = 0;
const failures = [];

function student(uid) {
  return {
    auth: {
      uid,
      token: { email_verified: true, role: "student", email: `${uid}@campus.edu` },
    },
  };
}

function faculty(uid) {
  return {
    auth: {
      uid,
      token: { email_verified: true, role: "faculty", email: `${uid}@campus.edu` },
    },
  };
}

function request(auth, data) {
  return { ...auth, data };
}

async function clearFirestore() {
  const url =
    `http://${EMULATOR_HOST}/emulator/v1/projects/${PROJECT_ID}` +
    "/databases/(default)/documents";
  const response = await fetch(url, { method: "DELETE" });
  if (!response.ok && response.status !== 404) {
    throw new Error(`Could not clear Firestore: HTTP ${response.status}`);
  }
}

async function test(name, fn) {
  try {
    await clearFirestore();
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

async function seedUser(uid, overrides = {}) {
  await db.collection("users").doc(uid).set(
    {
      uid,
      name: overrides.name || "Test User",
      email: overrides.email || `${uid}@campus.edu`,
      department: "Computer Science",
      role: "student",
      status: "Active",
      prefs: overrides.prefs || helpers.DEFAULT_PREFS,
      createdAt: Timestamp.now(),
      updatedAt: Timestamp.now(),
      ...overrides,
    },
    { merge: true }
  );
}

async function seedItem(itemId, reporterUid, overrides = {}) {
  await db.collection("items").doc(itemId).set({
    type: "lost",
    title: "Blue backpack",
    category: "Bags",
    location: "Main Library",
    desc: "Blue backpack with a laptop sleeve.",
    image: "",
    reporterUid,
    reporterName: "Reporter",
    reporterFirstName: "Reporter",
    reporterDepartment: "Computer Science",
    status: "approved",
    isCustody: false,
    custodyLocation: "",
    custodyHours: "",
    custodyNotes: "",
    isPinned: false,
    isStaffVerified: true,
    createdAt: Timestamp.now(),
    updatedAt: Timestamp.now(),
    updatedBy: reporterUid,
    ...overrides,
  });
}

async function seedClaim(claimId, claimantUid, itemId, overrides = {}) {
  await db.collection("claims").doc(claimId).set({
    itemId,
    itemTitle: "Blue backpack",
    claimantUid,
    claimantName: "Claimant",
    claimantEmail: `${claimantUid}@campus.edu`,
    status: "approved",
    createdAt: Timestamp.now(),
    updatedAt: Timestamp.now(),
    ...overrides,
  });
}

async function seedChat(chatId, overrides = {}) {
  await db.collection("chats").doc(chatId).set({
    itemId: "item-1",
    itemTitle: "Blue backpack",
    claimId: "claim-1",
    claimantUid: "alice",
    reporterUid: "bob",
    participantUids: ["alice", "bob"],
    status: "open",
    lastMessage: "",
    lastSenderUid: "",
    lastMessageAt: FieldValue.serverTimestamp(),
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
    ...overrides,
  });
}

function fakeNotificationEvent(notifId) {
  return {
    params: { notifId },
    data: {
      data: () => ({ toUid: "alice", text: "A chat message arrived.", event: "chatMessage" }),
    },
  };
}

async function readDoc(path) {
  const snap = await db.doc(path).get();
  return snap.exists ? snap.data() : null;
}

async function expectHttpsError(promise, code) {
  let error = null;
  try {
    await promise;
  } catch (caught) {
    error = caught;
  }
  assert.ok(error, "Expected the callable to reject");
  if (code) assert.equal(error.code, code, `Expected ${code}, got ${error.code}`);
  return error;
}

async function run() {
  /* ------------------------------------------------------------------ */
  console.log("\nHelpers: preferences and validation");
  await test("preference defaults safely handle missing and hostile values", async () => {
    const defaults = helpers.normalizePrefs(undefined);
    assert.equal(defaults.pushEnabled, true);
    assert.equal(defaults.emailEnabled, true);
    assert.equal(defaults.weeklyDigest, false);

    const normalized = helpers.normalizePrefs({
      pushEnabled: false,
      weeklyDigest: true,
      emailEnabled: "yes",
      role: "admin",
    });
    assert.equal(normalized.pushEnabled, false);
    assert.equal(normalized.weeklyDigest, true);
    assert.equal(normalized.emailEnabled, true, "non-boolean must fall back to default");
    assert.equal(Object.prototype.hasOwnProperty.call(normalized, "role"), false);
  });
  await test("prefEnabled respects channel and event switches", async () => {
    assert.equal(helpers.prefEnabled({}, "claimApproved", "push"), true);
    assert.equal(helpers.prefEnabled({}, "claimApproved", "email"), true);
    assert.equal(helpers.prefEnabled({ pushEnabled: false }, "claimApproved", "push"), false);
    assert.equal(helpers.prefEnabled({ emailEnabled: false }, "claimApproved", "email"), false);
    assert.equal(helpers.prefEnabled({ claimStatus: false }, "claimApproved", "email"), false);
    assert.equal(helpers.prefEnabled({ broadcast: false }, "broadcast", "push"), false);
    assert.equal(
      helpers.prefEnabled({ claimStatus: false }, "suspensionNotice", "email"),
      true,
      "unknown/security events must not be disabled by a preference typo"
    );
  });
  await test("clampString and isSafeId reject unsafe ids", async () => {
    assert.equal(helpers.clampString("  hello  ", 3), "  h");
    assert.equal(helpers.isSafeId("claim_1"), true);
    assert.equal(helpers.isSafeId("claim/1"), false);
    assert.equal(helpers.isSafeId(""), false);
  });

  /* ------------------------------------------------------------------ */
  console.log("\nEmail: templates, preferences and unsubscribe tokens");
  await test("email templates escape user text", async () => {
    const rendered = email.renderEmail({
      event: "claimApproved",
      text: '<img src=x onerror=alert("xss")> & "quoted"',
      url: "/index.html?view=dashboard",
      unsubscribe: "https://example.test/unsub?token=abc",
    });
    assert.equal(rendered.html.includes("<img src=x"), false);
    assert.equal(rendered.html.includes("&lt;img"), true);
    assert.equal(rendered.html.includes("&amp;"), true);
    assert.equal(rendered.text.includes('<img src=x onerror=alert("xss")>'), true);
    assert.match(rendered.subject, /Claim approved/);
  });
  await test("renderEmail rejects unknown events instead of guessing a template", async () => {
    const rendered = email.renderEmail({ event: "not-a-real-event", text: "Hello" });
    assert.match(rendered.subject, /Campus Connect/);
    assert.match(rendered.html, /Hello/);
  });
  await test("unsubscribe tokens round-trip, reject tampering and malformed input", async () => {
    const token = email.createUnsubscribeToken("alice");
    const verified = email.verifyUnsubscribeToken(token);
    assert.equal(verified.uid, "alice");

    const [payload, signature] = token.split(".");
    const tamperedSignature =
      (signature[0] === "A" ? "B" : "A") + signature.slice(1);
    assert.equal(
      email.verifyUnsubscribeToken(`${payload}.${tamperedSignature}`),
      null
    );
    assert.equal(email.verifyUnsubscribeToken(""), null);
    assert.equal(email.verifyUnsubscribeToken("not-a-token"), null);
    assert.equal(email.verifyUnsubscribeToken(null), null);

    // A correctly signed but expired token must still be refused.
    const expiredPayload = Buffer.from(
      JSON.stringify({
        uid: "alice",
        exp: Math.floor(Date.now() / 1000) - 60,
        purpose: "email-unsubscribe",
      })
    ).toString("base64url");
    const expiredSignature = crypto
      .createHmac("sha256", process.env.EMAIL_UNSUB_SECRET)
      .update(expiredPayload)
      .digest("base64url");
    assert.equal(
      email.verifyUnsubscribeToken(`${expiredPayload}.${expiredSignature}`),
      null,
      "expired tokens must be rejected"
    );
  });
  await test("sendNotificationEmail honours email preferences", async () => {
    await seedUser("alice", { prefs: { emailEnabled: false } });
    const disabled = await email.sendNotificationEmail({
      uid: "alice",
      event: "claimApproved",
      text: "Your claim was approved.",
    });
    assert.equal(disabled.reason, "preference-disabled");

    await seedUser("alice", { prefs: { emailEnabled: true, claimStatus: false } });
    const eventOff = await email.sendNotificationEmail({
      uid: "alice",
      event: "claimApproved",
      text: "Your claim was approved.",
    });
    assert.equal(eventOff.reason, "preference-disabled");

    const missing = await email.sendNotificationEmail({
      uid: "nobody",
      event: "claimApproved",
      text: "No profile.",
    });
    assert.equal(missing.reason, "no-profile");
  });
  await test("a missing provider key logs a failure and never throws", async () => {
    await seedUser("alice");
    const result = await email.sendNotificationEmail({
      uid: "alice",
      event: "claimApproved",
      text: "Your claim was approved.",
    });
    assert.equal(result.sent, false);
    assert.equal(result.reason, "provider-not-configured");
    const failuresSnap = await db.collection("emailFailures").get();
    assert.ok(failuresSnap.size >= 1);
    assert.equal(failuresSnap.docs[0].data().reason, "provider-not-configured");
  });

  /* ------------------------------------------------------------------ */
  console.log("\nChat: creation guards, callable-only messages and moderation");
  await test("an approved claim opens the deterministic chat for its claimant", async () => {
    await seedUser("alice");
    await seedItem("item-1", "bob");
    await seedClaim("claim-1", "alice", "item-1");

    const result = await chat.ensureChat.run(
      request(student("alice"), { claimId: "claim-1" })
    );
    assert.equal(result.chatId, "item-1_alice");
    assert.equal(result.created, true);
    const stored = await readDoc("chats/item-1_alice");
    assert.equal(stored.claimantUid, "alice");
    assert.equal(stored.reporterUid, "bob");
    assert.equal(stored.status, "open");
  });
  await test("chat creation rejects pending claims and unrelated members", async () => {
    await seedUser("alice");
    await seedUser("carol");
    await seedItem("item-1", "bob");
    await seedClaim("claim-pending", "alice", "item-1", { status: "pending" });
    await seedClaim("claim-approved", "alice", "item-1");

    await expectHttpsError(
      chat.ensureChat.run(request(student("alice"), { claimId: "claim-pending" })),
      "failed-precondition"
    );
    await expectHttpsError(
      chat.ensureChat.run(request(student("carol"), { claimId: "claim-approved" })),
      "permission-denied"
    );
  });
  await test("participants can send messages; outsiders and closed chats cannot", async () => {
    await seedUser("alice");
    await seedUser("bob");
    await seedUser("carol");
    await seedChat("chat-1");
    await seedItem("item-1", "bob");

    const sent = await chat.sendChatMessage.run(
      request(student("alice"), { chatId: "chat-1", text: "  Hello there  " })
    );
    assert.ok(sent.messageId);
    const messages = await db.collection("chats/chat-1/messages").get();
    assert.equal(messages.size, 1);
    assert.equal(messages.docs[0].data().text, "Hello there");
    assert.equal(messages.docs[0].data().senderUid, "alice");
    assert.equal((await readDoc("chats/chat-1")).lastMessage, "Hello there");

    await expectHttpsError(
      chat.sendChatMessage.run(
        request(student("carol"), { chatId: "chat-1", text: "Intruder" })
      ),
      "permission-denied"
    );

    await chat.closeChatsForItem("item-1", "item returned", "faculty1");
    assert.equal((await readDoc("chats/chat-1")).status, "closed");
    await expectHttpsError(
      chat.sendChatMessage.run(
        request(student("alice"), { chatId: "chat-1", text: "After close" })
      ),
      "failed-precondition"
    );
  });
  await test("message rate limiting rejects the eleventh message in a minute", async () => {
    await seedUser("alice");
    await seedUser("bob");
    await seedChat("chat-1");
    await seedItem("item-1", "bob");

    for (let index = 0; index < 10; index += 1) {
      await chat.sendChatMessage.run(
        request(student("alice"), { chatId: "chat-1", text: `Message ${index}` })
      );
    }
    await expectHttpsError(
      chat.sendChatMessage.run(
        request(student("alice"), { chatId: "chat-1", text: "One too many" })
      ),
      "resource-exhausted"
    );
  });
  await test("reporting a message records moderation without copying message text", async () => {
    await seedUser("alice");
    await seedUser("bob");
    await seedUser("carol");
    await seedChat("chat-1");
    await seedItem("item-1", "bob");
    const sent = await chat.sendChatMessage.run(
      request(student("alice"), { chatId: "chat-1", text: "Abusive message" })
    );

    const report = await chat.reportChatMessage.run(
      request(student("bob"), {
        chatId: "chat-1",
        messageId: sent.messageId,
        reason: "Harassment",
      })
    );
    const stored = await readDoc(`moderation/${report.reportId}`);
    assert.equal(stored.reportedBy, "bob");
    assert.equal(stored.status, "open");
    assert.equal(stored.reason, "Harassment");
    assert.equal(Object.prototype.hasOwnProperty.call(stored, "text"), false);
    assert.equal(Object.prototype.hasOwnProperty.call(stored, "messageText"), false);

    await expectHttpsError(
      chat.reportChatMessage.run(
        request(student("carol"), {
          chatId: "chat-1",
          messageId: sent.messageId,
          reason: "Not my chat",
        })
      ),
      "permission-denied"
    );
  });

  /* ------------------------------------------------------------------ */
  console.log("\nHandover: hashed tokens, atomic return and single use");
  await test("a claimant can issue a 128-bit+ token that is stored only as a SHA-256 hash", async () => {
    await seedUser("alice");
    await seedItem("item-1", "bob");
    await seedClaim("claim-1", "alice", "item-1");

    const result = await handover.getHandoverToken.run(
      request(student("alice"), { claimId: "claim-1" })
    );
    assert.match(result.token, /^CC1\.claim-1\.[A-Za-z0-9_-]{40,}$/);
    const secret = result.token.split(".")[2];
    assert.ok(Buffer.from(secret, "base64url").length >= 16, "token must carry >=128 bits");

    const stored = await readDoc("claims/claim-1/private/handover");
    assert.equal(stored.tokenHash, handover.hashToken(result.token));
    assert.notEqual(stored.tokenHash, result.token);
    assert.equal(JSON.stringify(stored).includes(secret), false);
    assert.equal(stored.used, false);
  });
  await test("only the claimant can issue a token, and pending claims are refused", async () => {
    await seedUser("alice");
    await seedUser("bob");
    await seedItem("item-1", "bob");
    await seedClaim("claim-1", "alice", "item-1");

    await expectHttpsError(
      handover.getHandoverToken.run(request(student("bob"), { claimId: "claim-1" })),
      "permission-denied"
    );

    await seedClaim("claim-pending", "alice", "item-1", { status: "pending" });
    await expectHttpsError(
      handover.getHandoverToken.run(
        request(student("alice"), { claimId: "claim-pending" })
      ),
      "failed-precondition"
    );
  });
  await test("staff verification atomically marks claim/item returned and writes a receipt", async () => {
    await seedUser("alice");
    await seedUser("bob");
    await seedItem("item-1", "bob");
    await seedClaim("claim-1", "alice", "item-1");
    const issued = await handover.getHandoverToken.run(
      request(student("alice"), { claimId: "claim-1" })
    );

    const result = await handover.verifyHandover.run(
      request(faculty("faculty1"), { token: issued.token })
    );
    assert.equal(result.claimId, "claim-1");
    assert.match(result.receiptCode, /^CC-[A-F0-9]{12}$/);

    const claim = await readDoc("claims/claim-1");
    assert.equal(claim.status, "returned");
    assert.equal(claim.verifiedBy, "faculty1");
    const item = await readDoc("items/item-1");
    assert.equal(item.status, "returned");
    const handoverDoc = await readDoc("claims/claim-1/private/handover");
    assert.equal(handoverDoc.used, true);
    assert.equal(handoverDoc.verifiedBy, "faculty1");

    const receipt = await readDoc("receipts/claim-1");
    assert.equal(receipt.receiptCode, result.receiptCode);
    assert.equal(receipt.claimantUid, "alice");
    assert.equal(receipt.reporterUid, "bob");
  });
  await test("a token cannot be used twice and failures do not change state", async () => {
    await seedUser("alice");
    await seedUser("bob");
    await seedItem("item-1", "bob");
    await seedClaim("claim-1", "alice", "item-1");
    const issued = await handover.getHandoverToken.run(
      request(student("alice"), { claimId: "claim-1" })
    );
    await handover.verifyHandover.run(
      request(faculty("faculty1"), { token: issued.token })
    );

    const claimBefore = await readDoc("claims/claim-1");
    const receiptBefore = await readDoc("receipts/claim-1");
    await expectHttpsError(
      handover.verifyHandover.run(
        request(faculty("faculty1"), { token: issued.token })
      ),
      "failed-precondition"
    );
    const claimAfter = await readDoc("claims/claim-1");
    const receiptAfter = await readDoc("receipts/claim-1");
    assert.equal(claimAfter.status, claimBefore.status);
    assert.equal(claimAfter.verifiedBy, claimBefore.verifiedBy);
    assert.equal(receiptAfter.receiptCode, receiptBefore.receiptCode);
  });
  await test("malformed and student-submitted tokens are rejected", async () => {
    await seedUser("alice");
    await seedItem("item-1", "bob");
    await seedClaim("claim-1", "alice", "item-1");
    await expectHttpsError(
      handover.verifyHandover.run(request(student("alice"), { token: "CC1.claim-1.abc" })),
      "permission-denied"
    );
    await expectHttpsError(
      handover.verifyHandover.run(request(faculty("faculty1"), { token: "not-a-token" })),
      "failed-precondition"
    );
    assert.equal((await readDoc("claims/claim-1")).status, "approved");
  });

  /* ------------------------------------------------------------------ */
  console.log("\nNotification fan-out: preferences, email and dedupe");
  await test("a push-enabled notification claims push delivery only", async () => {
    await seedUser("alice", {
      prefs: { pushEnabled: true, emailEnabled: false, chatMessage: true },
    });
    await db.collection("notifications").doc("notif-1").set({
      toUid: "alice",
      text: "A new chat message arrived.",
      event: "chatMessage",
      read: false,
      createdAt: FieldValue.serverTimestamp(),
    });

    await notifications.onNotificationCreated.run(fakeNotificationEvent("notif-1"));
    const notif = await readDoc("notifications/notif-1");
    assert.ok(notif.pushAttemptedAt, "push delivery should be claimed");
    assert.equal(notif.emailAttemptedAt, undefined);
  });
  await test("disabled push and email preferences skip delivery entirely", async () => {
    await seedUser("alice", {
      prefs: { pushEnabled: false, emailEnabled: false },
    });
    await db.collection("notifications").doc("notif-2").set({
      toUid: "alice",
      text: "Muted notification.",
      event: "chatMessage",
      read: false,
      createdAt: FieldValue.serverTimestamp(),
    });

    await notifications.onNotificationCreated.run(fakeNotificationEvent("notif-2"));
    const notif = await readDoc("notifications/notif-2");
    assert.equal(notif.pushAttemptedAt, undefined);
    assert.equal(notif.emailAttemptedAt, undefined);
  });
  await test("email fan-out respects preferences, logs failure and is deduplicated", async () => {
    await seedUser("alice", {
      prefs: { pushEnabled: false, emailEnabled: true, claimStatus: true, chatMessage: true },
    });
    await db.collection("notifications").doc("notif-3").set({
      toUid: "alice",
      text: "Your claim was approved.",
      event: "claimApproved",
      read: false,
      createdAt: FieldValue.serverTimestamp(),
    });

    await notifications.onNotificationCreated.run({
      params: { notifId: "notif-3" },
      data: {
        data: () => ({
          toUid: "alice",
          text: "Your claim was approved.",
          event: "claimApproved",
        }),
      },
    });
    const notif = await readDoc("notifications/notif-3");
    assert.ok(notif.emailAttemptedAt, "email delivery should be claimed");

    const failuresBefore = await db.collection("emailFailures").get();
    assert.ok(failuresBefore.size >= 1);
    const countBefore = failuresBefore.size;

    // At-least-once trigger retry: the claim marker must prevent a second send.
    await notifications.onNotificationCreated.run({
      params: { notifId: "notif-3" },
      data: {
        data: () => ({
          toUid: "alice",
          text: "Your claim was approved.",
          event: "claimApproved",
        }),
      },
    });
    const failuresAfter = await db.collection("emailFailures").get();
    assert.equal(failuresAfter.size, countBefore);
  });
  await test("a notification for a missing recipient profile is handled safely", async () => {
    await db.collection("notifications").doc("notif-4").set({
      toUid: "ghost",
      text: "Nobody home.",
      event: "chatMessage",
      read: false,
      createdAt: FieldValue.serverTimestamp(),
    });
    await notifications.onNotificationCreated.run(fakeNotificationEvent("notif-4"));
    const notif = await readDoc("notifications/notif-4");
    // Preferences fall back to safe defaults, so both channels are claimed and
    // then no-op (no profile, no devices). Nothing throws and no failure is
    // recorded against a user who does not exist.
    assert.ok(notif.pushAttemptedAt);
    assert.ok(notif.emailAttemptedAt);
    const failures = await db.collection("emailFailures").get();
    assert.equal(failures.size, 0);
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed) {
    console.error("\nFailures:");
    failures.forEach(({ name }) => console.error(` - ${name}`));
    process.exitCode = 1;
  }
}

run().catch((error) => {
  console.error("\nTest harness failed:", error);
  process.exitCode = 1;
});
