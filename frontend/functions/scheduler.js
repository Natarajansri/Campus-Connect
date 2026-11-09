"use strict";

/**
 * Scheduled email/reminder jobs.
 *
 * Both jobs are bounded per run and process recipients in small batches so a
 * single run cannot exhaust Firestore, Resend or the 9-minute function limit.
 */

const { onSchedule } = require("firebase-functions/v2/scheduler");

const {
  admin,
  db,
  clampString,
  normalizePrefs,
  prefEnabled,
  queueNotification,
  writeAudit,
} = require("./helpers");
const { sendEmail, escapeHtml, createUnsubscribeToken, EMAIL_SECRETS } = require("./email");

const DIGEST_USER_CAP = 1000;
const DIGEST_PAGE = 200;
const DIGEST_BATCH = 10;
const DIGEST_ITEM_LIMIT = 8;

const REMINDER_CAP = 200;
const REMINDER_BATCH = 20;
const REMINDER_AGE_MS = 30 * 24 * 60 * 60 * 1000;

function projectBaseUrl() {
  const configured = String(process.env.PUBLIC_BASE_URL || "").trim();
  if (configured) return configured.replace(/\/+$/, "");
  return `https://${process.env.GCLOUD_PROJECT || "campusconnect-bc130"}.web.app`;
}

function unsubscribeUrl(uid) {
  const functionsBase = process.env.FUNCTIONS_EMULATOR === "true"
    ? `http://localhost:5001/${process.env.GCLOUD_PROJECT || "demo-campusconnect"}/us-central1`
    : `https://us-central1-${process.env.GCLOUD_PROJECT || "campusconnect-bc130"}.cloudfunctions.net`;
  try {
    // Required lazily so a missing secret never crashes the scheduler.
    return `${functionsBase}/emailUnsubscribe?token=${encodeURIComponent(
      createUnsubscribeToken(uid)
    )}`;
  } catch (error) {
    return null;
  }
}

function buildDigestHtml(items, unsubscribe) {
  const list = items.length
    ? items
        .map(
          (item) =>
            `<li style="margin:0 0 10px"><strong>${escapeHtml(
              clampString(item.title, 100)
            )}</strong> — ${escapeHtml(clampString(item.category, 80))}, ${escapeHtml(
              clampString(item.location, 160)
            )}</li>`
        )
        .join("")
    : "<li>No new approved items this week.</li>";

  return `<!DOCTYPE html>
<html lang="en"><body style="margin:0;background:#FAF7F0;padding:24px">
<div style="font-family:Arial,Helvetica,sans-serif;max-width:560px;margin:0 auto;background:#fff;border:1px solid #E6DECF;border-radius:8px;padding:24px;color:#2B2620">
  <p style="font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#8B6F47;margin:0 0 8px">Campus Connect</p>
  <h1 style="font-size:22px;margin:0 0 16px">Your weekly lost &amp; found digest</h1>
  <p style="font-size:15px;line-height:1.6;margin:0 0 16px">Recently approved items on the campus board:</p>
  <ul style="font-size:14px;line-height:1.6;padding-left:20px;margin:0 0 22px">${list}</ul>
  <p style="margin:0 0 24px"><a href="${escapeHtml(
    projectBaseUrl()
  )}/index.html" style="display:inline-block;background:#8B6F47;color:#fff;text-decoration:none;padding:11px 18px;border-radius:4px;font-weight:bold">Open the board</a></p>
  <p style="font-size:12px;color:#6b6257;line-height:1.5;margin:0">You are receiving this because you enabled the weekly digest.${
    unsubscribe
      ? ` <a href="${escapeHtml(
          unsubscribe
        )}" style="color:#8B6F47">Unsubscribe from emails</a>.`
      : ""
  }</p>
</div>
</body></html>`;
}

function buildDigestText(items) {
  const lines = items.length
    ? items.map((item) => `- ${clampString(item.title, 100)} (${clampString(item.location, 160)})`)
    : ["- No new approved items this week."];
  return [
    "Campus Connect — weekly digest",
    "",
    "Recently approved items:",
    ...lines,
    "",
    `${projectBaseUrl()}/index.html`,
  ].join("\n");
}

exports.weeklyDigest = onSchedule(
  {
    schedule: "every monday 08:00",
    timeZone: "Etc/UTC",
    retryCount: 1,
    secrets: EMAIL_SECRETS,
  },
  async () => {
    const itemsSnap = await db
      .collection("items")
      .where("status", "==", "approved")
      .orderBy("createdAt", "desc")
      .limit(DIGEST_ITEM_LIMIT)
      .get()
      .catch(() => null);
    const items = itemsSnap ? itemsSnap.docs.map((doc) => doc.data()) : [];

    let lastDoc = null;
    let processed = 0;
    let sent = 0;
    let skipped = 0;

    while (processed < DIGEST_USER_CAP) {
      let query = db
        .collection("users")
        .where("prefs.weeklyDigest", "==", true)
        .limit(Math.min(DIGEST_PAGE, DIGEST_USER_CAP - processed));
      if (lastDoc) query = query.startAfter(lastDoc);

      const page = await query.get();
      if (page.empty) break;

      for (let index = 0; index < page.docs.length; index += DIGEST_BATCH) {
        const chunk = page.docs.slice(index, index + DIGEST_BATCH);
        const results = await Promise.allSettled(
          chunk.map(async (doc) => {
            const profile = doc.data() || {};
            if (String(profile.status || "Active") === "Suspended") return false;
            const prefs = normalizePrefs(profile.prefs);
            if (!prefEnabled(prefs, "weeklyDigest", "email")) return false;
            const email = String(profile.email || "").trim().toLowerCase();
            if (!email) return false;

            const unsubscribe = unsubscribeUrl(doc.id);
            const result = await sendEmail({
              uid: doc.id,
              event: "weeklyDigest",
              to: email,
              subject: "Your weekly Campus Connect digest",
              html: buildDigestHtml(items, unsubscribe),
              text: buildDigestText(items),
              unsubscribe,
            });
            return Boolean(result && result.sent);
          })
        );
        results.forEach((entry) => {
          if (entry.status === "fulfilled" && entry.value) sent += 1;
          else skipped += 1;
        });
      }

      processed += page.docs.length;
      lastDoc = page.docs[page.docs.length - 1];
      if (page.docs.length < DIGEST_PAGE) break;
    }

    await writeAudit({
      actorUid: "system",
      actorRole: "system",
      action: "email.weekly_digest",
      targetType: "audience",
      targetId: "weeklyDigest",
      details: `Digest run: ${sent} sent, ${skipped} skipped, ${processed} considered`,
    });

    return { processed, sent, skipped };
  }
);

exports.staleClaimReminders = onSchedule(
  {
    schedule: "every day 09:00",
    timeZone: "Etc/UTC",
    retryCount: 1,
    secrets: EMAIL_SECRETS,
  },
  async () => {
    const cutoff = admin.firestore.Timestamp.fromMillis(Date.now() - REMINDER_AGE_MS);
    let reminders = 0;
    let considered = 0;

    for (const status of ["pending", "approved"]) {
      const snap = await db
        .collection("claims")
        .where("status", "==", status)
        .limit(REMINDER_CAP)
        .get()
        .catch(() => null);
      if (!snap) continue;

      const stale = snap.docs.filter((doc) => {
        const createdAt = doc.data().createdAt;
        return createdAt && typeof createdAt.toMillis === "function" && createdAt.toMillis() <= cutoff.toMillis();
      });
      considered += stale.length;

      for (let index = 0; index < stale.length; index += REMINDER_BATCH) {
        const chunk = stale.slice(index, index + REMINDER_BATCH);
        await Promise.allSettled(
          chunk.map(async (doc) => {
            const claim = doc.data() || {};
            if (!claim.claimantUid) return false;
            const itemTitle = clampString(claim.itemTitle || "your item", 80);
            const event = status === "approved" ? "readyForPickup" : "claimReceived";
            const text = status === "approved"
              ? `Your claim for "${itemTitle}" has been approved for over 30 days. Contact the item reporter to arrange pickup.`
              : `Your claim for "${itemTitle}" has been pending for over 30 days. Campus staff can help if it is urgent.`;
            await queueNotification({
              toUid: claim.claimantUid,
              text,
              event,
              url: "/index.html?view=dashboard",
              dedupeKey: `claim_reminder30_${doc.id}`,
            });
            return true;
          })
        );
        reminders += chunk.length;
      }
    }

    await writeAudit({
      actorUid: "system",
      actorRole: "system",
      action: "claim.stale_reminder",
      targetType: "audience",
      targetId: "staleClaims",
      details: `Sent ${reminders} reminder(s) for ${considered} stale claim(s)`,
    });

    return { considered, reminders };
  }
);
