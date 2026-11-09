"use strict";

/**
 * Transactional email for Campus Connect.
 *
 * Provider: Resend (https://resend.com) over the REST API. Credentials come
 * from Secret Manager / environment variables, never from the repository:
 *   RESEND_API_KEY       — required in production
 *   EMAIL_FROM           — e.g. "Campus Connect <no-reply@campus.edu>"
 *   EMAIL_UNSUB_SECRET   — HMAC key for signed, expiring unsubscribe links
 *   PUBLIC_BASE_URL      — optional, defaults to the Hosting project URL
 *   FUNCTIONS_BASE_URL   — optional, overrides the unsubscribe endpoint origin
 *
 * Privacy: messages contain only the notification text and an internal link.
 * They never include reporter contact details, claim proofs or another user's
 * email address.
 */

const crypto = require("node:crypto");
const { onRequest } = require("firebase-functions/v2/https");
const { defineSecret } = require("firebase-functions/params");

const {
  db,
  FieldValue,
  clampString,
  normalizeEmail,
  consumeEmailQuota,
  logEmailFailure,
  getUserProfile,
  normalizePrefs,
  prefEnabled,
  EMAIL_EVENTS,
  writeAudit,
} = require("./helpers");

const UNSUB_TTL_DAYS = 30;
const MAX_EMAIL_TEXT = 2000;

// Production secrets. Firebase injects declared secrets into process.env at
// runtime; the emulator falls back to functions/.env (or the test environment)
// so tests never touch Secret Manager.
const RESEND_API_KEY_SECRET = defineSecret("RESEND_API_KEY");
const EMAIL_UNSUB_SECRET_SECRET = defineSecret("EMAIL_UNSUB_SECRET");
const EMAIL_SECRETS = [RESEND_API_KEY_SECRET, EMAIL_UNSUB_SECRET_SECRET];

const SUBJECTS = Object.freeze({
  claimReceived: "Claim received — Campus Connect",
  claimApproved: "Claim approved — Campus Connect",
  claimRejected: "Claim update — Campus Connect",
  claimReturned: "Item returned — Campus Connect",
  readyForPickup: "Ready for pickup — Campus Connect",
  returnedReceipt: "Your return receipt — Campus Connect",
  custodyUpdate: "Custody update — Campus Connect",
  broadcast: "Campus notice — Campus Connect",
  matchFound: "Possible match found — Campus Connect",
  weeklyDigest: "Your weekly Campus Connect digest",
});

const HTML_ESCAPES = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function escapeHtml(value) {
  return String(value === null || value === undefined ? "" : value).replace(
    /[&<>"']/g,
    (char) => HTML_ESCAPES[char]
  );
}

function projectId() {
  return process.env.GCLOUD_PROJECT || "campusconnect-bc130";
}

function publicBaseUrl() {
  const configured = String(process.env.PUBLIC_BASE_URL || "").trim();
  if (configured) return configured.replace(/\/+$/, "");
  return `https://${projectId()}.web.app`;
}

function functionsBaseUrl() {
  const configured = String(process.env.FUNCTIONS_BASE_URL || "").trim();
  if (configured) return configured.replace(/\/+$/, "");
  if (process.env.FUNCTIONS_EMULATOR === "true") {
    return `http://localhost:5001/${projectId()}/us-central1`;
  }
  return `https://us-central1-${projectId()}.cloudfunctions.net`;
}

function unsubscribeSecret() {
  const secret = process.env.EMAIL_UNSUB_SECRET;
  return typeof secret === "string" && secret.length >= 16 ? secret : null;
}

/** Signed, expiring token: base64url(payload).base64url(HMAC-SHA256). */
function createUnsubscribeToken(uid, ttlDays = UNSUB_TTL_DAYS) {
  const secret = unsubscribeSecret();
  if (!secret) throw new Error("EMAIL_UNSUB_SECRET is not configured.");
  const safeUid = clampString(uid, 128);
  if (!safeUid) throw new Error("A user id is required.");
  const payload = Buffer.from(
    JSON.stringify({
      uid: safeUid,
      exp: Math.floor(Date.now() / 1000) + Math.max(1, ttlDays) * 86400,
      purpose: "email-unsubscribe",
    })
  ).toString("base64url");
  const signature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");
  return `${payload}.${signature}`;
}

function verifyUnsubscribeToken(token) {
  const secret = unsubscribeSecret();
  if (!secret || typeof token !== "string" || token.length > 2048) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payload, signature] = parts;
  const expected = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");
  const providedBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (
    providedBuffer.length !== expectedBuffer.length ||
    !crypto.timingSafeEqual(providedBuffer, expectedBuffer)
  ) {
    return null;
  }
  try {
    const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    if (!parsed || parsed.purpose !== "email-unsubscribe") return null;
    if (typeof parsed.uid !== "string" || !parsed.uid) return null;
    if (!Number.isFinite(parsed.exp) || parsed.exp * 1000 <= Date.now()) return null;
    return { uid: parsed.uid };
  } catch (error) {
    return null;
  }
}

function unsubscribeUrl(uid) {
  try {
    const token = createUnsubscribeToken(uid);
    return `${functionsBaseUrl()}/emailUnsubscribe?token=${encodeURIComponent(token)}`;
  } catch (error) {
    return null;
  }
}

function safeInternalUrl(url) {
  const value = String(url || "").trim();
  if (!value.startsWith("/") || value.startsWith("//")) {
    return "/index.html?view=dashboard";
  }
  return value;
}

function absoluteUrl(url) {
  return `${publicBaseUrl()}${safeInternalUrl(url)}`;
}

/**
 * Renders a single notification email. All remote text is escaped; the URL is
 * restricted to a same-origin path before being embedded.
 */
function renderEmail({ event, text, url, unsubscribe }) {
  const subject = SUBJECTS[event] || "Campus Connect notification";
  const body = clampString(text, MAX_EMAIL_TEXT).trim() || "You have a new update.";
  const actionUrl = absoluteUrl(url);
  const footer = unsubscribe
    ? `<p style="font-size:12px;color:#6b6257;line-height:1.5">You can <a href="${escapeHtml(
        unsubscribe
      )}" style="color:#8B6F47">unsubscribe from email notifications</a> at any time.</p>`
    : "";
  const html = `<!DOCTYPE html>
<html lang="en"><body style="margin:0;background:#FAF7F0;padding:24px">
<div style="font-family:Arial,Helvetica,sans-serif;max-width:560px;margin:0 auto;background:#ffffff;border:1px solid #E6DECF;border-radius:8px;padding:24px;color:#2B2620">
  <p style="font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#8B6F47;margin:0 0 8px">Campus Connect</p>
  <h1 style="font-size:22px;line-height:1.3;margin:0 0 16px">${escapeHtml(subject)}</h1>
  <p style="font-size:15px;line-height:1.6;margin:0 0 20px">${escapeHtml(body).replace(
    /\n/g,
    "<br>"
  )}</p>
  <p style="margin:0 0 24px"><a href="${escapeHtml(
    actionUrl
  )}" style="display:inline-block;background:#8B6F47;color:#ffffff;text-decoration:none;padding:11px 18px;border-radius:4px;font-weight:bold">Open Campus Connect</a></p>
  <hr style="border:none;border-top:1px solid #E6DECF;margin:0 0 14px">
  <p style="font-size:12px;color:#6b6257;line-height:1.5;margin:0">This message was sent because you have a Campus Connect account. It never contains another member's private contact details or ownership proof.</p>
  ${footer}
</div>
</body></html>`;
  const plain = [
    "Campus Connect",
    "",
    subject,
    "",
    body,
    "",
    `Open: ${actionUrl}`,
    unsubscribe ? `Unsubscribe: ${unsubscribe}` : "",
    "",
    "This message never contains another member's private contact details or ownership proof.",
  ]
    .filter(Boolean)
    .join("\n");
  return { subject, html, text: plain };
}

/**
 * Sends one email through Resend. Returns { sent, skipped?, reason? } and never
 * throws to the caller: notification delivery must not fail user actions.
 */
async function sendEmail({ uid, event, to, subject, html, text, unsubscribe }) {
  const apiKey = String(process.env.RESEND_API_KEY || "").trim();
  const from = String(process.env.EMAIL_FROM || "").trim();
  const normalizedTo = normalizeEmail(to);
  const safeEvent = clampString(event || "unknown", 40);

  if (!normalizedTo || !normalizedTo.includes("@")) {
    await logEmailFailure({ uid, event: safeEvent, reason: "missing-recipient" });
    return { sent: false, reason: "missing-recipient" };
  }
  if (!apiKey || !from) {
    await logEmailFailure({
      uid,
      event: safeEvent,
      reason: "provider-not-configured",
    });
    console.warn("Email skipped: RESEND_API_KEY or EMAIL_FROM is not configured.");
    return { sent: false, reason: "provider-not-configured" };
  }

  const quota = await consumeEmailQuota(uid);
  if (!quota.allowed) {
    await logEmailFailure({ uid, event: safeEvent, reason: "daily-cap-reached" });
    return { sent: false, reason: "daily-cap-reached" };
  }

  const headers = {};
  if (unsubscribe) {
    headers["List-Unsubscribe"] = `<${unsubscribe}>`;
    headers["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click";
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      signal: controller.signal,
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        from,
        to: [normalizedTo],
        subject: clampString(subject, 160),
        html,
        text,
        headers,
      }),
    });
    if (!response.ok) {
      const detail = clampString(await response.text().catch(() => ""), 300);
      await logEmailFailure({
        uid,
        event: safeEvent,
        reason: `provider-${response.status}: ${detail}`,
      });
      return { sent: false, reason: `provider-${response.status}` };
    }
    const result = await response.json().catch(() => ({}));
    return { sent: true, id: result && result.id ? String(result.id).slice(0, 120) : null };
  } catch (error) {
    await logEmailFailure({
      uid,
      event: safeEvent,
      reason: error && error.name === "AbortError" ? "provider-timeout" : "provider-error",
    });
    return { sent: false, reason: "provider-error" };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Sends email for a notification document when the recipient opted in.
 * Called from the notification fan-out trigger.
 */
async function sendNotificationEmail({ uid, event, text, url }) {
  const safeEvent = clampString(event || "unknown", 40);
  if (!EMAIL_EVENTS.includes(safeEvent)) return { sent: false, reason: "no-template" };

  const profile = await getUserProfile(uid).catch(() => null);
  if (!profile) return { sent: false, reason: "no-profile" };
  if (String(profile.status || "Active") === "Suspended") {
    return { sent: false, reason: "suspended" };
  }
  const prefs = normalizePrefs(profile.prefs);
  if (!prefEnabled(prefs, safeEvent, "email")) {
    return { sent: false, reason: "preference-disabled" };
  }

  const email = normalizeEmail(profile.email);
  if (!email) return { sent: false, reason: "no-email" };

  const unsubscribe = unsubscribeUrl(uid);
  const rendered = renderEmail({
    event: safeEvent,
    text,
    url,
    unsubscribe,
  });
  return sendEmail({
    uid,
    event: safeEvent,
    to: email,
    subject: rendered.subject,
    html: rendered.html,
    text: rendered.text,
    unsubscribe,
  });
}

function unsubscribePage({ ok, message }) {
  const title = ok ? "Email notifications turned off" : "Unsubscribe link not valid";
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)} — Campus Connect</title></head>
<body style="margin:0;background:#FAF7F0;font-family:Arial,Helvetica,sans-serif;color:#2B2620">
<main style="max-width:520px;margin:10vh auto;background:#fff;border:1px solid #E6DECF;border-radius:8px;padding:28px">
<p style="font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:#8B6F47;margin:0 0 8px">Campus Connect</p>
<h1 style="font-size:24px;margin:0 0 12px">${escapeHtml(title)}</h1>
<p style="font-size:15px;line-height:1.6;margin:0 0 20px">${escapeHtml(message)}</p>
<a href="${escapeHtml(publicBaseUrl())}/index.html" style="display:inline-block;background:#8B6F47;color:#fff;text-decoration:none;padding:11px 18px;border-radius:4px;font-weight:bold">Return to Campus Connect</a>
</main>
</body></html>`;
}

/**
 * Public unsubscribe endpoint. The token is signed and expiring, so the link
 * works without a session while still preventing anyone from disabling another
 * member's email by guessing a UID.
 */
exports.emailUnsubscribe = onRequest({ cors: false, secrets: EMAIL_SECRETS }, async (request, response) => {
  const token = request.query && typeof request.query.token === "string"
    ? request.query.token
    : "";
  const verified = verifyUnsubscribeToken(token);
  if (!verified) {
    response
      .status(400)
      .set("Cache-Control", "no-store")
      .send(
        unsubscribePage({
          ok: false,
          message:
            "This link is invalid or has expired. Sign in to Campus Connect and update your notification settings instead.",
        })
      );
    return;
  }

  const profile = await getUserProfile(verified.uid).catch(() => null);
  if (!profile) {
    response
      .status(404)
      .set("Cache-Control", "no-store")
      .send(
        unsubscribePage({
          ok: false,
          message: "This account no longer exists.",
        })
      );
    return;
  }

  const prefs = normalizePrefs(profile.prefs);
  prefs.emailEnabled = false;
  prefs.weeklyDigest = false;

  await db.collection("users").doc(verified.uid).set(
    {
      prefs,
      updatedAt: FieldValue.serverTimestamp(),
      updatedBy: verified.uid,
    },
    { merge: true }
  );

  await writeAudit({
    actorUid: verified.uid,
    actorRole: "system",
    action: "email.unsubscribed",
    targetType: "user",
    targetId: verified.uid,
    details: "Email notifications disabled through a signed unsubscribe link",
  });

  response
    .status(200)
    .set("Cache-Control", "no-store")
    .send(
      unsubscribePage({
        ok: true,
        message:
          "You will no longer receive notification or digest emails. You can re-enable email in Dashboard → Notification Settings. Security notices still appear in the app.",
      })
    );
});

exports.sendNotificationEmail = sendNotificationEmail;
exports.sendEmail = sendEmail;
exports.renderEmail = renderEmail;
exports.createUnsubscribeToken = createUnsubscribeToken;
exports.verifyUnsubscribeToken = verifyUnsubscribeToken;
exports.escapeHtml = escapeHtml;
exports.SUBJECTS = SUBJECTS;
exports.EMAIL_SECRETS = EMAIL_SECRETS;
