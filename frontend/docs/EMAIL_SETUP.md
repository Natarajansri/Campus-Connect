# Transactional email setup

Campus Connect sends notification and digest email through **Resend** using a
server-side `fetch` call from Cloud Functions. There is no client-side email
provider key and no SMTP credential in the repository.

The implementation lives in [`functions/email.js`](../functions/email.js); the
fan-out trigger is in [`functions/notifications.js`](../functions/notifications.js)
and the scheduled digest/reminder jobs are in
[`functions/scheduler.js`](../functions/scheduler.js).

---

## 1. What is sent

| Event | Trigger | Template |
| --- | --- | --- |
| `claimReceived` | Claim created | claim received |
| `claimApproved` / `claimRejected` | Staff resolves a claim | claim status |
| `claimReturned` / `returnedReceipt` | QR handover verified | return confirmation + receipt |
| `readyForPickup` | Custody item ready | pickup instructions |
| `custodyUpdate` | Custody details changed | custody update |
| `broadcast` | Admin publishes a notice | campus notice |
| `matchFound` | Possible match | match notice |
| `weeklyDigest` | Scheduled Monday digest | weekly digest |

Messages contain only the notification text and an internal link. They never
include another member's email address, phone number, reporter contact details
or claim ownership proof.

Both the HTML and plain-text bodies are generated from the same notification.
Every interpolated value is escaped; links are restricted to same-origin paths.

---

## 2. Required configuration

| Variable | Required | Where | Notes |
| --- | --- | --- | --- |
| `RESEND_API_KEY` | Production | Secret Manager | Resend API key. Reads `process.env` at runtime. |
| `EMAIL_UNSUB_SECRET` | Production | Secret Manager | HMAC key for signed unsubscribe links. **Minimum 16 characters**; use 32+ random bytes. |
| `EMAIL_FROM` | Production | `functions/.env.<project>` | Verified Resend sender, e.g. `Campus Connect <no-reply@campus.edu>`. |
| `PUBLIC_BASE_URL` | Optional | `functions/.env.<project>` | Hosting origin used in links. Defaults to `https://<project>.web.app`. |
| `FUNCTIONS_BASE_URL` | Optional | `functions/.env.<project>` | Overrides the unsubscribe endpoint origin. |
| `EMAIL_DAILY_CAP` | Optional | `functions/.env.<project>` | Per-user email cap per UTC day. Default **15**. |
| `ALLOWED_EMAIL_DOMAINS` | Optional | `functions/.env.<project>` | Comma-separated college domains. Default `campus.edu`. |

`RESEND_API_KEY` and `EMAIL_UNSUB_SECRET` are declared with `defineSecret` in
`functions/email.js`, so the Functions emulator and deployment know they are
secrets. `EMAIL_FROM` is not sensitive and is supplied as a normal environment
variable.

Generate the HMAC secret locally:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

Never commit real values. `.gitignore` already excludes `.env`, `.env.*` and
`.secret.local`.

---

## 3. Configure secrets (production)

```bash
firebase login
firebase use campusconnect-bc130

firebase functions:secrets:set RESEND_API_KEY
# paste the Resend key when prompted

firebase functions:secrets:set EMAIL_UNSUB_SECRET
# paste the generated HMAC secret when prompted
```

Firebase stores both in Google Secret Manager and injects them into
`process.env` for the functions that declare them. On the first deploy that
binds a secret, Firebase asks you to grant the Cloud Functions service account
access to that secret — accept it.

Create `functions/.env.campusconnect-bc130` for the non-secret values:

```dotenv
EMAIL_FROM=Campus Connect <no-reply@campus.edu>
PUBLIC_BASE_URL=https://campusconnect-bc130.web.app
# EMAIL_DAILY_CAP=15
# ALLOWED_EMAIL_DOMAINS=campus.edu
```

Then deploy functions (and hosting if links changed):

```bash
npm --prefix functions install
firebase deploy --only functions,hosting
```

Rotate a key with the same `functions:secrets:set` command followed by a deploy.
Old unsubscribe links remain valid only until `EMAIL_UNSUB_SECRET` is rotated;
after rotation every previously issued unsubscribe link stops working.

---

## 4. Local emulator setup

For local work, create `functions/.secret.local` (v2 params) and/or
`functions/.env` with test-only values:

```dotenv
RESEND_API_KEY=re_test_only_not_a_real_key
EMAIL_FROM=Campus Connect <no-reply@campus.edu>
EMAIL_UNSUB_SECRET=local-only-unsubscribe-secret-32chars
PUBLIC_BASE_URL=http://localhost:5000
```

```bash
npm run serve
```

- `npm run test:functions` sets `FUNCTIONS_EMULATOR=true` and a test
  `EMAIL_UNSUB_SECRET` itself, and deliberately leaves the Resend key unset. The
  suite asserts that a missing provider key is logged and never throws.
- Do **not** use a production Resend key in the emulator. If a real key is
  present, the digest and notification tests could send real mail.
- The App Check requirement on new callables is skipped only when
  `FUNCTIONS_EMULATOR=true`; production always enforces it.

---

## 5. Resend account setup

1. Create a Resend account and add the sending domain (for example
   `campus.edu` or a dedicated `notifications.campus.edu`).
2. Add the DNS records Resend shows (SPF, DKIM, and optionally DMARC).
3. Wait for domain verification, then use an address on that domain in
   `EMAIL_FROM`.
4. For a subdomain, set `EMAIL_FROM` to an address on the verified subdomain.
5. Keep the Resend API key restricted to sending only; do not reuse a full-access
   account key.

The free tier is sufficient for local/test volume. Check the Resend dashboard for
bounces and complaints; the Cloud Function records provider failures under the
server-only `emailFailures` collection.

---

## 6. Unsubscribe endpoint

`sendNotificationEmail` and the digest jobs append a signed, expiring
unsubscribe link:

```text
https://us-central1-<project>.cloudfunctions.net/emailUnsubscribe?token=<token>
```

Token properties:

- `base64url(payload).base64url(HMAC-SHA256(payload))`;
- payload contains only `uid`, `exp` and `purpose: "email-unsubscribe"`;
- default lifetime is **30 days**;
- signature comparison is constant-time and malformed/tampered/expired tokens
  are rejected.

Opening a valid link:

1. verifies the signature and expiry;
2. loads the user profile;
3. sets `prefs.emailEnabled = false` and `prefs.weeklyDigest = false`;
4. writes an `email.unsubscribed` audit entry;
5. serves a small confirmation page with no user data.

The endpoint is intentionally public (no session required) because it is opened
from a mail client. Possession of a valid signed token is the authorization.

---

## 7. Preferences, caps and failure handling

The recipient's `users/{uid}.prefs` map is authoritative:

- `emailEnabled` disables all non-security email;
- `claimStatus`, `matchFound`, `chatMessage`, `custodyUpdate`, `broadcast` and
  `weeklyDigest` control individual categories;
- unknown or non-boolean values fall back to safe defaults;
- security notices are not silently disabled by a malformed preference map.

Protection against loops and abuse:

- the notification trigger claims delivery with `emailAttemptedAt` so an
  at-least-once retry cannot send twice;
- `consumeEmailQuota` enforces `EMAIL_DAILY_CAP` per user per UTC day;
- the weekly digest considers at most 1,000 users and sends in small batches;
- stale-claim reminders consider at most 200 claims per run;
- failed sends are captured in server-only `emailFailures` with a reason
  (`provider-not-configured`, `provider-timeout`, `provider-4xx`, …).

No email failure is allowed to fail the user action that triggered it.

---

## 8. Verification

```bash
npm run lint
npm run test:functions
```

The Functions suite covers:

- HTML escaping and plain-text fallback;
- unknown event handling;
- signed-token round-trip, tampering, malformed input and expiry;
- preference opt-out and per-event opt-out;
- missing recipient profile;
- missing provider key logging;
- notification fan-out dedupe and email claim marker.

For a live check, use a disposable account and a test notification. Confirm the
message arrives, the link opens `/index.html?view=dashboard`, and the unsubscribe
link disables email in Dashboard → Notification Settings.

---

## 9. Troubleshooting

| Symptom | Cause / fix |
| --- | --- |
| `provider-not-configured` in `emailFailures` | `RESEND_API_KEY` or `EMAIL_FROM` missing for the deployed function. Re-run the secret/env setup and redeploy. |
| Resend returns `403` / domain error | Sender domain is not verified in Resend, or `EMAIL_FROM` uses a different domain. |
| No digest on Monday | `prefs.weeklyDigest` is false, the user is suspended, or the scheduler has not run yet (timezone is `Etc/UTC`). |
| Unsubscribe link returns “invalid or expired” | Token older than 30 days, `EMAIL_UNSUB_SECRET` was rotated, or the link was truncated by the mail client. |
| Duplicate emails | Check `emailAttemptedAt` on the notification; a manual resend bypasses the trigger's dedupe. |
| Emulator tries to send real mail | Remove the real `RESEND_API_KEY` from `functions/.env` / `.secret.local`; tests expect it to be absent. |

---

## 10. Why Resend instead of the Trigger Email extension

- No extension-managed Firestore queue to monitor or secure separately.
- The provider key stays in Secret Manager and never reaches the browser.
- Delivery happens in the same trigger that owns notification preferences and
  per-user caps, so opt-outs and dedupe cannot be bypassed.
- Failure reasons are recorded in a server-only collection that admins can audit.
