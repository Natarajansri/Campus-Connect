# Campus Connect — Security Hardening Report (Phases 1–7)

**Project:** Campus Connect Lost & Found
**Firebase project:** `campusconnect-bc130`
**Deploy root:** `public/`
**Test project:** `demo-campusconnect` (Emulator Suite only)
**Last verified:** 2026-11-05

This document is the per-phase record requested for the hardening work. It
lists what changed, what was removed, how to verify it and what risk remains.
Details live in [`SECURITY.md`](../SECURITY.md),
[`docs/SECURITY_TEST_PLAN.md`](SECURITY_TEST_PLAN.md) and
[`docs/XSS_AUDIT.md`](XSS_AUDIT.md).

---

## Phase 1 — Hosting, deploy layout and configuration

### Summary

- Introduced `public/` as the single Hosting deploy root so only intended assets
  are published.
- Extracted the original inline `<style>` and app `<script>` blocks into
  `public/assets/css/` and `public/assets/js/`. This makes CSP `script-src
  'self'` effective against injected `<script>` tags.
- Rebuilt `public/index.html` and `public/login.html` as static shells that load
  the Firebase compat SDK, `firebase-config.js`, `firebase-service.js` and the
  page script.
- Added `firebase.json` with Hosting root, clean URLs, CSP and security headers,
  rules/functions wiring and emulator ports.
- Kept the existing Firebase compat/namespaced SDK (no build step) as required.
- No demo credentials, no client-side account provisioning and no hardcoded
  service-account keys.

### Files

**Created**

- `public/index.html`, `public/login.html`
- `public/assets/css/styles.css`, `public/assets/css/login.css`
- `public/assets/js/app.js`, `public/assets/js/login.js`
- `public/firebase-config.js`, `public/firebase-service.js`
- `firebase.json`, `package.json`, `.gitignore`

**Modified**

- `.firebaserc` default project retained/confirmed as `campusconnect-bc130`.
- `firestore.indexes.json` retained as the index definition source.

**Deleted (Phase 7 cleanup)**

- Root legacy copies `index.html`, `login.html`, `firebase-config.js`,
  `firebase-service.js` — superseded by `public/` and not referenced by
  `firebase.json`.
- Temporary extraction helpers `scripts/_extract-assets.js`,
  `scripts/_patch-app.js` (removed after the assets were extracted).

### Manual steps

1. `firebase login` and confirm `firebase projects:list` shows
   `campusconnect-bc130`.
2. Set the Web API key restrictions in Google Cloud Console (HTTP referrer +
   only Auth/Firestore/Storage/Identity Toolkit APIs).
3. Add the production Hosting domains to Firebase Auth → Authorized domains.
4. Run `npm run serve` and confirm `http://localhost:5000/index.html` and
   `login.html` load with no console errors.
5. In DevTools → Network, confirm the CSP/HSTS/`nosniff` headers are present
   (they are only injected by Hosting, so use `firebase serve` / emulator
   Hosting, not a raw file open).

### Remaining risks

- The Web API key is public by design; security depends on the console
  restrictions above.
- Hosting headers do not apply when the HTML is opened from the filesystem;
  always test through Hosting/emulators.

---

## Phase 2 — Authoritative data model and migration

### Summary

- Made `reporterUid` (items) and `claimantUid` (claims) the ownership fields.
  Legacy `ownerUid`/`userId`/`uid` values are mapped during migration.
- Moved sensitive data out of public documents:
  - reporter contact → `items/{itemId}/private/contact`
  - claim proof/contact → `claims/{claimId}/private/proof`
- Standardised lowercase item/claim statuses (`pending`, `approved`,
  `claimed`, `returned`, `rejected`) and complaint statuses (`Under Review`,
  `Investigating`, `Resolved`).
- Standardised server timestamps and retained original values as
  `legacyCreatedAt` / `legacyUpdatedAt` / `legacyStatus`.
- Complaints moved from `localStorage` to Firestore.
- Category list and campus broadcast moved to `metadata/categories` and
  `metadata/broadcast`.
- Client-created documents use auto-IDs; posting/reading still tolerates legacy
  IDs.
- Wrote `scripts/migrate-ids.js`:
  - dry-run by default,
  - normalises fields/statuses in place,
  - writes a replacement document before deleting a legacy-ID document,
  - only deletes old documents with `--delete-old`,
  - preserves unknown fields and excludes contact/proof from the public parent.

### Files

**Created**

- `scripts/migrate-ids.js`
- `scripts/backfill-claims.js`
- Data-model section in `README.md`

**Modified**

- `public/firebase-service.js` (auto-ID create paths, private subcollections,
  server timestamps, complaints in Firestore, category/broadcast helpers)
- `public/assets/js/app.js` (UID ownership, status normalisation, private
  contact/proof reads)

**Deleted**

- `localStorage`-backed complaint/category/broadcast storage paths in the
  frontend (replaced by Firestore; no user-facing feature was removed).

### Manual steps

1. **Back up Firestore and Storage** before any migration.
2. Run a dry run against production with ADC:
   `node scripts/migrate-ids.js`
3. Review warnings (missing `reporterUid`, unknown status, unparseable dates).
4. Apply without re-keying first:
   `node scripts/migrate-ids.js --apply`
5. When the dry run is clean and a backup exists, re-key legacy IDs:
   `node scripts/migrate-ids.js --apply --delete-old`
6. Verify a sample of items/claims in the console: no `contact`/`proof` fields
   remain on public documents, private subcollections are populated.
7. Confirm the board, dashboards, claims, complaints, categories and broadcast
   all still work in the emulator.

### Remaining risks

- Items with no recoverable owner UID remain unownable until staff assigns an
  owner; they are still readable/moderatable by staff.
- Re-keying changes document IDs. Any external bookmark/link to a legacy ID
  will break; `legacyId`/`migratedFrom` preserves traceability.
- The migration cannot repair data that was already lost before the backup.

---

## Phase 3 — Firestore and Storage Security Rules

### Summary

- `firestore.rules` is now the authorization boundary:
  - every read requires a signed-in, email-verified, non-suspended token;
  - role comes only from the `role` custom claim; missing/invalid claims are
    treated as `student`;
  - token reads use `.get(key, default)` so a missing claim cannot cause a rules
    evaluation error;
  - items are public only in `approved|claimed|returned`; owners see their own;
  - item create is forced to `pending`, `isPinned: false`,
    `isStaffVerified: false`, caller UID and bounded strings;
  - owner updates cannot self-approve a pending item, pin, verify, change
    custody, reassign ownership or rewrite `createdAt`;
  - claims can only target an existing `approved` item the claimant does not
    own; proof lives in a private subcollection; resolved claims are immutable;
  - user profiles are self-readable; role/status/email are immutable from the
    client; client-side deletion is always denied;
  - notifications are recipient-scoped; students cannot notify others;
  - complaints are reporter/staff-only; only staff change status;
  - metadata writes are admin-only; audit logs are append-only, role-checked and
    admin-readable.
- `storage.rules`:
  - writes only to `items/{auth.uid}/{fileName}`;
  - image content types only (`image/jpeg`, `image/png`, `image/webp`);
  - filename pattern + extension checked; 3 MB maximum;
  - reads require a verified, non-suspended session;
  - owners delete their objects; admins can delete any object.
- Tests were written first-class for each rule and fixed two real bugs found by
  the suite:
  - missing token claims caused evaluation errors for ordinary students;
  - an item owner could move `pending` → `approved` (privilege escalation).

### Files

**Created**

- `firestore.rules`
- `storage.rules`
- `tests/rules/security.rules.test.js`

**Modified**

- `firebase.json` (rules locations)
- `functions/admin.js` / `functions/helpers.js` where they must write the
  fields the rules expect (e.g. `updatedBy`, audit entries)

**Deleted**

- Nothing.

### Manual steps

1. `npm install`
2. `npm test` (runs Firestore + Storage emulators and the 51-case suite).
3. In the Emulator UI, sign in as a student and run the negative probes in
   [`docs/SECURITY_TEST_PLAN.md`](SECURITY_TEST_PLAN.md#25-direct-api-probes-negative-tests).
4. Deploy rules only after tests pass:
   `firebase deploy --only firestore:rules,storage`
5. Re-run the probes against a disposable production account.

### Remaining risks

- Existing ID tokens keep old claims for up to one hour. Refresh tokens are
  revoked on suspension/role change, but an already-issued token remains valid
  until expiry.
- Rules enforce shape/length, not content quality; spam and abusive text are
  possible and need moderation/rate limiting.
- Duplicate pending claims are blocked in the UI but not by rules; staff review
  is still required before marking an item claimed.

---

## Phase 4 — Cloud Functions and privileged actions

### Summary

- Added a Node 20 Functions project with Admin SDK guards.
- **Blocking Auth functions**
  - `beforeUserCreated`: college-domain allowlist (`ALLOWED_EMAIL_DOMAINS`,
    default `campus.edu`), forces `role: "student"` and no `suspended` claim.
  - `beforeUserSignedIn`: rejects disabled/suspended accounts and unverified
    external accounts where configured.
- **Profile creation trigger**: `onUserCreated` creates the informational
  `users/{uid}` document.
- **Admin callables** (all require a verified admin token; sensitive ones also
  require recent authentication):
  - `setUserRole` — validates role, preserves unrelated claims, refuses to
    demote the last enabled admin, revokes refresh tokens.
  - `setUserStatus` — disables/enables Auth, revokes refresh tokens, sets/clears
    the `suspended` claim, refuses self-suspension/last-admin suspension.
  - `inviteUser` — admin-only account creation with a random unusable password
    and a one-time password-reset link; no SMTP credentials in the repo.
  - `deleteUserAccount` — admin-only; removes Auth, owned Firestore documents,
    private subcollections and Storage objects; audit logs retained.
  - `deleteOwnAccount` — self-service with recent auth and last-admin
    protection.
  - `revokeSessions` — self only.
  - `sendNotification` — admin-only, bounded audience/message.
- **Triggers**:
  - `onItemWritten` / `onClaimWritten` / `onUserWritten` write the authoritative
    audit trail and moderation notifications;
  - private contact/proof cleanup on parent deletion.
- Admin scripts (`make-admin.js`, `backfill-claims.js`) are dry-run by default
  and use Application Default Credentials only.

### Files

**Created**

- `functions/package.json`, `functions/package-lock.json`
- `functions/index.js`, `functions/helpers.js`, `functions/auth.js`,
  `functions/admin.js`, `functions/triggers.js`
- `scripts/make-admin.js`, `scripts/backfill-claims.js`
- `functions/.env` is **not** committed; `ALLOWED_EMAIL_DOMAINS` is documented.

**Modified**

- `public/firebase-service.js` (callable wrappers, reauth helper,
  `signOutAllDevices`, generic errors)
- `public/assets/js/app.js` (admin UI uses callables, reauth before sensitive
  actions)

**Deleted**

- Client-side role/status/delete/notification mutations that bypassed the
  server; replaced by callables. No UI feature was removed.

### Manual steps

1. Enable the **Blaze** plan (required for blocking Auth functions and
   Cloud Functions).
2. Set `ALLOWED_EMAIL_DOMAINS` in `functions/.env` for the real college
   domain(s), then `npm --prefix functions install`.
3. Deploy functions: `firebase deploy --only functions`.
4. Bootstrap the first admin with ADC:
   `node scripts/make-admin.js --email admin@campus.edu` (dry run), then
   `--apply`.
5. In the emulator, test invite, role change, suspension, deletion, broadcast
   and notification flows as an admin and confirm a student token is rejected by
   the same callables.
6. Configure MFA for staff/admin accounts (Identity Platform).
7. Configure Cloud Logging alerts for function errors and denied-request spikes.

### Remaining risks

- Blocking Auth functions and some Identity Platform features require Blaze and
  specific project settings; verify them in the target project.
- Functions are syntax-checked and reviewed but have no automated
  Functions-emulator integration suite in this repo. Add one before changing
  `admin.js`.
- `deleteUserAccount` is irreversible. It is guarded by recent auth and
  last-admin protection, but operators should back up before bulk use.
- Invite links are one-time but bearer-style; share them only over a trusted
  channel.

---

## Phase 5 — Frontend authentication, session and UI hardening

### Summary

- `firebase-service.js` is now the single source for auth/session/data:
  - role comes only from the ID token custom claim; `users.role` is display-only;
  - no roles/claims/private data in `localStorage`; only non-sensitive UI
    preferences and a login cooldown counter;
  - generic auth errors to prevent account enumeration;
  - email-verification gating; student-only sign-up;
  - Google sign-in uses redirect (popup-safe), with cooldown/error handling;
  - reauth helper and `signOutAllDevices` for sensitive actions;
  - rules-aware listeners with error handling so a denied query does not crash
    the dashboard;
  - compressed, re-encoded uploads; no base64 fallback.
- `login.html` / `login.js`:
  - removed demo autofill and the browser-side provisioner;
  - generic credential errors, cooldown/backoff after repeated failures;
  - forgot-password flow with a generic response;
  - verification gating and friendly resend.
- `app.js`:
  - requires a verified authenticated session; `index.html` redirects to login
    when signed out;
  - role-aware nav/dashboards, item lifecycle, claims, custody, complaints,
    categories, broadcast, notifications, audit view;
  - in-memory caches only; idle warning + auto sign-out; single auth listener;
  - sign-out-all-devices and reauth before destructive admin actions.
- Admin user directory now uses the audit-backed callables, not direct writes.

### Files

**Created**

- `public/assets/js/login.js` (rewritten)
- `public/firebase-service.js` (rewritten)

**Modified**

- `public/login.html`, `public/index.html`
- `public/assets/js/app.js`
- `public/assets/css/login.css` (removed dead demo pill styles)

**Deleted**

- Demo credential markup, demo autofill logic, browser-side account
  provisioning, and localStorage-based session/role caches. No user-facing
  workflow was removed.

### Manual steps

1. Run the account/session checks A1–A7 in
   [`docs/SECURITY_TEST_PLAN.md`](SECURITY_TEST_PLAN.md#21-account-and-session).
2. Verify index redirect, verification gating, generic errors and cooldown in a
   clean browser profile.
3. Run the student, faculty and admin flows S1–S8, F1–F8 and AD1–AD9.
4. Confirm no `campusCurrentUser` role value is written to localStorage (only
   non-sensitive UI prefs remain).
5. Confirm idle timeout signs the user out and clears in-memory caches.

### Remaining risks

- Client-side cooldown is a UX speed bump, not a security control. Firebase
  Auth/Identity Platform provide the real rate limiting.
- Idle timeout is client-side; a modified client can ignore it. Server-side
  session length/refresh-token settings are the real limit.
- Google sign-in depends on correct authorized domains and provider setup.

---

## Phase 6 — XSS and browser hardening

### Summary

- Centralised output encoding: `escapeHtml()` for all remote text/attributes;
  `handlerArg()`/`jsArg()` for inline-handler arguments; `safeDocId()` for
  document IDs; `safeImageUrl()` allowlists Firebase Storage hosts only.
- Audited every `innerHTML`, `.src`, `.href`, `textContent`, `location` and
  `localStorage` sink. No unescaped remote-data sink remains.
- `firebase.json` sends a strict CSP:
  - `script-src 'self'` (no inline `<script>`),
  - `script-src-attr 'unsafe-inline'` retained for the existing `onclick` UI,
  - `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`,
    `form-action 'self'`,
  - allowlisted `connect-src`/`img-src`/`frame-src`,
  - HSTS, `nosniff`, `X-Frame-Options: DENY`, referrer policy, Permissions
    Policy, COOP.
- Photos are re-encoded to JPEG via canvas before upload (strips EXIF/GPS and
  polyglot payloads); there is no base64/HTML fallback.
- Audit CSV export neutralises spreadsheet formula injection (`=`, `+`, `-`,
  `@`, tab, CR) in addition to quoting.
- Negative-test checklist added to `docs/XSS_AUDIT.md`.

### Files

**Created**

- `docs/XSS_AUDIT.md`

**Modified**

- `public/assets/js/app.js` (escaping helpers, safe URLs/IDs, CSV hardening)
- `public/assets/js/login.js` (text-only UI output)
- `firebase.json` (CSP/security headers)

**Deleted**

- Inline `<style>`/`<script>` blocks from the published HTML (moved to external
  files). No functionality removed.

### Manual steps

1. Load the site through Hosting/emulator and confirm the CSP header in
   DevTools → Network.
2. Create items/proofs/complaints containing `<img src=x onerror=alert(1)>`,
   `<svg onload=alert(1)>`, quotes and `javascript:` image URLs; confirm they
   render as text and no script runs.
3. Set a malicious broadcast as admin and confirm it renders as text.
4. Check the audit CSV for a title beginning with `=cmd|...` and confirm the
   cell is prefixed with `'` and treated as text by the spreadsheet.
5. Run the re-test checklist in `docs/XSS_AUDIT.md` after any UI change.

### Remaining risks

- Inline event handlers remain, so `script-src-attr 'unsafe-inline'` is still
  required. Migrating to `addEventListener` and removing it is the main
  follow-up.
- `style-src 'unsafe-inline'` is required by existing inline style attributes.
- No Trusted Types enforcement yet.
- Firebase/reCAPTCHA origins in `script-src`/`connect-src` are trusted
  third parties.
- Uploaded images are validated by declared type/size and client re-encode, but
  a modified client could still send arbitrary bytes labelled `image/jpeg`;
  they are only served as images with `nosniff`.

---

## Phase 7 — Verification, documentation and cleanup

### Summary

- Added a 51-case Firestore + Storage rules suite and ran it against the
  Emulator Suite.
- Added `npm run lint` (syntax check for frontend, functions, scripts and tests)
  and `npm test` (emulator rules suite).
- Wrote/updated:
  - `README.md` — setup, emulator use, scripts, deploy, data model, security
    summary, troubleshooting; no demo passwords.
  - `SECURITY.md` — threat model, controls, deployment checklist, residual
    risks.
  - `docs/SECURITY_TEST_PLAN.md` — automated matrix + manual checks + direct API
    probes.
  - `docs/XSS_AUDIT.md` — source/sink audit and residual inline-handler risk.
  - `docs/PHASES.md` — this report.
- Cleaned up the repository:
  - removed legacy root HTML/JS copies superseded by `public/`,
  - removed temporary asset-extraction/patching scripts,
  - removed dead demo-pill CSS and the stale demo hint markup/comments,
  - removed generated emulator debug log.
- Installed `functions/node_modules` so the Functions project is deploy-ready.
- Verified in this environment:
  - `npm run lint` — passes for all frontend, functions, scripts and tests.
  - `npm test` — **51 passed, 0 failed** (Firestore 8080 + Storage 9199,
    project `demo-campusconnect`). Level 2 later extended this to 70 rules
    cases plus 22 Functions-emulator cases.
  - `npm --prefix functions install` — 239 packages installed.
  - Node v24.12.0, npm 11.6.2, Java 24.0.2, Firebase CLI 15.5.1.

### Files

**Created**

- `docs/PHASES.md` (this file)
- `docs/XSS_AUDIT.md`
- `docs/SECURITY_TEST_PLAN.md`
- `README.md`, `SECURITY.md`
- `functions/package-lock.json`, `functions/node_modules/` (local install,
  gitignored)
- `package-lock.json`

**Modified**

- `package.json` (lint/test/emulator scripts)
- `public/assets/css/login.css` (dead demo styles removed)
- `public/assets/js/app.js` (CSV formula-injection hardening)

**Deleted**

- `index.html`, `login.html`, `firebase-config.js`, `firebase-service.js`
  (root legacy copies)
- `scripts/_extract-assets.js`, `scripts/_patch-app.js` (temporary helpers)
- `firestore-debug.log` (generated)

### Manual steps

1. `npm install && npm --prefix functions install`
2. `npm run lint`
3. `npm test`
4. `npm run serve` and run the manual checks in
   `docs/SECURITY_TEST_PLAN.md`.
5. Complete the console checklist in `SECURITY.md`:
   - API key restrictions,
   - authorized domains,
   - email verification template,
   - MFA policy,
   - App Check site key replacement + enforcement,
   - IAM least privilege,
   - budget/logging alerts.
6. Replace `REPLACE_WITH_RECAPTCHA_V3_SITE_KEY` in
   `public/firebase-config.js` and enforce App Check for Auth, Firestore,
   Storage and Functions.
7. Deploy:
   `firebase deploy --only firestore:rules,storage,functions,hosting`
8. Run the production verification list in
   `docs/SECURITY_TEST_PLAN.md#3-production-verification-after-deploy`.

### Remaining risks (overall)

1. **Inline handlers / CSP.** `script-src-attr 'unsafe-inline'` is still
   allowed. Values are encoded, but moving to `addEventListener` and dropping
   the allowance is the highest-value follow-up.
2. **App Check placeholder.** Until the real reCAPTCHA v3 key is configured and
   enforced, scripted clients can call public endpoints. Rules and Auth rate
   limits still apply.
3. **Stale tokens.** Role/suspension changes reach existing sessions only after
   a token refresh (up to one hour).
4. **Console-only settings.** API key restrictions, App Check enforcement, MFA,
   email templates, authorized domains and IAM are not in code and must be
   re-verified after project/domain changes.
5. **No Functions integration tests at the time of Phase 7.** Level 2 later
   added `tests/functions/level2.functions.test.js`; keep extending it when
   callables change.
6. **No server-side per-user rate limiting** beyond Auth/App Check; spam
   reports/claims/complaints are possible.
7. **Duplicate claims** are UI-prevented only; staff review remains mandatory.
8. **Audit trust split.** Client-written logs are role-checked and append-only
   but content is caller-controlled; treat Cloud Function entries as
   authoritative.
9. **Storage URLs.** Firebase download URLs are bearer-style; do not log or
   share them.
10. **CSV export** excludes private data but the downloaded file is unprotected;
    treat it as confidential.

---

## Quick verification record

| Check | Command | Result |
| --- | --- | --- |
| Syntax/lint (frontend, functions, scripts, tests) | `npm run lint` | Pass |
| Firestore + Storage rules suite | `npm test` | 51 passed, 0 failed |
| Functions dependencies installed | `npm --prefix functions install` | 239 packages |
| Emulator stack | `npm run serve` | Manual checks listed above |
| Deploy (after console setup) | `firebase deploy --only firestore:rules,storage,functions,hosting` | Operator action |

No phase required deleting a user-facing feature. The only deletions were
legacy duplicate files, temporary tooling, generated logs and dead demo styling.

---

# Level 2 — Engagement features (Phases 1–6)

This section records the Level 2 work added after the initial security
hardening. The original security model is unchanged: roles still come only from
ID-token custom claims, rules remain authoritative, and server-sensitive work
runs in Cloud Functions.

## Phase 1 — Push notifications (FCM)

### Summary

- FCM registration happens only after a user click in Dashboard → Notification
  Settings; the permission prompt is never shown on load.
- Tokens are stored at `users/{uid}/devices/{tokenId}` with a platform, enabled
  flag, user agent and timestamps. Owners can rotate/disable/delete their token.
- `onNotificationCreated` fans out data-only messages to enabled devices, deletes
  permanently invalid tokens reported by FCM, and records per-channel delivery
  markers (`pushAttemptedAt`) so an at-least-once retry cannot duplicate a send.
- The bell shows unread counts. Opening one notification marks only that item
  read and follows its validated same-origin `url`; “Mark all read” is explicit.
- Event triggers create notifications for moderation, claims, custody, chat and
  match events.

### Files

**Created**

- `functions/notifications.js`
- `tests/functions/level2.functions.test.js` (shared with later phases)

**Modified**

- `functions/helpers.js` (preferences, queueing, rate limits)
- `functions/triggers.js`, `functions/index.js`
- `firestore.rules`, `tests/rules/security.rules.test.js`
- `public/firebase-config.js`, `public/firebase-service.js`
- `public/index.html`, `public/assets/js/app.js`, `public/assets/css/styles.css`

### Manual steps

1. Replace `FCM_VAPID_KEY` in `public/firebase-config.js`.
2. Enable Cloud Messaging and upload the Web Push certificate.
3. Serve over HTTPS and click “Enable push”; verify foreground toast and
   background notification.
4. Deny permission once and confirm the UI explains how to re-enable it.

### Remaining risks

- Push is best-effort; OS/browser settings and battery savers can suppress it.
- Notification bodies are non-secret and may appear on a lock screen.

## Phase 2 — Email notifications

### Summary

- Resend delivery is server-side only. `RESEND_API_KEY` and
  `EMAIL_UNSUB_SECRET` are Secret Manager secrets declared on the email
  functions; `EMAIL_FROM` is a non-secret environment value.
- HTML and plain-text templates exist for claim received/approved/rejected,
  ready for pickup, returned receipt, custody update, broadcast, match and the
  weekly digest. Every interpolated value is escaped.
- User preferences and a per-user daily cap (`EMAIL_DAILY_CAP`, default 15) are
  checked before sending. Missing profiles, provider outages and failures are
  logged to the server-only `emailFailures` collection without failing the user
  action.
- The unsubscribe link carries a signed, 30-day token; tampering and expiry are
  rejected, and a valid link disables email + digest and writes an audit entry.
- Scheduled jobs send a weekly digest (Monday 08:00 UTC) and 30-day stale-claim
  reminders with per-run caps and small batches.

### Files

**Created**

- `functions/email.js`, `functions/scheduler.js`
- `docs/EMAIL_SETUP.md`

**Modified**

- `functions/notifications.js`, `functions/scheduler.js`, `functions/index.js`
- `functions/helpers.js`, `functions/triggers.js`
- `firestore.rules`, `tests/rules/security.rules.test.js`
- `tests/functions/level2.functions.test.js`
- `public/firebase-service.js`, `public/assets/js/app.js`,
  `public/assets/css/styles.css`
- `README.md`, `SECURITY.md`, `docs/SECURITY_TEST_PLAN.md`

### Manual steps

1. Verify the Resend sender domain (SPF/DKIM/DMARC).
2. Create `RESEND_API_KEY` and `EMAIL_UNSUB_SECRET` with
   `firebase functions:secrets:set` and grant the Functions service account.
3. Set `EMAIL_FROM`, `PUBLIC_BASE_URL` and optional `EMAIL_DAILY_CAP` /
   `ALLOWED_EMAIL_DOMAINS` in `functions/.env.<project>`.
4. Deploy functions and enable the Cloud Scheduler API.
5. Send a test notification, click the unsubscribe link, and confirm email is
   disabled in Notification Settings.

### Remaining risks

- Deliverability depends on Resend, DNS and the recipient's spam filter.
- Email is best-effort; in-app notifications are authoritative.

## Phase 3 — Secure chat

### Summary

- Chat IDs are deterministic (`chats/{itemId}_{claimantUid}`) and created only by
  the `ensureChat` callable after a claim is approved.
- Messages are written only by `sendChatMessage`: participants are checked,
  suspension blocks writes, text is trimmed/limited, a per-user fixed-window
  rate limit applies, and push is debounced.
- Rules deny all direct client chat/message writes. Participants and staff can
  read; staff are read-only unless they are a participant.
- The UI uses real-time listeners, date separators, unread markers and
  `textContent`/escaped rendering. A message can be reported; the moderation
  record does not copy the message text.
- Returning the item or rejecting the claim closes the chat automatically.

### Files

**Created**

- `functions/chat.js`

**Modified**

- `firestore.rules`, `tests/rules/security.rules.test.js`
- `tests/functions/level2.functions.test.js`
- `functions/helpers.js`, `functions/index.js`
- `public/firebase-service.js`, `public/assets/js/app.js`,
  `public/assets/css/styles.css`, `public/index.html`

### Manual steps

1. Approve a claim and open the chat from the claimant and reporter accounts.
2. Confirm an unrelated student cannot read the chat or send directly.
3. Send more than 10 messages in a minute and confirm the rate-limit message.
4. Report a message as a student and review it as staff.
5. Return the item with the QR flow and confirm the chat closes.

### Remaining risks

- Chat is campus-private, not end-to-end encrypted; staff can read it by rule.
- Retention is not automated; define a policy if required.

## Phase 4 — QR handover and receipts

### Summary

- `getHandoverToken` issues `CC1.<claimId>.<32 random bytes>` (256 bits) to the
  claimant for an approved claim. Only the SHA-256 hash is stored at
  `claims/{claimId}/private/handover`; no client, including admins, can read it.
- Tokens expire after 24 hours. Re-issuing rotates the token and invalidates the
  previous one. Issuing and verification are rate-limited.
- Staff scan with `BarcodeDetector` when available, the vendored `jsQR` fallback
  otherwise, or manual token entry. Camera permission is the only Permissions
  Policy capability enabled.
- `verifyHandover` runs in one Firestore transaction: it checks hash/expiry/used
  state, marks the claim and item returned, closes the chat, burns the token,
  writes a receipt and audits both success and failure.
- The claimant and reporter can view the digital return receipt; clients cannot
  create or edit receipts.

### Files

**Created**

- `functions/handover.js`
- `public/assets/vendor/qrcode.js`, `public/assets/vendor/jsQR.js`,
  `public/assets/vendor/jsQR.LICENSE.txt`

**Modified**

- `firestore.rules`, `tests/rules/security.rules.test.js`
- `tests/functions/level2.functions.test.js`
- `functions/index.js`, `functions/helpers.js`
- `firebase.json` (`Permissions-Policy: camera=(self)`)
- `public/index.html`, `public/firebase-service.js`,
  `public/assets/js/app.js`, `public/assets/css/styles.css`

### Manual steps

1. Approve a claim, open “Handover code”, and show the QR/token.
2. Scan it from a staff device (or paste the token) and confirm the success
   receipt.
3. Try the same token again and confirm it is rejected without state changes.
4. Try a student account and confirm verification is denied.
5. Revoke camera permission and confirm manual entry still works.

### Remaining risks

- The QR token is bearer-style until used/expired; do not screenshot or share it.
- A lost staff device can scan codes until the token expires; suspension and
  staff re-authentication remain the main controls.

## Phase 5 — PWA, offline queue and install

### Summary

- Added `manifest.webmanifest`, 192/512/maskable/apple-touch icons and a single
  root service worker. `firebase-messaging-sw.js` is a thin
  `importScripts("/sw.js")` shim; only `/sw.js` is registered.
- App-shell precache; HTML is network-first; static assets use
  stale-while-revalidate. Firebase/Auth/Storage and authenticated data are never
  cached.
- `/sw.js` and the FCM worker are served `no-cache`; the manifest has the correct
  MIME type; icons are cached for a week.
- Offline banner, queued-report count, install prompt and iOS “Add to Home
  Screen” instructions are shown. Text-only reports queue in IndexedDB and flush
  automatically; photo reports abort clearly while offline.
- The CSP now includes `worker-src 'self' blob:` and `manifest-src 'self'`; no
  `unsafe-inline` was added to `script-src`.

### Files

**Created**

- `public/manifest.webmanifest`, `public/sw.js`,
  `public/firebase-messaging-sw.js`
- `public/assets/icons/` (192/512/maskable/apple-touch)
- `scripts/generate-pwa-icons.js`

**Modified**

- `firebase.json` (CSP, service-worker/manifest/icon headers)
- `public/index.html`, `public/assets/js/app.js`,
  `public/assets/css/styles.css`, `public/firebase-service.js`

### Manual steps

1. Serve over HTTPS (or localhost), install the app and confirm the icon/name.
2. Go offline: confirm the banner, queued report count and text-report flush.
3. Confirm a photo report is refused offline with a clear message.
4. Confirm no authenticated Firestore/Storage response appears in Cache Storage.
5. Run Lighthouse if available; the CLI is not installed in this environment, so
   no Lighthouse report is included.

### Remaining risks

- Cache versioning must be updated when shell assets change.
- IndexedDB data persists on a shared device until flushed or cleared.

## Phase 6 — Verification and documentation

### Summary

- Extended the rules suite to 70 cases: devices, preferences, chats, messages,
  read markers, moderation, receipts, handover secrecy, claim-returned denial,
  server-only bookkeeping collections and notification URL validation.
- Added 22 Functions-emulator tests covering helpers/preferences, email
  templates/tokens/quotas/failures, chat guards/rate limits/moderation, QR
  issuance/verification/single-use and notification fan-out/dedupe.
- `npm run lint` covers the frontend, service workers, PWA icon script, Functions
  modules and both test suites. `npm test` runs rules then Functions.
- Updated `README.md`, `SECURITY.md`, `docs/SECURITY_TEST_PLAN.md`,
  `docs/PHASES.md` and added `docs/EMAIL_SETUP.md`.

### Manual steps

1. `npm install && npm --prefix functions install`
2. `npm run lint`
3. `npm run test:rules`
4. `npm run test:functions`
5. `npm test`
6. Complete the console checklist in `SECURITY.md`.
7. Run the Level 2 manual checks in `docs/SECURITY_TEST_PLAN.md`.

### Remaining risks

See the Level 2 additions in [`SECURITY.md`](../SECURITY.md#residual-risks-and-assumptions):
partial rate-limiting coverage, chat retention/encryption expectations, email
deliverability, bearer-style QR tokens, service-worker trust, offline queue
persistence and push payload visibility.

## Level 2 verification record

| Check | Command | Result |
| --- | --- | --- |
| Syntax/lint (frontend, workers, functions, scripts, tests) | `npm run lint` | Pass |
| Firestore + Storage rules suite | `npm run test:rules` | 70 passed, 0 failed |
| Functions emulator suite | `npm run test:functions` | 22 passed, 0 failed |
| Combined suite | `npm test` | Rules then Functions, all pass |
| Lighthouse | not run | CLI not installed in this environment |

No user-facing feature was deleted in Level 2. The only non-code additions are
the vendored MIT/Apache-2.0 QR libraries and generated PWA icons.
