# Campus Connect — Lost & Found Portal

A university Lost & Found board with student, faculty/staff and administrator
workflows. The frontend is plain HTML, CSS and JavaScript (no build step) and
uses the Firebase compat SDK. Firebase Authentication, Cloud Firestore, Cloud
Storage, Cloud Functions and Security Rules provide the security boundary.

> **There are no demo accounts or seeded passwords in this repository.** Real
> accounts are created through the admin-only `inviteUser` Cloud Function or the
> Firebase Console, and elevated roles are assigned only by an administrator.

---

## Project layout

```text
frontend/
├─ public/                     # Hosting deploy root
│  ├─ index.html               # Board + dashboards (authenticated only)
│  ├─ login.html               # Sign-in / password reset / Google SSO
│  ├─ firebase-config.js       # Public Firebase config + emulator switch
│  ├─ firebase-service.js      # Auth, Firestore, Storage, callables
│  ├─ manifest.webmanifest     # PWA manifest
│  ├─ sw.js                    # Root service worker (PWA + FCM)
│  ├─ firebase-messaging-sw.js # Thin FCM worker that imports sw.js
│  └─ assets/
│     ├─ css/                  # Extracted styles
│     ├─ icons/                # PWA icons (192/512/maskable/apple-touch)
│     ├─ js/                   # app.js + login.js
│     └─ vendor/               # Local QR generator + jsQR fallback
├─ functions/                  # Cloud Functions (Node 20)
│  ├─ auth.js                  # Blocking sign-up/sign-in checks + profile trigger
│  ├─ admin.js                 # Role, suspension, invite, deletion, notifications
│  ├─ triggers.js              # Audit trail, claim notifications, private cleanup
│  ├─ notifications.js         # FCM fan-out + invalid-token cleanup + email fan-out
│  ├─ email.js                 # Resend delivery, templates, signed unsubscribe endpoint
│  ├─ chat.js                  # Deterministic chats, callable-only messages, moderation
│  ├─ handover.js              # Hashed single-use QR tokens + atomic verification
│  ├─ scheduler.js             # Weekly digest + stale-claim reminders
│  ├─ helpers.js               # Admin SDK guards and shared utilities
│  └─ index.js                 # Function exports
├─ scripts/
│  ├─ make-admin.js            # Bootstrap/repair a role custom claim (dry-run default)
│  ├─ backfill-claims.js       # Repair legacy accounts' role/suspended claims
│  ├─ migrate-ids.js           # Migrate legacy Firestore documents (dry-run default)
│  └─ generate-pwa-icons.js    # Regenerate manifest/apple icons
├─ tests/
│  ├─ rules/                   # Firestore + Storage rules tests
│  └─ functions/               # Functions-emulator tests (Level 2 modules)
├─ docs/                       # Security test plan, XSS audit, email setup, phase report
├─ firebase.json               # Hosting, CSP/headers, rules, functions, emulators
├─ firebase.functions-test.json # Firestore-only emulator config (port 8081)
├─ firestore.rules             # Authoritative Firestore rules
├─ storage.rules               # Authoritative Storage rules
├─ firestore.indexes.json
├─ .firebaserc                 # Default project (campusconnect-bc130)
└─ package.json                # Emulator tests + migration scripts
```

---

## Security model (short version)

| Concern | Control |
| --- | --- |
| Roles | Firebase Auth **custom claim** `role` (`student`, `faculty`, `admin`). The `users/{uid}.role` field is informational only. |
| Sessions | `users/{uid}.email_verified == true` and `suspended != true` required by rules. Suspension disables Auth, revokes refresh tokens and adds a `suspended` claim. |
| Data access | `firestore.rules` and `storage.rules` are authoritative; client checks are UX only. |
| Private data | Reporter contact lives at `items/{id}/private/contact`; ownership proof at `claims/{id}/private/proof`. Neither is in public board queries. |
| Privileged actions | Only Cloud Functions (Admin SDK) can change roles, suspend accounts, invite users, delete accounts or broadcast to everyone. |
| Photos | Client re-encodes to JPEG (strips EXIF/GPS), then Storage rules enforce owner path, image content type and 3 MB maximum. No base64 fallback. |
| Audit | Client logs are append-only and role-checked; Cloud Functions write the authoritative audit trail. |
| Browser hardening | Strict CSP, HSTS, `nosniff`, `frame-ancestors 'none'`, restrictive Permissions Policy (`camera=(self)` only for QR scanning). All remote text is escaped before insertion. |
| Local storage | Only non-sensitive UI preferences, a login cooldown counter and a text-only offline report queue. Never roles, private proof, photos or tokens. |
| Push | FCM tokens are stored per user under `users/{uid}/devices`; only a Cloud Function can fan out a notification, and invalid tokens are deleted. Payloads are data-only. |
| Email | Resend is called server-side with Secret Manager credentials. HTML is escaped, preferences and a daily cap are enforced, and unsubscribe links are signed and expiring. |
| Chat | Deterministic `chats/{itemId}_{claimantUid}` documents are created only by a Cloud Function. Messages are callable-only, rate-limited and can be reported; direct client message writes are denied. |
| QR handover | The claimant receives a 128-bit+ token on demand; only its SHA-256 hash is stored in a server-only subcollection. Staff verification is single-use, atomic and audited. |
| PWA | One root service worker precaches the app shell, network-first for HTML, stale-while-revalidate for static assets, and never caches Firebase/Auth/Storage data. |

See [`SECURITY.md`](SECURITY.md), [`docs/XSS_AUDIT.md`](docs/XSS_AUDIT.md) and
[`docs/EMAIL_SETUP.md`](docs/EMAIL_SETUP.md) for the full model, email
configuration and residual risks.

---

## Engagement features

- **Push notifications.** The bell shows unread notifications; opening one marks
  that item read and navigates to its same-origin target. “Mark all read” is
  explicit. Push permission is requested only after a user click in
  Dashboard → Notification Settings, and the root service worker handles both
  foreground toasts and background data messages.
- **Email notifications.** Claim received/approved/rejected/returned, pickup,
  custody, broadcast, match and weekly digest templates are available. Users can
  opt out per category, and every message carries a signed unsubscribe link.
- **Secure chat.** Approved claims get one deterministic chat per claimant and
  item. Participants (and staff, read-only) can exchange messages with date
  separators and an unread indicator. Messages are callable-only, rate-limited,
  reportable, and auto-close when the item is returned or the claim rejected.
- **QR handover.** The claimant shows a rotating single-use QR code and token;
  staff scan it with the camera (`BarcodeDetector`, with a vendored `jsQR`
  fallback) or type the token manually. A successful scan atomically marks the
  claim and item returned, closes the chat and creates a digital receipt.
- **PWA.** The app is installable from the browser, shows an offline banner and
  queued-report count, and stores text-only reports in IndexedDB while offline.
  Photos require a connection because they are never cached or queued.

---

## Local development

### Prerequisites

- Node.js 20 or newer (this repo was verified with Node 24.12)
- Java 11+ for the Firestore/Storage emulators
- Firebase CLI: `npm install -g firebase-tools`
- A browser with Application Default Credentials only if you run admin scripts
  against a real project

### Install

```bash
npm install
npm --prefix functions install
```

### Run the whole stack in emulators

```bash
npm run serve
# Hosting      http://localhost:5000
# Emulator UI  http://localhost:4000
# Auth         9099 | Firestore 8080 | Storage 9199 | Functions 5001
```

`public/firebase-config.js` connects to emulators **only** when the page is
served from `localhost` or `127.0.0.1`. A deployed build always uses production.

### Create a local administrator

1. Open `http://localhost:5000/login.html`, create a student account, then use
   the Auth emulator UI to mark the email verified (the Auth emulator does not
   send real email).
2. With the emulators running, in a second terminal:

   ```powershell
   $env:FIREBASE_AUTH_EMULATOR_HOST = "127.0.0.1:9099"
   $env:FIRESTORE_EMULATOR_HOST  = "127.0.0.1:8080"
   node scripts/make-admin.js --email you@campus.edu --apply
   ```

3. Sign out and sign in again so the new ID token contains `role: "admin"`.

Other useful scripts:

```bash
node scripts/backfill-claims.js            # dry run
node scripts/backfill-claims.js --apply --revoke
node scripts/migrate-ids.js                # dry run
node scripts/migrate-ids.js --apply --delete-old
```

---

## Tests

```bash
npm run lint              # node --check on all frontend, functions and script files
npm test                  # rules suite, then Functions suite
npm run test:rules        # Firestore + Storage rules only
npm run test:functions    # Functions emulator only (Firestore)
```

The rules suite covers authentication claims, items, private contact, claims and
private proof, users/roles, notifications, complaints, metadata, audit logs,
devices, notification preferences, chats, messages, read markers, moderation,
receipts, handover secrecy, claim-returned denial, server-only bookkeeping
collections and Storage ownership/type/size limits. The Functions suite exercises
preferences, email templates and unsubscribe tokens, chat guards and rate limits,
QR issuance/verification/single-use and notification fan-out/dedupe against the
Firestore emulator.

See [`docs/SECURITY_TEST_PLAN.md`](docs/SECURITY_TEST_PLAN.md) for the full matrix
and manual verification steps, [`docs/PHASES.md`](docs/PHASES.md) for the
per-phase hardening report, and [`docs/EMAIL_SETUP.md`](docs/EMAIL_SETUP.md) for
Resend setup.

---

## Deploy

1. Create/select the Firebase project and update `.firebaserc` if it is not
   `campusconnect-bc130`.
2. Enable **Blaze** (required for blocking Auth functions and Cloud Functions),
   then enable Email/Password and Google providers.
3. Create `functions/.env.campusconnect-bc130` (never commit it) with the
   non-secret configuration:

   ```dotenv
   ALLOWED_EMAIL_DOMAINS=campus.edu
   EMAIL_FROM=Campus Connect <no-reply@campus.edu>
   PUBLIC_BASE_URL=https://campusconnect-bc130.web.app
   # EMAIL_DAILY_CAP=15
   ```

4. Create the Resend API key and the unsubscribe signing secret in Secret
   Manager (see [`docs/EMAIL_SETUP.md`](docs/EMAIL_SETUP.md)):

   ```bash
   firebase functions:secrets:set RESEND_API_KEY
   firebase functions:secrets:set EMAIL_UNSUB_SECRET
   ```

5. Replace `APP_CHECK_SITE_KEY` in `public/firebase-config.js` with your
   reCAPTCHA v3 site key and `FCM_VAPID_KEY` with the Web Push certificate from
   Firebase Console → Project settings → Cloud Messaging. Then enforce App Check
   for Auth, Firestore, Storage and Functions.
6. Deploy:

   ```bash
   npm --prefix functions install
   firebase deploy --only firestore:rules,storage,functions,hosting
   ```

   The first deploy that binds a secret asks you to grant the Functions service
   account access. Scheduled digest/reminder jobs are created automatically
   (enable the Cloud Scheduler API if prompted).

7. Bootstrap the first administrator (ADC, dry-run first):

   ```bash
   gcloud auth application-default login
   node scripts/make-admin.js --email admin@campus.edu
   node scripts/make-admin.js --email admin@campus.edu --apply
   ```

8. Complete the console checklist in [`SECURITY.md`](SECURITY.md), including API
   key restrictions, authorized domains, email templates, MFA policy, Resend
   domain verification and IAM least privilege.

### Environment / configuration

- `public/firebase-config.js` — public Web API key, project IDs, emulator switch,
  App Check site key and FCM VAPID key. These are public identifiers, but the API
  key must still be restricted.
- `RESEND_API_KEY`, `EMAIL_UNSUB_SECRET` — Secret Manager secrets bound to the
  email functions. Never commit them.
- `functions/.env.<project>` — `ALLOWED_EMAIL_DOMAINS`, `EMAIL_FROM`,
  `PUBLIC_BASE_URL` and optional `EMAIL_DAILY_CAP`.
- `firebase.json` — hosting root, CSP/headers, service-worker/manifest cache
  rules, rules locations, functions runtime and emulator ports.
- `.firebaserc` — default project alias.

---

## Data model

```text
users/{uid}                          role/status informational mirror (claims are authoritative)
users/{uid}/devices/{tokenId}        per-device FCM token (owner only; server cleans invalid tokens)
items/{itemId}                       public board record; status pending|approved|claimed|returned|rejected
items/{itemId}/private/contact       reporter contact (owner + staff only)
claims/{claimId}                     claim metadata; pending|approved|rejected|returned (returned is server-only)
claims/{claimId}/private/proof       ownership proof (claimant + staff only)
claims/{claimId}/private/handover    SHA-256 handover token hash (server-only)
chats/{itemId}_{claimantUid}         deterministic secure chat (server-created)
chats/{chatId}/messages/{messageId}  callable-written messages (participants + staff read)
chats/{chatId}/reads/{uid}           per-user read marker
notifications/{notifId}              per-user notifications (+ push/email attempt markers)
receipts/{claimId}                   digital return receipt (parties + staff read, server-written)
moderation/{reportId}                message reports (reporter + staff read, server-written)
complaints/{complaintId}             disputes / inquiries
metadata/categories                  board categories
metadata/broadcast                   campus-wide banner
logs/{logId}                         append-only audit trail
rateLimits/{uid_action}              server-only rate-limit counters
emailUsage/{uid}                     server-only daily email quota
emailFailures/{id}                   server-only delivery failure log
```

All client-created records use auto-IDs and server timestamps. The
`reporterUid` / `claimantUid` fields are immutable from the client after create.
The server-only collections and private subcollections are readable only through
Cloud Functions or the owning participant/staff rule; they are never part of a
public board query.

---

## Troubleshooting

- **“Missing or insufficient permissions”** — the ID token is stale. Sign out and
  in, or run `node scripts/backfill-claims.js --apply --revoke` for legacy
  accounts.
- **Emulator port already in use** — stop the previous emulator (or the Java
  process holding port 8080) before running `npm test`.
- **Google sign-in blocked** — add the hosting domain to Firebase Auth
  authorized domains and finish the Google provider setup.
- **App Check errors in production** — confirm the site key is set and the
  provider is registered for the correct domains; use a debug token only in
  local development.
- **Functions deploy fails** — confirm the Blaze plan is active,
  `functions/node_modules` is installed, and the Resend/unsubscribe secrets
  exist if the deploy binds them.
- **Push permission denied or no token** — the user must click “Enable push”,
  `FCM_VAPID_KEY` must be a real Web Push certificate, and the site must be
  served over HTTPS (localhost is allowed).
- **No emails arrive** — check `emailFailures` in the console, confirm the Resend
  sender domain is verified, `EMAIL_FROM` matches it, and the recipient has not
  opted out. See [`docs/EMAIL_SETUP.md`](docs/EMAIL_SETUP.md).
- **QR scanner shows no camera** — grant camera permission; Permissions Policy
  allows `camera=(self)`. If `BarcodeDetector` is unavailable, the app falls back
  to the vendored `jsQR` bundle. Manual token entry always works.
- **Service worker serves stale HTML** — HTML is network-first; a new deploy
  activates on the next reload. `/sw.js` and the FCM worker are served with
  `no-cache`, so never add them to a long-lived cache rule.
