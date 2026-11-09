# Security Policy — Campus Connect

## Reporting a vulnerability

Do **not** open a public issue for a suspected vulnerability. Contact the campus
IT/security team that operates this deployment, or the repository owner
privately, with:

- affected page/function and version or commit,
- reproduction steps and required account role,
- impact (data exposed, privilege gained, availability),
- any suggested fix.

Please allow time for triage before public disclosure.

## Supported versions

Only the current `main` deployment (Firebase project `campusconnect-bc130`) and
the current `firebase.json` / rules / functions in this repository are supported.
There are no long-lived release branches; redeploy rules and functions together
when changing the security model.

---

## Threat model

### Assets

- Student and staff account identities and role claims.
- Private reporter contact details, claim ownership proofs and claim email addresses.
- Moderation state (approval, rejection, claim resolution, suspension).
- Uploaded item photos.
- Audit logs.
- FCM device tokens and push/email delivery state.
- Secure chat messages and message reports.
- Plaintext QR handover tokens (short-lived, never stored) and return receipts.
- Resend API key and unsubscribe signing secret.

### Adversaries

- An authenticated student attempting privilege escalation or reading other
  users' private data.
- A suspended or unverified account attempting to keep using the API.
- A malicious/compromised browser bypassing the UI (all client checks are
  bypassable by design).
- An anonymous internet client probing Firestore/Storage/Auth endpoints.
- A spammer or scripted client abusing open endpoints, chat, push or email.
- A member trying to forge a chat, read another chat, replay/guess a handover
  token, or tamper with an unsubscribe link.
- A stolen device token or leaked browser cache.

### Trust boundaries

- **Untrusted:** browser code, localStorage, URL parameters, all request bodies,
  document fields, filenames and uploaded bytes.
- **Trusted:** Cloud Functions with the Admin SDK, Security Rules, Firebase Auth
  ID tokens, and server-side App Check verification.

---

## Authoritative controls

### 1. Roles are custom claims only

`request.auth.token.role` is the only authorization source. The `users/{uid}.role`
field is an informational mirror for the admin UI. A forged or stale `users`
document cannot grant access. Roles are written only by:

- `beforeUserCreated` (forces `student` on sign-up),
- the admin-only `setUserRole` callable,
- `inviteUser` (admin-only account creation),
- the audited `scripts/make-admin.js` / `scripts/backfill-claims.js` bootstrap.

### 2. Verified, non-suspended sessions

Every Firestore/Storage rule requires:

```text
request.auth.token.email_verified == true
request.auth.token.suspended != true
```

Account suspension is applied in three layers by `setUserStatus`:

1. Firebase Auth `disabled` (blocks new sign-ins),
2. refresh-token revocation (blocks silent session renewal),
3. a `suspended` custom claim (rules reject the refreshed token).

Existing ID tokens can remain valid for up to one hour after a change; refresh
tokens are revoked so no new token is issued. This is a deliberate trade-off
documented under residual risks.

### 3. Rules are the enforcement point

- Items: public statuses only (`approved`, `claimed`, `returned`); owners can see
  their own pending/rejected items; staff can see all.
- Item creation is forced to `pending`, `isPinned: false`,
  `isStaffVerified: false` and the caller's UID. Only staff can approve.
- Owners cannot self-approve, pin, verify, change custody, reassign ownership or
  rewrite `createdAt`.
- Claims can target only an existing **approved** item the claimant does not own.
- Claim proof and reporter contact are in private subcollections with separate
  owner/staff rules and no public read path.
- User documents are self-readable; admins can read the directory. Role, status
  and email are immutable from the client. Client deletion is always denied.
- Notifications are readable only by the recipient; students may write only to
  themselves; recipients may only flip `read`.
- Complaints are private to the reporter and staff; only staff change status.
- Metadata writes are admin-only; audit logs are append-only (client entries
  must match the caller's real role) and admin-readable.

### 4. Privileged operations live in Cloud Functions

The Admin SDK bypasses rules, so every callable re-validates the caller:

| Callable | Guard |
| --- | --- |
| `setUserRole` | verified admin + recent auth (10 min) + last-admin protection |
| `setUserStatus` | verified admin + recent auth + cannot suspend self/last admin |
| `inviteUser` | verified admin + allowed college domain + random unusable password |
| `deleteUserAccount` | verified admin + recent auth + last-admin protection |
| `deleteOwnAccount` | verified user + recent auth (5 min) + last-admin protection |
| `revokeSessions` | signed-in user, self only |
| `sendNotification` | verified admin, bounded audience/message |

Account deletion removes Auth, owned Firestore documents, private subcollections
and Storage objects. Audit logs are intentionally retained.

### 5. Storage

- Uploads only to `items/{auth.uid}/{fileName}`.
- Content type restricted to `image/jpeg`, `image/png`, `image/webp`.
- Maximum object size 3 MB; filename pattern and extension are checked.
- Reads require a verified, non-suspended session.
- Owners can delete their own objects; admins can delete any object.
- The browser re-encodes to JPEG through a canvas before upload, which strips
  EXIF/GPS metadata. There is no base64 fallback: a failed upload aborts the
  submission.

### 6. Browser hardening

`firebase.json` sends:

- Content-Security-Policy with `script-src 'self'` (no inline `<script>`),
  `object-src 'none'`, `base-uri 'self'`, `frame-ancestors 'none'`,
  `form-action 'self'`, restricted `connect-src`/`img-src`/`frame-src`;
- HSTS (one year, include subdomains, preload);
- `X-Content-Type-Options: nosniff`;
- `X-Frame-Options: DENY`;
- `Referrer-Policy: strict-origin-when-cross-origin`;
- Permissions Policy allowing `camera=(self)` only for QR scanning, while
  disabling microphone, geolocation, payment and USB;
- `Cross-Origin-Opener-Policy: same-origin-allow-popups` for Google sign-in.

CSP still allows inline event-handler attributes (`script-src-attr
'unsafe-inline'`) because the existing UI uses `onclick`. Every value inserted
into an inline handler is escaped and percent-encoded; see
[`docs/XSS_AUDIT.md`](docs/XSS_AUDIT.md). Removing this allowance is a planned
follow-up (move handlers to `addEventListener`).

### 7. Secrets

- No service-account keys, SMTP passwords, Resend keys or HMAC secrets are in the
  repository.
- `RESEND_API_KEY` and `EMAIL_UNSUB_SECRET` are stored in Secret Manager and
  declared on the email functions. `EMAIL_FROM` and `PUBLIC_BASE_URL` are
  non-secret environment values.
- The Web API key, App Check site key and FCM VAPID key are public identifiers;
  restrict the API key by HTTP referrer and allowed APIs in Google Cloud Console.
- Admin scripts use Application Default Credentials. Never pass a private key on
  the command line or commit `functions/.env` / `service-account*.json`.
- `.gitignore` excludes `.env*`, service-account JSON, emulator state and logs.

### 8. Push, email, chat, QR and PWA

- **Push.** Tokens live at `users/{uid}/devices/{tokenId}`; only the owner can
  read/write them, and rules reject unknown fields, invalid platforms and short
  tokens. Fan-out is a Firestore trigger, never a client call. Payloads are
  data-only and the service worker chooses the same-origin link. Permanently
  invalid tokens are deleted by the trigger. Permission is requested only from a
  user click.
- **Email.** Resend is called server-side with `RESEND_API_KEY` from Secret
  Manager. HTML is escaped, links are restricted to same-origin paths, and
  messages never contain another member's contact details or proof. Preferences
  and a per-user daily cap are checked before sending. The unsubscribe endpoint
  accepts only a signed, expiring HMAC token; tampering and expiry are rejected
  in constant time.
- **Chat.** `chats/{itemId}_{claimantUid}` is deterministic and created only by
  `ensureChat` after a claim is approved. Clients cannot create/update/delete
  chats or messages; `sendChatMessage` is the only write path, with participant
  checks, a per-user rate limit, text length limits, suspension blocking and
  auto-close on return/rejection. Staff are read-only unless they are
  participants. Reports create a moderation record without copying message text.
- **QR handover.** `getHandoverToken` issues a `CC1.<claimId>.<32 random bytes>`
  token (256 bits) to the claimant. Only its SHA-256 hash is stored at
  `claims/{claimId}/private/handover`, which no client (including admins) can
  read. Staff call `verifyHandover`; verification is rate-limited, audited on
  failure, and atomically marks the claim/item returned, closes the chat, writes
  a receipt and burns the token. Tokens expire after 24 hours and re-issuing
  rotates the previous one.
- **PWA.** One root service worker precaches the app shell. HTML is network-first,
  static assets use stale-while-revalidate, and Firebase/Auth/Storage traffic and
  authenticated API responses are never cached. `/sw.js` and
  `firebase-messaging-sw.js` are served `no-cache`; the manifest is served as
  `application/manifest+json`. Offline reports are text-only IndexedDB entries
  and are removed after a successful flush.

---

## Deployment checklist

- [ ] Blaze plan enabled; Cloud Functions and blocking Auth functions deployed.
- [ ] `ALLOWED_EMAIL_DOMAINS` set for the real college domain(s).
- [ ] Email/Password and Google providers configured; authorized domains added.
- [ ] Email verification template configured; new accounts start as `student`.
- [ ] MFA policy enabled for staff/admin accounts (Identity Platform).
- [ ] App Check reCAPTCHA v3 key replaced and enforcement enabled for Auth,
      Firestore, Storage and Functions.
- [ ] `FCM_VAPID_KEY` replaced with the Web Push certificate; Cloud Messaging
      API enabled.
- [ ] `RESEND_API_KEY` and `EMAIL_UNSUB_SECRET` set in Secret Manager; the
      Functions service account has secret access.
- [ ] Resend sender domain verified; `EMAIL_FROM` matches it; SPF/DKIM/DMARC
      records published.
- [ ] `ALLOWED_EMAIL_DOMAINS`, `PUBLIC_BASE_URL` and optional `EMAIL_DAILY_CAP`
      set for the deployment.
- [ ] Cloud Scheduler API enabled; weekly digest and stale-claim reminder jobs
      created.
- [ ] `camera=(self)` is the only camera allowance; no other Permissions Policy
      capability is enabled.
- [ ] Service worker and FCM worker are served `no-cache`; authenticated data is
      not cached (verify in DevTools → Application → Cache Storage).
- [ ] Web API key restricted by HTTP referrer and to the required APIs.
- [ ] Firestore and Storage rules deployed from this repository.
- [ ] First admin bootstrapped with `scripts/make-admin.js`; at least two admins
      exist to avoid a single point of failure.
- [ ] Legacy data migrated with `scripts/migrate-ids.js` (dry run first).
- [ ] Legacy accounts repaired with `scripts/backfill-claims.js` (dry run first).
- [ ] Budget/alerting and Cloud Logging alerts configured for function errors and
      denied-request spikes.
- [ ] IAM least privilege: deploy/service accounts cannot read user data unless
      required; no long-lived owner keys.

---

## Residual risks and assumptions

1. **Inline event handlers.** CSP allows inline `on*` attributes. Escaping and
   `safeDocId`/`safeImageUrl` reduce XSS risk, but removing `script-src-attr
   'unsafe-inline'` is stronger. Tracked as a follow-up.
2. **App Check placeholder.** Until the real reCAPTCHA v3 site key is configured
   and enforced, scripted clients can call public endpoints. Firebase Auth rate
   limits and rules still apply.
3. **Stale tokens.** Role/suspension changes reach existing sessions only after
   token refresh (up to one hour). Sensitive callables require fresh auth, which
   mitigates this for destructive actions.
4. **Storage download URLs.** A Firebase download URL is bearer-style: anyone who
   obtains it while able to authenticate can fetch the object. URLs should not be
   logged or shared outside the app.
5. **Content validation.** Storage trusts the declared `image/*` content type and
   size. The app re-encodes images, but a modified client could upload arbitrary
   bytes labelled `image/jpeg`. Images are rendered only through `<img>` with
   `nosniff`; do not proxy them through HTML responses.
6. **Per-user rate limiting is partial.** New chat/handover callables use
   server-only fixed-window counters, and email has a daily cap. Reports,
   claims and complaints still rely on Auth/App Check limits; add callable
   counters if spam becomes a problem.
7. **Duplicate claims.** Rules allow more than one pending claim per user/item.
   The UI prevents it, but a modified client can bypass the check. Staff review
   is still required before any item is marked claimed.
8. **Audit trust split.** Client logs are append-only but forgeable in content
   (role is checked). Use the Cloud Function-written entries as authoritative.
9. **Chat content is not encrypted at rest beyond Firestore defaults.** Treat
   chat as campus-private, not end-to-end encrypted. Staff can read chats under
   the rules, and messages are retained with the chat. Define a retention policy
   before launch if local policy requires one.
10. **Manual console settings are not in code.** API key restrictions, App Check
    enforcement, MFA, email templates, IAM, authorized domains, Resend domain
    verification and the VAPID key must be set in Firebase/Google Cloud/Resend
    consoles and re-verified after project changes.
11. **Email is best-effort.** Resend outages, bounces and spam filtering can
    delay or drop a message. In-app notifications remain the source of truth;
    `emailFailures` records provider errors but is not a retry queue.
12. **Handover token interception.** The plaintext QR token is bearer-style until
    it expires or is used. It is never persisted, is single-use, expires after 24
    hours, and every verification failure is audited. Display it only to the
    claimant; do not screenshot or share it.
13. **Service worker scope.** A compromised or malicious service worker could
    intercept same-origin requests. Only deploy `sw.js`/the FCM shim from this
    repository, keep them `no-cache`, and review any third-party script added to
    the cache list.
14. **Offline report queue.** Text-only reports wait in IndexedDB on the device.
    A shared device can reveal a queued report/contact until it is flushed;
    provide a clear-queue action and avoid offline reports on public machines.
15. **Push payload visibility.** Data-only FCM payloads can be displayed by the
    OS/service worker and should be treated as non-secret. Do not put private
    contact details or proof into a notification body.
