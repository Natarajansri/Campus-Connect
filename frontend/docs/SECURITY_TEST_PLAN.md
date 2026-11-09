# Security Test Plan — Campus Connect

This document covers the automated rules suite and the manual checks that need a
real browser / Firebase project. Run everything against the Emulator Suite first.

---

## 1. Automated tests

```bash
npm install
npm run lint
npm test
# or individually:
npm run test:rules
npm run test:functions
```

`npm test` runs both suites against the Emulator Suite for the
`demo-campusconnect` project:

1. **Rules** — starts Firestore (8080) + Storage (9199), deploys
   [`firestore.rules`](../firestore.rules) / [`storage.rules`](../storage.rules),
   and runs [`tests/rules/security.rules.test.js`](../tests/rules/security.rules.test.js).
2. **Functions** — starts Firestore on port 8081 (via
   `firebase.functions-test.json`, so it does not collide with the rules
   emulator's lingering 8080 process on Windows) and runs
   [`tests/functions/level2.functions.test.js`](../tests/functions/level2.functions.test.js).
   The suite calls v2 `.run()` entry points directly with synthetic auth
   requests; it never needs real FCM or Resend credentials.

**Last verified:** rules **70 passed, 0 failed**; Functions **22 passed,
0 failed** (2026-11-05).

### Coverage matrix

| Area | Tests |
| --- | --- |
| Session claims | unauthenticated read denied; unverified denied; suspended denied; verified read allowed; owner can read own pending item |
| Items | validated pending create + atomic private contact; cannot create approved/pinned/staff-verified/forged-reporter item; owner edit allowed; **owner cannot self-approve**; owner can return/reopen; owner cannot reassign/pin; staff approve; student cannot moderate; staff cannot change owner/createdAt; owner/admin delete, other student denied |
| Private contact | owner read; other student denied; staff read/update; reporter UID immutable |
| Claims | valid claim + proof batch; self-claim denied; pending-item claim denied; claimant/staff read; proof private; staff resolve, student denied; resolved claims immutable; **staff cannot resolve directly to `returned`**; admin delete |
| Users/roles | self-create student only; cannot self-provision admin/suspended; name/department self-update; role/status immutable; admin read; admin name-only edit; client delete denied |
| Notifications | self-notify allowed; cross-user notify denied for students; staff moderation notice allowed; recipient read flag only; recipient delete; same-origin URL required |
| Devices/prefs | owner-only device read/write; cannot register for another account; invalid platform/short token/extra fields denied; token rotation/disable/delete; valid preference map; unknown keys/non-booleans denied |
| Chats | participants + staff read; outsiders/unauthenticated denied; clients cannot create/edit/delete chats; direct message writes denied; own read marker only |
| Moderation/receipts | reporter + staff read reports; clients cannot create/delete; staff review only; receipts readable by parties + staff, never writable |
| Handover secrecy | `claims/{id}/private/handover` unreadable by claimant, staff and admin; client write denied |
| Server bookkeeping | `rateLimits`, `emailUsage`, `emailFailures` deny all client access; admin can read failures but not write |
| Complaints | own complaint create; forged reporter denied; reporter/staff read; staff status update; student update denied |
| Metadata & logs | verified read; admin-only write; client log role must match token; append-only; admin-only read |
| Storage | owner JPEG upload; unverified/suspended denied; cross-folder denied; bad type/name denied; >3 MB denied; verified read only; owner/admin delete |
| Functions: helpers | preference defaults/normalization; channel/event switches; string/id validation |
| Functions: email | HTML escaping; unknown event; signed token round-trip/tamper/expiry; preference opt-out; missing profile; missing provider logging; fan-out dedupe |
| Functions: chat | deterministic creation after approval; pending/unrelated denial; callable-only send; closed-chat denial; 11th message rate limit; moderation without text copy |
| Functions: QR | 128-bit+ token; hash-only storage; claimant-only issue; pending denial; atomic return/receipt; single-use; malformed/student denial |

### Interpreting failures

- `PERMISSION_DENIED` on an `assertSucceeds` case means a legitimate flow is
  blocked — check the rules and the exact payload fields.
- A passing `assertFails` with an “evaluation error” is expected for malformed
  data; the rule denied the write. Only investigate if an `assertSucceeds` case
  reports an evaluation error.
- A Functions failure usually means a guard, transaction or rate-limit counter
  changed shape. Read the `assert` message; it names the expected code or field.
- If ports 8080/9199 are busy, stop the previous emulator (on Windows a stale
  `java.exe` may hold port 8080) and re-run.

---

## 2. Manual emulator checks

Start the full stack:

```bash
npm run serve
```

Use `http://localhost:5000` and `http://localhost:4000` (Emulator UI).

### 2.1 Account and session

| # | Step | Expected |
| --- | --- | --- |
| A1 | Open `index.html` signed out | Redirect to `login.html` |
| A2 | Sign up with an off-domain email (e.g. `x@gmail.com`) | Rejected by the blocking function / client domain check |
| A3 | Sign up with `@campus.edu` | Account created, verification email attempt, signed out |
| A4 | Mark the user verified in Auth emulator UI, sign in | Board loads; student role |
| A5 | Sign in with a wrong password repeatedly | Generic “Invalid credentials”; cooldown after 5 failures |
| A6 | Use “Forgot password?” for an unknown address | Same generic success message (no enumeration) |
| A7 | Leave the page idle (or shorten timers for testing) | Warning, then redirect to login; session cleared |

### 2.2 Student item lifecycle

| # | Step | Expected |
| --- | --- | --- |
| S1 | Submit a lost item with a photo | Upload succeeds; item is `pending`; not on public board |
| S2 | Submit without a photo | Allowed; item is `pending` |
| S3 | Upload a >10 MB or non-image file | Rejected client-side before upload |
| S4 | Temporarily break Storage rules / network for upload | Submission aborts with a clear error; no base64 fallback |
| S5 | Edit own pending item | Title/category/location/description update; role/status unchanged |
| S6 | Try to approve own item via browser console | Rules deny (`PERMISSION_DENIED`) |
| S7 | Mark an approved item returned, then reopen | Status cycles `returned` → `approved`; board updates |
| S8 | Delete own item | Item and private contact/photo removed (trigger or rules) |

### 2.3 Faculty/staff moderation

| # | Step | Expected |
| --- | --- | --- |
| F1 | Sign in as faculty (claim set by `setUserRole`) | Staff dashboard, pending queue |
| F2 | Approve a pending item | Item becomes public; reporter gets a notification |
| F3 | Reject a pending item | Item stays hidden; reporter notification |
| F4 | Set custody details | Only staff update path succeeds; public board shows custody info |
| F5 | Open a claim review | Private proof loads; other students can never read it |
| F6 | Approve a claim | Claim `approved`; item becomes `claimed`; audit log written |
| F7 | Reject a claim | Claim `rejected`; no item status change |
| F8 | Try to change a user role from the browser | Rules deny; only admin callable succeeds |

### 2.4 Admin

| # | Step | Expected |
| --- | --- | --- |
| AD1 | `make-admin.js --apply` for an account, then sign in again | Admin dashboard and user directory visible |
| AD2 | Change a role with recent re-auth | Claim + profile updated; target must re-authenticate/refresh |
| AD3 | Suspend a user | Auth disabled, refresh tokens revoked, `suspended` claim set; user is signed out on next refresh |
| AD4 | Invite a new user | Account created; one-time reset link returned for secure sharing; no password in UI |
| AD5 | Delete a user | Auth + owned Firestore/Storage data removed; audit retained |
| AD6 | Broadcast a notice | `metadata/broadcast` updated; all users see escaped banner text |
| AD7 | Edit categories | Admin-only write; students see updated list |
| AD8 | Export audit log / view logs | Admin-readable; client logs cannot be edited/deleted |
| AD9 | Try to delete own admin account as the last admin | Callable refuses |

### 2.5 Direct API probes (negative tests)

Use the browser console while signed in (or the Emulator UI request editor):

```js
// 1. Read another user's pending item — should fail.
firebase.firestore().collection('items').where('status', '==', 'pending').get();

// 2. Self-approve an item you own — should fail.
firebase.firestore().collection('items').doc('YOUR_ITEM').update({
  status: 'approved', updatedBy: firebase.auth().currentUser.uid
});

// 3. Write a role into your own profile — should fail.
firebase.firestore().collection('users').doc(firebase.auth().currentUser.uid).update({ role: 'admin' });

// 4. Read another user's private claim proof — should fail.
firebase.firestore().collection('claims').doc('OTHER_CLAIM').collection('private').doc('proof').get();

// 5. Read another user's notification — should fail.
firebase.firestore().collection('notifications').where('toUid', '==', 'OTHER_UID').get();

// 6. Upload to another user's Storage folder — should fail.
firebase.storage().ref('items/OTHER_UID/photo.jpg').put(new Blob(['x'], { type: 'image/jpeg' }));

// 7. Write a chat message directly — should fail (callable only).
firebase.firestore().collection('chats').doc('CHAT_ID').collection('messages').add({
  senderUid: firebase.auth().currentUser.uid, text: 'forged'
});

// 8. Read another user's FCM device token — should fail.
firebase.firestore().collection('users').doc('OTHER_UID').collection('devices').get();

// 9. Read a handover hash — should fail even for staff/admin.
firebase.firestore().collection('claims').doc('CLAIM_ID').collection('private').doc('handover').get();

// 10. Write your own return receipt — should fail.
firebase.firestore().collection('receipts').doc('CLAIM_ID').set({ returnedAt: new Date() });
```

Every probe should produce `permission-denied` / `storage/unauthorized`. A success
is a release blocker.

### 2.6 Push and email notifications

| # | Step | Expected |
| --- | --- | --- |
| N1 | Open Notification Settings and click “Enable push” | Browser permission prompt appears; token saved under `users/{uid}/devices` |
| N2 | Deny permission, then retry | Clear explanation; no token saved; no repeated prompt on load |
| N3 | Trigger a claim/chat event with push enabled | Foreground toast or background notification; deep link opens the same-origin target |
| N4 | Open one notification | Only that notification becomes read; unread badge decrements |
| N5 | Press “Mark all read” | All visible notifications become read |
| N6 | Disable a category in Notification Settings, then trigger it | Push/email for that category is skipped |
| N7 | Send a test claim email | HTML and plain text arrive; no other user's contact/proof appears |
| N8 | Open the unsubscribe link, then send another non-security email | Confirmation page; email is disabled in settings |
| N9 | Tamper with the unsubscribe token | 400 page; no settings change |
| N10 | Send more than `EMAIL_DAILY_CAP` emails in a UTC day | Further sends are skipped and no duplicate arrives |

### 2.7 Secure chat

| # | Step | Expected |
| --- | --- | --- |
| C1 | Approve a claim and open chat as claimant/reporter | Deterministic chat `{itemId}_{claimantUid}`; both see real-time messages |
| C2 | Sign in as an unrelated student and open the same chat ID | Read denied |
| C3 | Send a message with HTML/emoji/long text | Rendered as text (escaped); length limited |
| C4 | Send 11 messages within a minute | 11th rejected with a rate-limit message |
| C5 | Report a message | Moderation record created; reporter and staff can read it; message text is not copied |
| C6 | Sign in as staff (not a participant) | Chat is readable but the composer is read-only |
| C7 | Reject the claim or return the item | Chat auto-closes; further sends are rejected |

### 2.8 QR handover and receipt

| # | Step | Expected |
| --- | --- | --- |
| Q1 | Approve a claim and open “Handover code” | QR + copyable `CC1.` token; token is not stored in Firestore plaintext |
| Q2 | Scan with staff camera (or paste token) | Success receipt; claim and item become `returned`; chat closes |
| Q3 | Reuse the same token | Rejected as invalid/expired/used; no state change |
| Q4 | Open the handover document from the client (including admin) | Read denied |
| Q5 | Submit a token as a student | Permission denied |
| Q6 | Revoke camera permission, then use manual entry | Manual verification still works |
| Q7 | Re-issue a token before use | Previous token stops working; new token succeeds |
| Q8 | Open the receipt as claimant/reporter, then as an outsider | Parties + staff can read; outsider denied; no client can edit |

### 2.9 PWA, service worker and offline queue

| # | Step | Expected |
| --- | --- | --- |
| P1 | Install the app (desktop/Android) or use iOS “Add to Home Screen” | Icon, name and theme colour are correct |
| P2 | Go offline | Offline banner appears; queued-report count is shown |
| P3 | Submit a text-only report offline | Queued in IndexedDB; flushes automatically when back online |
| P4 | Submit a report with a photo offline | Refused with a clear message; nothing silently dropped |
| P5 | DevTools → Application → Cache Storage | Only the app shell/static assets; no Firestore/Auth/Storage responses |
| P6 | Reload after a deploy | HTML is network-first; shell updates; `/sw.js` is revalidated |
| P7 | Check response headers for `/sw.js`, `firebase-messaging-sw.js`, manifest | `no-cache` for workers; manifest `application/manifest+json` |
| P8 | Run Lighthouse (if installed) | PWA/performance report recorded; CLI absent in this environment |

---

## 3. Production verification (after deploy)

1. Confirm the hosted pages send the expected CSP/HSTS/nosniff headers
   (browser DevTools → Network → response headers).
2. Confirm an unauthenticated `GET` to a Storage object URL is denied.
3. Confirm App Check is enforced (requests without a token fail in a clean
   browser profile).
4. Confirm role changes require a fresh token (sign out/in) and that a suspended
   user cannot sign in.
5. Confirm password reset / verification emails arrive and links point at the
   production domain.
6. Confirm Cloud Logging shows function errors, and alerting is configured.
7. Run the direct API probes from §2.5 against a disposable test account.
8. Confirm `RESEND_API_KEY` and `EMAIL_UNSUB_SECRET` are Secret Manager secrets
   and that no secret value appears in the hosting bundle or repository.
9. Confirm push works on HTTPS, the VAPID key is not a placeholder, and an
   invalid/rotated device token is cleaned up.
10. Confirm the unsubscribe link works without a session, then stop working after
    expiry or secret rotation.
11. Confirm `/sw.js`, `firebase-messaging-sw.js` and the manifest return the
    expected cache/MIME headers, and that Cache Storage contains no authenticated
    data.
12. Confirm `camera=(self)` is the only enabled Permissions Policy capability and
    that QR scanning still works over HTTPS.

---

## 4. Known gaps

- No automated browser E2E suite; the UI checks above are manual.
- Functions are covered by the emulator suite, but FCM/Resend delivery to a real
  device/inbox is not automated. Use a disposable account for live checks.
- Lighthouse is not installed in this environment, so no automated PWA/Lighthouse
  report is committed.
- App Check, API key restrictions, MFA, IAM, Resend domain verification, the VAPID
  key and Cloud Scheduler are console/account settings and must be re-verified
  after project or domain changes.
- Chat retention and any institutional data-retention requirement are policy
  decisions not enforced by code.
