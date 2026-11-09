# Cloud Functions (Campus Connect)

These functions enforce the security properties that cannot be enforced in a
browser:

| Export | Type | Purpose |
| --- | --- | --- |
| `beforeUserCreated` | Blocking Auth | Reject non-college domains; force new accounts to `student`. |
| `beforeUserSignedIn` | Blocking Auth | Reject non-college domains, disabled, or suspended accounts. |
| `onUserCreated` | Auth trigger | Create the informational `users/{uid}` profile. |
| `setUserRole` | Callable (admin) | Write the authoritative `role` custom claim. |
| `setUserStatus` | Callable (admin) | Disable Auth, revoke tokens, set `suspended` claim. |
| `inviteUser` | Callable (admin) | Create an account and return a one-time reset link. |
| `revokeSessions` | Callable (self) | Revoke the caller's refresh tokens. |
| `deleteUserAccount` | Callable (admin) | Delete an account and owned data. |
| `deleteOwnAccount` | Callable (self) | Self-service deletion with recent re-auth. |
| `sendNotification` | Callable (admin) | Fan out a campus notification in batches. |
| `onItemWritten` | Firestore trigger | Audit item writes, clean up deleted items/photos. |
| `onClaimWritten` | Firestore trigger | Audit claims, notify reporters, clean up proofs. |
| `onUserWritten` | Firestore trigger | Audit profile changes. |

## Setup

```bash
cd functions
npm install
```

Environment variables (optional, no secrets):

```bash
ALLOWED_EMAIL_DOMAINS=campus.edu,student.campus.edu
```

The default is `campus.edu`. The frontend uses the same list for UX; the
blocking function is the authoritative check.

## Local emulators

From the repository root:

```bash
firebase emulators:start --only auth,firestore,storage,functions
```

The Auth emulator routes blocking functions to the Functions emulator. Create
local users with a `@campus.edu` address. Mark them verified in the Auth
emulator UI or via the Auth REST API before testing protected data.

## Deploy

```bash
firebase deploy --only functions
```

Blocking functions require the Blaze (pay-as-you-go) plan and Identity Platform
features enabled for the project. Verify them in the Firebase Console after
deployment. Functions use the project's default service account; do not commit
service-account keys.

## Notes

- The Admin SDK bypasses Security Rules. Every callable re-checks the caller's
  `role` custom claim and input.
- `setUserRole` and `setUserStatus` revoke refresh tokens. Existing ID tokens
  stay valid until expiry (up to one hour); this is documented in `SECURITY.md`.
- `inviteUser` cannot send SMTP mail. It returns a password-reset link that the
  administrator must share over a trusted channel.
