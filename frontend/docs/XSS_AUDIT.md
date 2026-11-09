# XSS Audit — Campus Connect

**Scope:** `public/index.html`, `public/login.html`, `public/assets/js/app.js`,
`public/assets/js/login.js`, `public/firebase-service.js`,
`public/firebase-config.js`, plus the CSP in `firebase.json`.

**Date:** 2026-11-05

**Result:** No direct HTML-injection sink was found that renders unescaped
remote data. All dynamic text passes through `escapeHtml()`, `textContent` or an
allowlisted URL/ID encoder. One defence-in-depth gap remains: the app still uses
inline `on*` event-handler attributes, which forces `script-src-attr
'unsafe-inline'` in the CSP. That is documented under [Residual risks](#residual-risks).

---

## 1. Threat model for this audit

Remote data is **untrusted** even when it was created by an authenticated user:

| Source | Attacker control | Notes |
| --- | --- | --- |
| `items/{id}` fields (`title`, `desc`, `location`, `category`, `custody*`, `reporterName`, `image`) | Any verified student via a crafted client | Rules bound length/type but not character content |
| `claims/{id}` fields (`itemTitle`, `claimantName`, `claimantEmail`) | Claimant | Read by staff UI |
| `complaints/{id}` fields | Reporter | Read by staff UI |
| `users/{id}` fields (`name`, `email`, `department`) | Self-service profile update | Read by admin UI |
| `metadata/categories`, `metadata/broadcast` | Admin only, still treated as data | Rendered on every board |
| `logs/{id}` (`text`) | Client logs are role-checked but content is caller-written | Admin UI |
| `notifications/{id}` (`text`) | Self/staff-written | Notification drawer |
| Photo URLs | Owner-supplied string | Rendered in `<img src>` |
| URL query string (`?view=`) | Anyone | Only compared to a literal |
| `localStorage` UI preferences | Anyone with local access | Only search/filter/theme-style prefs |
| Firebase Auth ID token (`role`, `email`, `name`) | Server-issued | Trusted for display, still escaped |

## 2. Output encoding helpers

`public/assets/js/app.js`:

```js
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
```

- Used for **all** remote text and for attribute values.
- Escapes both quote styles, so it is safe inside single- or double-quoted
  attributes as well as text nodes.
- `handlerArg(value)` = `escapeHtml(jsArg(value))`; `jsArg` percent-encodes the
  value and additionally encodes `'` and `"`, so a value cannot break out of the
  single-quoted JS string inside an `onclick` attribute.
- `safeDocId(id)` only allows `[A-Za-z0-9_-]{1,128}` before a document ID is
  interpolated into a handler.
- `safeImageUrl(url)` allows only:
  - `https://firebasestorage.googleapis.com`,
  - `https://*.firebasestorage.app`,
  - the configured Storage bucket host,
  - `http://localhost:9199` / `http://127.0.0.1:9199` for the emulator.
  Anything else (including `javascript:`, `data:`, `blob:` and arbitrary hosts)
  becomes an empty string, so it is never placed in `src`.

`safeImageUrl` returns `parsed.href`, which normalises the URL; the result is
still passed through `escapeHtml()` before insertion.

`public/assets/js/login.js` never writes HTML. It uses `textContent` for alert
and toast text and only ever assigns literal page URLs to `window.location.href`.

## 3. Sink inventory

### 3.1 HTML sinks in `app.js`

All `innerHTML` assignments are template literals built from **literals plus
already-escaped values**. The table lists the remote fields reaching each sink.

| Sink (approx. line) | Remote data rendered | Encoding |
| --- | --- | --- |
| Auth header (`282`, `291`) | `user.name`, `user.email` | `escapeHtml`; role label/class from a fixed map |
| Campus broadcast (`336`) | `metadata/broadcast.text` | `escapeHtml` |
| Category dropdowns (`438`–`445`, `1379`, `2200`) | category strings | `escapeHtml` in value and text |
| Board card (`502`–`558`) | title, category, location, custody location, date, image | `escapeHtml`; image via `safeImageUrl`; ID via `safeDocId` + `handlerArg` |
| Item detail (`688`–`705`) | title, category, location, description, reporter name, custody fields, date, status, image | `escapeHtml`; status class uses normalised literal |
| Claim review (`1127`–`1145`) | item title, claimant name/email, date | `escapeHtml`; claim ID via `safeDocId` + `handlerArg` |
| Dashboard user card (`1262`) | `user.name`, `user.email` | `escapeHtml`; role uppercase from claim |
| Dashboard tables (`1337`–`2169`) | item/claim/user/complaint/log fields | `escapeHtml`; IDs via safe ID encoder |
| Categories admin (`1822`–`1827`) | category name | `escapeHtml` in `data-category`; delete handler reads `this.dataset.category` |
| Complaints (`1856`–`1885`) | student name/email, subject, type, message, date, status | `escapeHtml`; status class from a fixed map |
| Analytics/locations (`1901`–`1958`) | counts only | numeric |
| Audit log (`2009`) | log text, date | `escapeHtml` |
| Search results (`2094`–`2112`, `2142`–`2171`) | item fields | `escapeHtml` |
| Notifications (`2617`–`2624`) | notification text, date | `escapeHtml` |

Numeric counters (`items.length`, `lostCount`, KPI values, category counts) are
computed locally and cannot carry markup.

### 3.2 Non-HTML sinks

| Sink | Use | Safety |
| --- | --- | --- |
| `textContent` (`app.js` 192, 264, 714, 717, 930–931, 1070, 1156–1159, 2370–2378; `login.js` 44–77) | Toasts, badges, private contact/proof, modal titles | Native text assignment; no parsing |
| `.value =` on form inputs (`app.js` 1205–1215, 2207–2220) | Populate edit forms | Property assignment, never HTML |
| `.src =` (`930`) | Local `URL.createObjectURL` preview of the file the user just chose | Blob URL created in-page; revoked after use |
| `window.location.href = "login.html"` / `"index.html"` | Navigation | Literal URLs only; `?view=dashboard` is compared to a literal, never used as a URL |
| `URLSearchParams` (`app.js` end) | `?view=dashboard` | Used only by `=== "dashboard"` |
| `link.href = URL.createObjectURL(blob)` (`2599`) | CSV download | Blob generated locally from escaped/derived data |
| `localStorage` | UI preferences + login cooldown | Never rendered as HTML; never used for authorization |

### 3.3 HTML pages

- `index.html` / `login.html` contain only static markup and static `on*`
  handlers plus external scripts/styles.
- No inline `<script>` blocks remain, so CSP `script-src 'self'` is effective
  against injected `<script>` elements.
- No `javascript:` URLs remain. Two former `javascript:void(0)` anchors now use
  `href="#"` with `return false` in the handler, so navigation is cancelled
  without relying on inline script execution.

## 4. Defence layers outside the code

`firebase.json` sends:

```text
default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none';
form-action 'self';
script-src 'self' https://www.gstatic.com https://www.google.com ...
script-src-attr 'unsafe-inline';
style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
img-src 'self' data: blob: https://firebasestorage.googleapis.com https://*.firebasestorage.app ...;
object-src 'none'; frame-ancestors 'none';
X-Content-Type-Options: nosniff
```

- `object-src 'none'` blocks plugin-based script execution.
- `base-uri 'self'` blocks `<base>` hijacking.
- `frame-ancestors 'none'` + `X-Frame-Options: DENY` block clickjacking.
- `form-action 'self'` prevents credential forms from posting off-site.
- `nosniff` stops MIME confusion on uploaded content.
- Uploaded photos are re-encoded to JPEG through a canvas (strips EXIF/GPS and
  any polyglot payload), then served from Firebase Storage with a fixed content
  type. They are only ever consumed by `<img>`.

## 5. Related injection checks

| Class | Check | Result |
| --- | --- | --- |
| DOM XSS | `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function` | Only the escaped `innerHTML` sinks above; no `eval`/`Function`/`document.write` |
| Attribute injection | remote values in `title`, `data-*`, `class` | `escapeHtml` on all remote values; class names come from fixed maps |
| URL injection | `href`, `src`, `location` | No remote `href`; `src` allowlisted by `safeImageUrl`; navigation literals only |
| CSS injection | `style` attributes | Static strings only; no remote value concatenated into `style` |
| CSV/formula injection | Audit CSV export | `csvCell` quotes, doubles quotes and prefixes `'` when a cell starts with `=`, `+`, `-`, `@`, tab or CR |
| Prototype pollution | `Object.assign`/spread from remote objects | Documents are treated as plain records; no recursive merge of user keys into prototypes |
| Stored XSS via logs | Client-written log text | Escaped on render; only admins read logs |
| Open redirect | `?next=`, `location` from query | No redirect target is read from the query string |

## 6. Residual risks

1. **Inline event handlers remain.** `onclick`, `onsubmit`, `oninput`, etc. are
   used throughout the UI, so the CSP keeps `script-src-attr 'unsafe-inline'`.
   Inline handlers are not a vulnerability by themselves, and every remote value
   placed inside one is encoded with `handlerArg` (plus `safeDocId`). However, if
   a future edit forgets to escape a value, an injected attribute could execute
   script. The recommended follow-up is to migrate handlers to
   `addEventListener` in `app.js` / `login.js`, then remove `script-src-attr
   'unsafe-inline'`.
2. **`style-src 'unsafe-inline'`** is required by existing inline `style="..."`
   attributes. This permits CSS injection but not script execution; no remote
   value is interpolated into a `style` attribute today.
3. **Third-party origins in `script-src`/`connect-src`** are required for the
   Firebase compat SDK and reCAPTCHA/Google sign-in. A compromise of those CDNs
   is outside this app's control; pinning SDK versions and Subresource Integrity
   for the gstatic scripts would reduce that risk.
4. **No Trusted Types enforcement.** Adding `require-trusted-types-for 'script'`
   would harden DOM sinks but requires converting every `innerHTML` assignment
   to a Trusted Types policy or DOM APIs. Tracked as a follow-up after the
   inline-handler migration.
5. **`data:`/`blob:` allowed in `img-src`.** The app only renders Firebase
   Storage URLs and local blob previews, but CSP permits data/blob images for
   previews. SVG data URLs are not used; keep it that way (SVG can contain
   script when navigated to directly).
6. **Email/display-name rendering.** Auth profile names are escaped. Names can
   contain bidi/control characters that spoof UI text but cannot execute script.
7. **CSV contents are still sensitive.** The export excludes private contact and
   proof data, but the downloaded file itself is unprotected. Treat it as
   confidential and store it accordingly.

## 7. Re-test checklist after UI changes

- [ ] `grep` for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`
      and confirm every interpolation is `escapeHtml`, a numeric value, or a
      fixed literal.
- [ ] `grep` for `on[a-z]+="` in `public/*.html` and confirm any argument is a
      literal or `handlerArg`.
- [ ] Create an item with title `<img src=x onerror=alert(1)>`, description and
      location containing `"><script>alert(1)</script>`, then view the board,
      detail modal, dashboard table, search results and audit CSV.
- [ ] Set an admin broadcast to `<svg onload=alert(1)>` and confirm it renders as
      text.
- [ ] Register with a display name containing quotes and angle brackets and
      check the header/dash card.
- [ ] Submit a claim proof containing HTML and confirm staff see literal text.
- [ ] Confirm DevTools shows the CSP response header and no CSP violations.
- [ ] Confirm a `javascript:` value in an item `image` field does not render an
      image (the card shows no `<img>`).
