"use strict";

/**
 * Campus Connect Cloud Functions entry point.
 *
 * Exports are split by concern:
 *   auth.js        — blocking sign-up/sign-in checks + profile creation
 *   admin.js       — privileged callables (roles, suspension, invites, deletion)
 *   triggers.js    — authoritative audit trail, notifications, private cleanup
 *   notifications.js — FCM fan-out + invalid-token cleanup
 *   email.js       — Resend delivery, templates, signed unsubscribe endpoint
 *   chat.js        — deterministic chats, callable-only messages, moderation
 *   handover.js    — hashed single-use QR tokens + atomic verification
 *   scheduler.js   — weekly digest + stale-claim reminders
 */

module.exports = {
  ...require("./auth"),
  ...require("./admin"),
  ...require("./triggers"),
  ...require("./notifications"),
  ...require("./email"),
  ...require("./chat"),
  ...require("./handover"),
  ...require("./scheduler"),
};
