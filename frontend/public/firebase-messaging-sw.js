/*
 * Compatibility shim for Firebase Messaging.
 *
 * The real PWA + FCM worker is /sw.js and is the only worker this app
 * registers. This file exists for older SDKs/tools that request the default
 * /firebase-messaging-sw.js path; it intentionally just imports the root
 * worker so there is a single source of push/notification logic.
 */
importScripts("/sw.js");
