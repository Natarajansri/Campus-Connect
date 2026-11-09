/*
 * Campus Connect root service worker.
 *
 * Responsibilities:
 *   1. App-shell precache + safe runtime caching for same-origin static files.
 *   2. Network-first HTML so a new deploy is picked up immediately.
 *   3. Firebase Cloud Messaging background messages and notification clicks.
 *
 * It deliberately never caches cross-origin Firebase/Auth/Storage traffic,
 * requests with an Authorization header, or anything under /__/ (Firebase Auth
 * helper endpoints). Authenticated data is always fetched live by the page.
 */

const CACHE_VERSION = "campusconnect-v10";
const APP_SHELL = [
  "/",
  "/index.html",
  "/login.html",
  "/manifest.webmanifest",
  "/firebase-config.js?v=live10",
  "/firebase-service.js?v=live10",
  "/assets/css/styles.css?v=live10",
  "/assets/css/login.css?v=live10",
  "/assets/js/app.js?v=live10",
  "/assets/js/login.js?v=live10",
  "/assets/icons/icon-192.png",
  "/assets/icons/icon-512.png",
  "/assets/icons/maskable-512.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_VERSION)
      .then((cache) => cache.addAll(APP_SHELL))
      .catch((error) => console.warn("App-shell precache failed:", error.message))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((key) => key.startsWith("campusconnect-") && key !== CACHE_VERSION)
            .map((key) => caches.delete(key))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener("message", (event) => {
  if (event.data && event.data.type === "SKIP_WAITING") {
    self.skipWaiting();
  }
});

function isCacheableAsset(request, url) {
  if (request.method !== "GET") return false;
  if (url.origin !== self.location.origin) return false;
  if (url.pathname.startsWith("/__/")) return false;
  if (url.pathname === "/firebase-config.js" || url.pathname === "/firebase-service.js") return false;
  if (request.headers.has("Authorization")) return false;
  const destination = request.destination;
  return ["script", "style", "font", "image", "manifest"].includes(destination) ||
    /\.(?:css|js|png|svg|webp|woff2?|webmanifest)$/i.test(url.pathname);
}

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);

  // Never intercept Firebase/Google cross-origin traffic.
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/__/")) return;
  if (request.method !== "GET") return;
  if (request.headers.has("Authorization")) return;

  // Network-first for navigations: users get the current HTML shell, and the
  // cached shell is only an offline fallback.
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response && response.ok) {
            const copy = response.clone();
            caches.open(CACHE_VERSION).then((cache) => cache.put(request, copy)).catch(() => {});
          }
          return response;
        })
        .catch(async () => {
          const cached = await caches.match(request);
          return cached || caches.match("/index.html") || caches.match("/");
        })
    );
    return;
  }

  if (!isCacheableAsset(request, url)) return;

  // Stale-while-revalidate for static, public assets.
  event.respondWith(
    caches.match(request).then((cached) => {
      const network = fetch(request)
        .then((response) => {
          if (response && response.ok) {
            const copy = response.clone();
            caches.open(CACHE_VERSION).then((cache) => cache.put(request, copy)).catch(() => {});
          }
          return response;
        })
        .catch(() => cached);
      return cached || network;
    })
  );
});

/* ------------------------------------------------------------------------- *
 * Firebase Cloud Messaging (background)
 * ------------------------------------------------------------------------- */

try {
  importScripts("https://www.gstatic.com/firebasejs/10.8.0/firebase-app-compat.js");
  importScripts("https://www.gstatic.com/firebasejs/10.8.0/firebase-messaging-compat.js");
  importScripts("/firebase-config.js");

  if (
    self.CAMPUS_FIREBASE_CONFIG &&
    typeof firebase !== "undefined" &&
    firebase.apps &&
    !firebase.apps.length
  ) {
    firebase.initializeApp(self.CAMPUS_FIREBASE_CONFIG);
    const messaging = firebase.messaging();
    messaging.onBackgroundMessage((payload) => {
      const data = (payload && payload.data) || {};
      const title = String(data.title || "Campus Connect").slice(0, 80);
      const body = String(data.body || "You have a new update.").slice(0, 180);
      const url = typeof data.url === "string" && data.url.startsWith("/") && !data.url.startsWith("//")
        ? data.url
        : "/index.html?view=dashboard";
      self.registration.showNotification(title, {
        body,
        icon: "/assets/icons/icon-192.png",
        badge: "/assets/icons/icon-192.png",
        tag: data.notifId ? String(data.notifId).slice(0, 120) : undefined,
        data: { url }
      });
    });
  }
} catch (error) {
  console.warn("Firebase messaging is unavailable in the service worker:", error.message);
}

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const raw = event.notification && event.notification.data && event.notification.data.url;
  const path = typeof raw === "string" && raw.startsWith("/") && !raw.startsWith("//")
    ? raw
    : "/index.html?view=dashboard";
  const targetUrl = new URL(path, self.location.origin).href;

  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if (client.url === targetUrl && "focus" in client) return client.focus();
      }
      for (const client of clients) {
        if (new URL(client.url).origin === self.location.origin && "navigate" in client) {
          return client.navigate(targetUrl).then((navigated) => navigated && navigated.focus && navigated.focus());
        }
      }
      return self.clients.openWindow(targetUrl);
    })
  );
});
