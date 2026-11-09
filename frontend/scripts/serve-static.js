"use strict";

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const PORT = parseInt(process.env.PORT, 10) || 5000;
const PUBLIC_DIR = path.resolve(__dirname, "..", "public");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".webmanifest": "application/manifest+json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".txt": "text/plain; charset=utf-8"
};

const SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Cross-Origin-Opener-Policy": "same-origin-allow-popups",
  "Permissions-Policy": "camera=(self), microphone=(), geolocation=(), payment=(), usb=()"
};

const server = http.createServer((req, res) => {
  // Only handle GET and HEAD
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { "Content-Type": "text/plain" });
    res.end("Method Not Allowed");
    return;
  }

  // Parse path
  const parsedUrl = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  let pathname = decodeURIComponent(parsedUrl.pathname);

  // Default to index.html for root
  if (pathname === "/") {
    pathname = "/index.html";
  }

  let filePath = path.join(PUBLIC_DIR, pathname);

  // Prevent path traversal
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end("Forbidden");
    return;
  }

  // Check if file exists, or if clean URL maps to .html
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    if (fs.existsSync(filePath + ".html")) {
      filePath = filePath + ".html";
    } else if (fs.existsSync(path.join(filePath, "index.html"))) {
      filePath = path.join(filePath, "index.html");
    } else {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not Found: " + pathname);
      return;
    }
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || "application/octet-stream";

  const headers = {
    ...SECURITY_HEADERS,
    "Content-Type": contentType
  };

  // Cache settings
  if (ext === ".html" || pathname.includes("firebase-config") || pathname.includes("firebase-service")) {
    headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
  } else if (pathname === "/sw.js" || pathname === "/firebase-messaging-sw.js") {
    headers["Cache-Control"] = "no-cache, no-store, must-revalidate";
    headers["Service-Worker-Allowed"] = "/";
  } else {
    headers["Cache-Control"] = "public, max-age=86400";
  }

  try {
    const data = fs.readFileSync(filePath);
    res.writeHead(200, headers);
    if (req.method === "HEAD") {
      res.end();
    } else {
      res.end(data);
    }
  } catch (err) {
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("Internal Server Error: " + err.message);
  }
});

server.listen(PORT, "0.0.0.0", () => {
  console.log("=================================================");
  console.log("  Campus Connect — Live Static Server");
  console.log("=================================================");
  console.log(`  Local URL:        http://localhost:${PORT}`);
  console.log(`  Login Portal:     http://localhost:${PORT}/login`);
  console.log(`  Backend:          Google Firebase Cloud`);
  console.log(`  Project ID:       campusconnect-bc130`);
  console.log("=================================================");
});
