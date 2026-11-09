#!/usr/bin/env node
"use strict";

/**
 * Generates the PWA PNG icons without any build tooling or external packages.
 * Run: node scripts/generate-pwa-icons.js
 *
 * The mark is a white map-pin on the brand brown background. Maskable icons
 * keep the mark inside the central safe zone so Android can crop them.
 */

const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

const OUT_DIR = path.join(__dirname, "..", "public", "assets", "icons");
const BACKGROUND = [139, 111, 71, 255];
const FOREGROUND = [255, 255, 255, 255];

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (let i = 0; i < buffer.length; i += 1) {
    crc = CRC_TABLE[(crc ^ buffer[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const typeBuffer = Buffer.from(type, "ascii");
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])), 0);
  return Buffer.concat([length, typeBuffer, data, crc]);
}

function encodePng(width, height, rgba) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y += 1) {
    raw[y * (stride + 1)] = 0;
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }
  const idat = zlib.deflateSync(raw, { level: 9 });
  return Buffer.concat([
    signature,
    chunk("IHDR", ihdr),
    chunk("IDAT", idat),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function render(size, maskable) {
  const scale = 4;
  const big = size * scale;
  const pixels = Buffer.alloc(big * big * 4);

  const contentScale = maskable ? 0.58 : 0.72;
  const cx = big / 2;
  const cy = big * (maskable ? 0.44 : 0.40);
  const outer = big * contentScale * 0.31;
  const inner = outer * 0.42;
  const tipY = cy + outer * 2.15;
  const shoulder = outer * 0.78;

  function setPixel(x, y, rgba) {
    const offset = (y * big + x) * 4;
    pixels[offset] = rgba[0];
    pixels[offset + 1] = rgba[1];
    pixels[offset + 2] = rgba[2];
    pixels[offset + 3] = rgba[3];
  }

  function inTriangle(px, py) {
    // Triangle from the circle shoulder to the pin tip.
    const ax = cx - shoulder;
    const ay = cy + outer * 0.15;
    const bx = cx + shoulder;
    const by = cy + outer * 0.15;
    const cxp = cx;
    const cyp = tipY;
    const d1 = (px - bx) * (ay - by) - (ax - bx) * (py - by);
    const d2 = (px - cxp) * (by - cyp) - (bx - cxp) * (py - cyp);
    const d3 = (px - ax) * (cyp - ay) - (cxp - ax) * (py - ay);
    const hasNeg = d1 < 0 || d2 < 0 || d3 < 0;
    const hasPos = d1 > 0 || d2 > 0 || d3 > 0;
    return !(hasNeg && hasPos);
  }

  for (let y = 0; y < big; y += 1) {
    for (let x = 0; x < big; x += 1) {
      setPixel(x, y, BACKGROUND);
      const dx = x - cx;
      const dy = y - cy;
      const distance = Math.sqrt(dx * dx + dy * dy);
      const inPin = distance <= outer || (y >= cy && inTriangle(x, y));
      if (inPin) {
        const inHole = distance <= inner;
        setPixel(x, y, inHole ? BACKGROUND : FOREGROUND);
      }
    }
  }

  // Box-downsample 4x for smooth edges.
  const out = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y += 1) {
    for (let x = 0; x < size; x += 1) {
      const sums = [0, 0, 0, 0];
      for (let sy = 0; sy < scale; sy += 1) {
        for (let sx = 0; sx < scale; sx += 1) {
          const offset = ((y * scale + sy) * big + (x * scale + sx)) * 4;
          for (let channel = 0; channel < 4; channel += 1) {
            sums[channel] += pixels[offset + channel];
          }
        }
      }
      const outOffset = (y * size + x) * 4;
      for (let channel = 0; channel < 4; channel += 1) {
        out[outOffset + channel] = Math.round(sums[channel] / (scale * scale));
      }
    }
  }
  return out;
}

fs.mkdirSync(OUT_DIR, { recursive: true });

const outputs = [
  ["icon-192.png", 192, false],
  ["icon-512.png", 512, false],
  ["maskable-512.png", 512, true],
  ["apple-touch-icon-180.png", 180, false],
];

outputs.forEach(([name, size, maskable]) => {
  const png = encodePng(size, size, render(size, maskable));
  fs.writeFileSync(path.join(OUT_DIR, name), png);
  console.log(`wrote ${name} (${size}x${size}, ${png.length} bytes)`);
});
