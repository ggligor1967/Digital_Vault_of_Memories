/**
 * Generates the 1024x1024 source PNG that `pnpm tauri icon` rasterises into
 * the application icon set.
 *
 * Committed so the icon set is reproducible from source rather than being an
 * opaque binary nobody can regenerate. It is not part of the build: the icons
 * under `apps/desktop/src-tauri/icons/` are committed, and this script is only
 * re-run when the mark itself changes.
 *
 *   node scripts/generate-source-icon.mjs <output.png>
 *   pnpm exec tauri icon <output.png> -o apps/desktop/src-tauri/icons
 *
 * Pure Node, no image dependency: raw RGBA scanlines -> zlib -> PNG chunks.
 */
import { deflateSync } from 'node:zlib';
import { writeFileSync } from 'node:fs';

const SIZE = 1024;

const crcTable = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

// --- draw -----------------------------------------------------------------
const px = Buffer.alloc(SIZE * SIZE * 4, 0);

const set = (x, y, [r, g, b, a]) => {
  if (x < 0 || y < 0 || x >= SIZE || y >= SIZE) return;
  const i = (y * SIZE + x) * 4;
  const sa = a / 255;
  px[i] = Math.round(px[i] * (1 - sa) + r * sa);
  px[i + 1] = Math.round(px[i + 1] * (1 - sa) + g * sa);
  px[i + 2] = Math.round(px[i + 2] * (1 - sa) + b * sa);
  px[i + 3] = Math.max(px[i + 3], a);
};

const NAVY = [23, 30, 56, 255];
const STEEL = [143, 176, 255, 255];
const PALE = [226, 234, 255, 255];

// Coverage-based antialiasing: sample each pixel on a 3x3 grid.
function fill(test, colour) {
  for (let y = 0; y < SIZE; y++) {
    for (let x = 0; x < SIZE; x++) {
      let hits = 0;
      for (let sy = 0; sy < 3; sy++) {
        for (let sx = 0; sx < 3; sx++) {
          if (test(x + (sx + 0.5) / 3, y + (sy + 0.5) / 3)) hits++;
        }
      }
      if (hits > 0)
        set(x, y, [colour[0], colour[1], colour[2], Math.round((hits / 9) * colour[3])]);
    }
  }
}

const C = SIZE / 2;
// Signed distance to a rounded box, evaluated at (x, y). Inside when <= 0.
const roundedSquare = (x, y, half, radius) => {
  const qx = Math.abs(x - C) - half + radius;
  const qy = Math.abs(y - C) - half + radius;
  const outside = Math.hypot(Math.max(qx, 0), Math.max(qy, 0));
  const inside = Math.min(Math.max(qx, qy), 0);
  return outside + inside - radius <= 0;
};
const ring = (x, y, rOuter, rInner) => {
  const d = Math.hypot(x - C, y - C);
  return d <= rOuter && d >= rInner;
};

// Vault door: rounded plate, an outer ring, and four spokes on a hub.
fill((x, y) => roundedSquare(x, y, 460, 150), NAVY);
fill((x, y) => ring(x, y, 330, 292), STEEL);
fill((x, y) => Math.hypot(x - C, y - C) <= 96, PALE);

for (const angle of [0, 90, 180, 270]) {
  const rad = (angle * Math.PI) / 180;
  const ux = Math.cos(rad);
  const uy = Math.sin(rad);
  fill((x, y) => {
    const dx = x - C;
    const dy = y - C;
    const along = dx * ux + dy * uy;
    const across = -dx * uy + dy * ux;
    return along >= 70 && along <= 300 && Math.abs(across) <= 26;
  }, STEEL);
}

// --- encode ---------------------------------------------------------------
const raw = Buffer.alloc(SIZE * (SIZE * 4 + 1));
for (let y = 0; y < SIZE; y++) {
  raw[y * (SIZE * 4 + 1)] = 0; // filter: none
  px.copy(raw, y * (SIZE * 4 + 1) + 1, y * SIZE * 4, (y + 1) * SIZE * 4);
}

const ihdr = Buffer.alloc(13);
ihdr.writeUInt32BE(SIZE, 0);
ihdr.writeUInt32BE(SIZE, 4);
ihdr[8] = 8; // bit depth
ihdr[9] = 6; // colour type: RGBA
ihdr[10] = 0;
ihdr[11] = 0;
ihdr[12] = 0;

const png = Buffer.concat([
  Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
  chunk('IHDR', ihdr),
  chunk('IDAT', deflateSync(raw, { level: 9 })),
  chunk('IEND', Buffer.alloc(0)),
]);

writeFileSync(process.argv[2], png);
console.log(`wrote ${process.argv[2]} (${png.length} bytes)`);
