/**
 * Dependency-free app icon generator.
 * Generates PNG, ICO, and SVG assets for the intranet secure transfer desktop app.
 */

const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const ASSET_DIR = path.join(__dirname, 'assets');
const MAC_ICONSET_DIR = path.join(ASSET_DIR, 'icon.iconset');

function rgba(hex, alpha = 255) {
  const normalized = hex.replace('#', '');
  return [
    Number.parseInt(normalized.slice(0, 2), 16),
    Number.parseInt(normalized.slice(2, 4), 16),
    Number.parseInt(normalized.slice(4, 6), 16),
    alpha,
  ];
}

function createSurface(size) {
  const data = Buffer.alloc(size * size * 4, 0);

  function blendPixel(x, y, color) {
    if (x < 0 || y < 0 || x >= size || y >= size) return;
    const offset = (y * size + x) * 4;
    const srcAlpha = color[3] / 255;
    const dstAlpha = data[offset + 3] / 255;
    const outAlpha = srcAlpha + dstAlpha * (1 - srcAlpha);
    if (outAlpha === 0) return;

    data[offset] = Math.round((color[0] * srcAlpha + data[offset] * dstAlpha * (1 - srcAlpha)) / outAlpha);
    data[offset + 1] = Math.round((color[1] * srcAlpha + data[offset + 1] * dstAlpha * (1 - srcAlpha)) / outAlpha);
    data[offset + 2] = Math.round((color[2] * srcAlpha + data[offset + 2] * dstAlpha * (1 - srcAlpha)) / outAlpha);
    data[offset + 3] = Math.round(outAlpha * 255);
  }

  function rect(x, y, w, h, color) {
    for (let yy = Math.max(0, y); yy < Math.min(size, y + h); yy++) {
      for (let xx = Math.max(0, x); xx < Math.min(size, x + w); xx++) {
        blendPixel(xx, yy, color);
      }
    }
  }

  function roundedRect(x, y, w, h, r, color) {
    for (let yy = y; yy < y + h; yy++) {
      for (let xx = x; xx < x + w; xx++) {
        const dx = xx < x + r ? x + r - xx : xx >= x + w - r ? xx - (x + w - r - 1) : 0;
        const dy = yy < y + r ? y + r - yy : yy >= y + h - r ? yy - (y + h - r - 1) : 0;
        if (dx * dx + dy * dy <= r * r) blendPixel(xx, yy, color);
      }
    }
  }

  function circle(cx, cy, radius, color) {
    const r2 = radius * radius;
    for (let yy = Math.floor(cy - radius); yy <= Math.ceil(cy + radius); yy++) {
      for (let xx = Math.floor(cx - radius); xx <= Math.ceil(cx + radius); xx++) {
        const dx = xx - cx;
        const dy = yy - cy;
        if (dx * dx + dy * dy <= r2) blendPixel(xx, yy, color);
      }
    }
  }

  function thickLine(x1, y1, x2, y2, width, color) {
    const minX = Math.floor(Math.min(x1, x2) - width);
    const maxX = Math.ceil(Math.max(x1, x2) + width);
    const minY = Math.floor(Math.min(y1, y2) - width);
    const maxY = Math.ceil(Math.max(y1, y2) + width);
    const dx = x2 - x1;
    const dy = y2 - y1;
    const len2 = dx * dx + dy * dy || 1;
    const radius = width / 2;

    for (let y = minY; y <= maxY; y++) {
      for (let x = minX; x <= maxX; x++) {
        const t = Math.max(0, Math.min(1, ((x - x1) * dx + (y - y1) * dy) / len2));
        const px = x1 + t * dx;
        const py = y1 + t * dy;
        const dist2 = (x - px) ** 2 + (y - py) ** 2;
        if (dist2 <= radius * radius) blendPixel(x, y, color);
      }
    }
  }

  function polygon(points, color) {
    const xs = points.map(point => point[0]);
    const ys = points.map(point => point[1]);
    const minX = Math.floor(Math.min(...xs));
    const maxX = Math.ceil(Math.max(...xs));
    const minY = Math.floor(Math.min(...ys));
    const maxY = Math.ceil(Math.max(...ys));

    for (let y = minY; y <= maxY; y++) {
      for (let x = minX; x <= maxX; x++) {
        let inside = false;
        for (let i = 0, j = points.length - 1; i < points.length; j = i++) {
          const [xi, yi] = points[i];
          const [xj, yj] = points[j];
          const intersect = ((yi > y) !== (yj > y)) && (x < ((xj - xi) * (y - yi)) / (yj - yi) + xi);
          if (intersect) inside = !inside;
        }
        if (inside) blendPixel(x, y, color);
      }
    }
  }

  return { data, rect, roundedRect, circle, thickLine, polygon };
}

function makePng(size) {
  const surface = createSurface(size);
  const s = value => Math.round((value / 512) * size);
  const colors = {
    bg: rgba('#0b1020'),
    bg2: rgba('#121a2e'),
    stroke: rgba('#d8f3ff'),
    cyan: rgba('#35d2ff'),
    green: rgba('#55f29d'),
    amber: rgba('#ffcf5a'),
    shadow: rgba('#000000', 80),
  };

  surface.roundedRect(s(28), s(28), s(456), s(456), s(96), colors.bg);
  surface.roundedRect(s(48), s(48), s(416), s(416), s(76), colors.bg2);
  surface.thickLine(s(92), s(406), s(420), s(406), s(18), colors.shadow);

  for (const x of [118, 168, 344, 394]) {
    surface.circle(s(x), s(146), s(18), colors.cyan);
    surface.thickLine(s(x), s(164), s(x), s(214), s(9), colors.cyan);
  }
  surface.thickLine(s(118), s(214), s(394), s(214), s(13), colors.cyan);

  surface.thickLine(s(84), s(304), s(194), s(304), s(20), colors.cyan);
  surface.polygon([[s(194), s(268)], [s(250), s(304)], [s(194), s(340)]], colors.cyan);
  surface.thickLine(s(428), s(304), s(318), s(304), s(20), colors.cyan);
  surface.polygon([[s(318), s(268)], [s(262), s(304)], [s(318), s(340)]], colors.cyan);

  surface.polygon(
    [[s(256), s(104)], [s(350), s(138)], [s(334), s(286)], [s(256), s(360)], [s(178), s(286)], [s(162), s(138)]],
    colors.stroke
  );
  surface.polygon(
    [[s(256), s(128)], [s(324), s(153)], [s(312), s(272)], [s(256), s(326)], [s(200), s(272)], [s(188), s(153)]],
    colors.bg
  );
  surface.polygon(
    [[s(256), s(142)], [s(306), s(162)], [s(296), s(258)], [s(256), s(300)], [s(216), s(258)], [s(206), s(162)]],
    colors.green
  );

  surface.thickLine(s(228), s(226), s(250), s(248), s(18), colors.bg);
  surface.thickLine(s(250), s(248), s(294), s(202), s(18), colors.bg);

  for (const [x, y, color] of [
    [112, 370, colors.amber],
    [156, 370, colors.green],
    [200, 370, colors.cyan],
    [312, 370, colors.cyan],
    [356, 370, colors.green],
    [400, 370, colors.amber],
  ]) {
    surface.roundedRect(s(x - 16), s(y - 12), s(32), s(24), s(5), color);
  }

  surface.roundedRect(s(28), s(28), s(456), s(456), s(96), rgba('#ffffff', 18));
  return encodePng(size, size, surface.data);
}

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let i = 0; i < 8; i++) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const typeBuffer = Buffer.from(type);
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length, 0);
  typeBuffer.copy(chunk, 4);
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])), 8 + data.length);
  return chunk;
}

function encodePng(width, height, rgbaData) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0;
    rgbaData.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  return Buffer.concat([
    signature,
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

function makeIco(frames) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(frames.length, 4);

  const entries = [];
  let imageOffset = 6 + frames.length * 16;
  for (const frame of frames) {
    const entry = Buffer.alloc(16);
    entry[0] = frame.size >= 256 ? 0 : frame.size;
    entry[1] = frame.size >= 256 ? 0 : frame.size;
    entry[2] = 0;
    entry[3] = 0;
    entry.writeUInt16LE(1, 4);
    entry.writeUInt16LE(32, 6);
    entry.writeUInt32LE(frame.data.length, 8);
    entry.writeUInt32LE(imageOffset, 12);
    entries.push(entry);
    imageOffset += frame.data.length;
  }

  return Buffer.concat([header, ...entries, ...frames.map(frame => frame.data)]);
}

function makeSvg() {
  return `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" role="img" aria-label="Intranet secure transfer icon">
  <rect x="28" y="28" width="456" height="456" rx="96" fill="#0b1020"/>
  <rect x="48" y="48" width="416" height="416" rx="76" fill="#121a2e"/>
  <path d="M118 146v68h276v-68M118 146h0M168 146h0M344 146h0M394 146h0" stroke="#35d2ff" stroke-width="18" stroke-linecap="round" stroke-linejoin="round"/>
  <path d="M84 304h136M194 268l56 36-56 36M428 304H292M318 268l-56 36 56 36" stroke="#35d2ff" stroke-width="20" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
  <path d="M256 104l94 34-16 148-78 74-78-74-16-148z" fill="#d8f3ff"/>
  <path d="M256 128l68 25-12 119-56 54-56-54-12-119z" fill="#0b1020"/>
  <path d="M256 142l50 20-10 96-40 42-40-42-10-96z" fill="#55f29d"/>
  <path d="M228 226l22 22 44-46" stroke="#0b1020" stroke-width="18" stroke-linecap="round" stroke-linejoin="round" fill="none"/>
  <g>
    <rect x="96" y="358" width="32" height="24" rx="5" fill="#ffcf5a"/>
    <rect x="140" y="358" width="32" height="24" rx="5" fill="#55f29d"/>
    <rect x="184" y="358" width="32" height="24" rx="5" fill="#35d2ff"/>
    <rect x="296" y="358" width="32" height="24" rx="5" fill="#35d2ff"/>
    <rect x="340" y="358" width="32" height="24" rx="5" fill="#55f29d"/>
    <rect x="384" y="358" width="32" height="24" rx="5" fill="#ffcf5a"/>
  </g>
</svg>
`;
}

function main() {
  fs.mkdirSync(ASSET_DIR, { recursive: true });
  const png512 = makePng(512);
  const icoFrames = [256, 128, 64, 48, 32, 16].map(size => ({ size, data: makePng(size) }));
  const macIconsetFrames = [
    ['icon_16x16.png', 16],
    ['icon_16x16@2x.png', 32],
    ['icon_32x32.png', 32],
    ['icon_32x32@2x.png', 64],
    ['icon_128x128.png', 128],
    ['icon_128x128@2x.png', 256],
    ['icon_256x256.png', 256],
    ['icon_256x256@2x.png', 512],
    ['icon_512x512.png', 512],
    ['icon_512x512@2x.png', 1024],
  ];

  fs.writeFileSync(path.join(ASSET_DIR, 'icon.png'), png512);
  fs.writeFileSync(path.join(ASSET_DIR, 'icon.ico'), makeIco(icoFrames));
  fs.writeFileSync(path.join(ASSET_DIR, 'icon.svg'), makeSvg(), 'utf8');
  fs.rmSync(MAC_ICONSET_DIR, { recursive: true, force: true });
  fs.mkdirSync(MAC_ICONSET_DIR, { recursive: true });
  for (const [fileName, size] of macIconsetFrames) {
    fs.writeFileSync(path.join(MAC_ICONSET_DIR, fileName), makePng(size));
  }

  console.log(`Success: generated ${path.join(ASSET_DIR, 'icon.png')}`);
  console.log(`Success: generated ${path.join(ASSET_DIR, 'icon.ico')}`);
  console.log(`Success: generated ${path.join(ASSET_DIR, 'icon.svg')}`);
  console.log(`Success: generated ${MAC_ICONSET_DIR}`);
}

main();
