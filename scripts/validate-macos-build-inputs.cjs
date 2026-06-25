const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const packageJsonPath = path.join(root, 'package.json');
const packageJson = JSON.parse(fs.readFileSync(packageJsonPath, 'utf8'));
const requireIcns = process.argv.includes('--require-icns');

const requiredFiles = [
  'electron-main.cjs',
  'electron-preload.cjs',
  'generate-icon.cjs',
  'scripts/ensure-macos-build-host.cjs',
  'scripts/prepare-macos-icon.cjs',
  'assets/icon.png',
  'assets/icon.svg',
  'assets/icon.ico',
];

const requiredIconsetFiles = [
  'icon_16x16.png',
  'icon_16x16@2x.png',
  'icon_32x32.png',
  'icon_32x32@2x.png',
  'icon_128x128.png',
  'icon_128x128@2x.png',
  'icon_256x256.png',
  'icon_256x256@2x.png',
  'icon_512x512.png',
  'icon_512x512@2x.png',
];

function fail(message) {
  console.error(`macOS build input check failed: ${message}`);
  process.exit(1);
}

function requirePath(relativePath) {
  if (!fs.existsSync(path.join(root, relativePath))) fail(`missing ${relativePath}`);
}

for (const relativePath of requiredFiles) requirePath(relativePath);

const iconsetDir = path.join(root, 'assets', 'icon.iconset');
if (!fs.existsSync(iconsetDir) || !fs.statSync(iconsetDir).isDirectory()) {
  fail('missing assets/icon.iconset');
}
for (const fileName of requiredIconsetFiles) requirePath(path.join('assets', 'icon.iconset', fileName));

const build = packageJson.build || {};
const files = build.files || [];
const extraResources = build.extraResources || [];

for (const pattern of ['dist/**/*', 'assets/**/*', 'electron-main.cjs', 'electron-preload.cjs', 'package.json']) {
  if (!files.includes(pattern)) fail(`package.json build.files must include ${pattern}`);
}

const hasPreloadResource = extraResources.some(item => item && item.from === 'electron-preload.cjs' && item.to === 'electron-preload.cjs');
if (!hasPreloadResource) fail('package.json build.extraResources must include electron-preload.cjs');

if (build.mac?.icon !== 'assets/icon.icns') fail('package.json build.mac.icon must be assets/icon.icns');
if (!Array.isArray(build.mac?.target) || !build.mac.target.includes('dmg')) fail('package.json build.mac.target must include dmg');
const dmgContents = build.dmg?.contents || [];
const hasDmgApp = dmgContents.some(item => item && item.type === 'file');
const hasApplicationsLink = dmgContents.some(item => item && item.type === 'link' && item.path === '/Applications');
if (!hasDmgApp) fail('package.json build.dmg.contents must include the app file icon');
if (!hasApplicationsLink) fail('package.json build.dmg.contents must include an /Applications link');
if (!packageJson.scripts?.['electron:build:mac']?.includes('ensure-macos-build-host.cjs')) {
  fail('electron:build:mac must guard that DMG builds only run on macOS');
}
if (!packageJson.scripts?.['electron:build:mac']?.includes('mac:icon')) {
  fail('electron:build:mac must generate assets/icon.icns before electron-builder');
}

if (requireIcns) {
  requirePath('assets/icon.icns');
} else {
  console.log('assets/icon.icns strict check skipped; npm run mac:icon generates it on macOS.');
}

console.log('macOS build input check passed.');
