#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const productName = '内网闪传';
const { version } = require(path.join(root, 'package.json'));
const architecture = process.arch === 'arm64' ? 'aarch64' : process.arch;
const dmgName = `${productName}_${version}_${architecture}.dmg`;
const bundleRoot = path.join(root, 'src-tauri', 'target', 'release', 'bundle');
const macosDir = path.join(bundleRoot, 'macos');
const dmgDir = path.join(bundleRoot, 'dmg');
const releaseDir = path.join(root, 'release-tauri');
const appBundle = path.join(macosDir, `${productName}.app`);
const stagingDir = path.join(bundleRoot, 'dmg-staging');
const finalDmg = path.join(dmgDir, dmgName);

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || root,
    env: options.env || process.env,
    stdio: 'inherit',
    shell: process.platform === 'win32',
  });
  if (result.status !== 0 && !options.allowFailure) {
    process.exit(result.status || 1);
  }
  return result.status || 0;
}

fs.mkdirSync(dmgDir, { recursive: true });
fs.mkdirSync(releaseDir, { recursive: true });

const releaseDmg = path.join(releaseDir, dmgName);
if (fs.existsSync(finalDmg) || fs.existsSync(releaseDmg)) {
  console.error(`Version ${version} already has a DMG. Run "npm run version:next" before packaging another iteration.`);
  process.exit(1);
}

const tauriBin = path.join(root, 'node_modules', '.bin', process.platform === 'win32' ? 'tauri.cmd' : 'tauri');
run(tauriBin, ['build', '--bundles', 'app']);

if (!fs.existsSync(appBundle)) {
  console.error(`Missing app bundle: ${appBundle}`);
  process.exit(1);
}
run('codesign', ['--force', '--deep', '--sign', '-', '--timestamp=none', appBundle]);
run('codesign', ['--verify', '--deep', '--strict', '--verbose=2', appBundle]);

fs.rmSync(stagingDir, { recursive: true, force: true });
fs.mkdirSync(stagingDir, { recursive: true });
fs.cpSync(appBundle, path.join(stagingDir, `${productName}.app`), { recursive: true });
run('xattr', ['-cr', path.join(stagingDir, `${productName}.app`)]);
fs.symlinkSync('/Applications', path.join(stagingDir, 'Applications'));

run('hdiutil', [
  'create',
  '-volname',
  productName,
  '-srcfolder',
  stagingDir,
  '-format',
  'UDZO',
  '-fs',
  'APFS',
  finalDmg,
]);

run('hdiutil', ['verify', finalDmg]);
fs.copyFileSync(finalDmg, releaseDmg, fs.constants.COPYFILE_EXCL);
run('hdiutil', ['verify', releaseDmg]);
console.log(`Tauri DMG ready: ${releaseDmg}`);
