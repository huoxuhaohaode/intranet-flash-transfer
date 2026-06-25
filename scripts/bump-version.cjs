#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const packagePath = path.join(root, 'package.json');
const lockPath = path.join(root, 'package-lock.json');
const tauriConfigPath = path.join(root, 'src-tauri', 'tauri.conf.json');
const cargoPath = path.join(root, 'src-tauri', 'Cargo.toml');

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function nextVersion(current) {
  const parts = current.split('.').map(Number);
  if (parts.length !== 3 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 9)) {
    throw new Error(`Version must use three decimal digits, received: ${current}`);
  }

  let [major, minor, patch] = parts;
  patch += 1;
  if (patch === 10) {
    patch = 0;
    minor += 1;
  }
  if (minor === 10) {
    minor = 0;
    major += 1;
  }
  return `${major}.${minor}.${patch}`;
}

const packageJson = readJson(packagePath);
const next = nextVersion(packageJson.version);
packageJson.version = next;
writeJson(packagePath, packageJson);

const packageLock = readJson(lockPath);
packageLock.version = next;
packageLock.packages[''].version = next;
writeJson(lockPath, packageLock);

const tauriConfig = readJson(tauriConfigPath);
tauriConfig.version = next;
writeJson(tauriConfigPath, tauriConfig);

const cargoToml = fs.readFileSync(cargoPath, 'utf8');
const updatedCargoToml = cargoToml.replace(
  /(\[package\][\s\S]*?\nversion = ")[^"]+(")/,
  `$1${next}$2`,
);
if (updatedCargoToml === cargoToml) {
  throw new Error('Could not update Cargo.toml package version.');
}
fs.writeFileSync(cargoPath, updatedCargoToml);

console.log(`Version bumped: ${packageJson.version}`);
