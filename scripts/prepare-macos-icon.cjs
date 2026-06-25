const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const iconsetPath = path.join(root, 'assets', 'icon.iconset');
const icnsPath = path.join(root, 'assets', 'icon.icns');

if (!fs.existsSync(iconsetPath)) {
  console.error(`Missing ${iconsetPath}. Run node generate-icon.cjs first.`);
  process.exit(1);
}

if (process.platform !== 'darwin') {
  console.log('Skipped assets/icon.icns generation: iconutil is available only on macOS.');
  console.log(`macOS iconset is ready at ${iconsetPath}`);
  process.exit(0);
}

function hasValidIcns() {
  if (!fs.existsSync(icnsPath)) return false;
  try {
    const output = execFileSync('file', [icnsPath], { encoding: 'utf8' });
    return output.includes('Mac OS X icon');
  } catch {
    return false;
  }
}

const result = spawnSync('iconutil', ['-c', 'icns', iconsetPath, '-o', icnsPath], { stdio: 'inherit' });
if (result.status === 0) {
  console.log(`Success: generated ${icnsPath}`);
  process.exit(0);
}

if (hasValidIcns()) {
  console.warn(`Warning: iconutil rejected ${iconsetPath}; keeping existing valid ${icnsPath}.`);
  process.exit(0);
}

process.exit(result.status || 1);
