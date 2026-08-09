#!/usr/bin/env node
/**
 * Generates a per-platform Tauri updater JSON manifest.
 *
 * Usage:
 *   node scripts/generate-updater-manifest.cjs \
 *     --target darwin-aarch64 \
 *     --asset-path src-tauri/target/release/bundle/macos/App.app.tar.gz \
 *     --signature-file <path-to-sig> \
 *     --repository owner/repo \
 *     --tag v0.2.1 \
 *     --output src-tauri/target/release/bundle/updater/latest-darwin-aarch64.json
 */

const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i += 1) {
    const key = argv[i];
    if (!key.startsWith('--')) continue;
    const name = key.slice(2);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`Missing value for ${key}`);
    }
    args[name] = value;
    i += 1;
  }
  return args;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  for (const required of ['target', 'asset-path', 'signature-file', 'repository', 'tag', 'output']) {
    if (!args[required]) {
      throw new Error(`Missing required argument: --${required}`);
    }
  }

  const config = JSON.parse(fs.readFileSync('src-tauri/tauri.conf.json', 'utf8'));
  const version = config.version;
  const assetName = path.basename(args['asset-path']);
  const encodedAssetName = encodeURIComponent(assetName);
  const downloadUrl =
    `https://github.com/${args.repository}/releases/download/${args.tag}/${encodedAssetName}`;
  const signature = fs.readFileSync(args['signature-file'], 'utf8').trim();

  const manifest = {
    version,
    notes: args.notes || null,
    pub_date: new Date().toISOString(),
    platforms: {
      [args.target]: {
        url: downloadUrl,
        signature,
      },
    },
  };

  fs.mkdirSync(path.dirname(args.output), { recursive: true });
  fs.writeFileSync(args.output, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
  console.log(`Generated ${args.output} for ${args.target} (v${version})`);
}

main();
