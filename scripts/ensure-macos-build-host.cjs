const os = require('os');

if (process.platform !== 'darwin') {
  console.error(
    [
      'macOS DMG packages must be built on macOS.',
      `Current host: ${os.platform()} ${os.release()}`,
      'Move this project to a Mac, run npm install, then run npm run electron:build:mac.',
    ].join('\n')
  );
  process.exit(1);
}
