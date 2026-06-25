/**
 * Electron preload bridge.
 *
 * The renderer receives only a small, explicit API. All filesystem,
 * networking, passcode hashing, and HTTP service control stays in the
 * main process.
 */

const { clipboard, contextBridge, ipcRenderer } = require('electron');

function invoke(channel, ...args) {
  return ipcRenderer.invoke(channel, ...args);
}

contextBridge.exposeInMainWorld('desktopEnvironment', {
  isElectron: true,
  platform: process.platform,
  version: process.versions.electron,
});

contextBridge.exposeInMainWorld('lanTransfer', {
  getNetworkInterfaces: () => invoke('lan:getNetworkInterfaces'),
  getServerState: () => invoke('lan:getServerState'),
  setServerConfig: config => invoke('lan:setServerConfig', config),
  chooseDirectory: () => invoke('lan:chooseDirectory'),
  chooseFile: () => invoke('lan:chooseFile'),
  listShares: () => invoke('lan:listShares'),
  createShare: payload => invoke('lan:createShare', payload),
  updateShare: (id, patch) => invoke('lan:updateShare', id, patch),
  extendShareExpiry: (id, addMs) => invoke('lan:extendShareExpiry', id, addMs),
  deleteShare: id => invoke('lan:deleteShare', id),
  listFiles: shareId => invoke('lan:listFiles', shareId),
  previewFile: (shareId, relativePath) => invoke('lan:previewFile', shareId, relativePath),
  forceRelease: shareId => invoke('lan:forceRelease', shareId),
  copyText: text => clipboard.writeText(String(text || '')),
});
