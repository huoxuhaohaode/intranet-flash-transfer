import { invoke } from '@tauri-apps/api/core';
import { writeText } from '@tauri-apps/plugin-clipboard-manager';
import { open } from '@tauri-apps/plugin-dialog';
import type { LanTransferBridge } from './types';

const isTauriRuntime = Boolean((window as typeof window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__);

async function choosePath(directory: boolean) {
  const selected = await open({
    directory,
    multiple: false,
  });
  return typeof selected === 'string' ? selected : null;
}

if (isTauriRuntime && !window.lanTransfer) {
  window.desktopEnvironment = {
    isElectron: false,
    platform: 'tauri',
    version: '2',
  };

  const bridge: LanTransferBridge = {
    getNetworkInterfaces: () => invoke('get_network_interfaces'),
    getServerState: () => invoke('get_server_state'),
    setServerConfig: config => invoke('set_server_config', { config }),
    chooseDirectory: () => choosePath(true),
    chooseFile: () => choosePath(false),
    listShares: () => invoke('list_shares'),
    createShare: payload => invoke('create_share', { payload }),
    updateShare: (id, patch) => invoke('update_share', { id, patch }),
    extendShareExpiry: (id, addMs) => invoke('extend_share_expiry', { id, addMs }),
    deleteShare: id => invoke('delete_share', { id }),
    listFiles: shareId => invoke('list_files', { shareId }),
    previewFile: (shareId, relativePath) => invoke('preview_file', { shareId, relativePath }),
    forceRelease: shareId => invoke('force_release', { shareId }),
    copyText: text => {
      void writeText(String(text || ''));
    },
  };

  window.lanTransfer = bridge;
}
