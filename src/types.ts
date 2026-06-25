export type FileCategory =
  | 'document'
  | 'spreadsheet'
  | 'code'
  | 'archive'
  | 'media'
  | 'folder'
  | 'other';

export interface PhysicalFile {
  id: string;
  name: string;
  relativePath: string;
  type: 'file' | 'folder';
  sizeBytes: number;
  size: string;
  lastModified: string;
  category: FileCategory;
}

export interface ShareRecord {
  id: string;
  name: string;
  encryptedLinkToken: string;
  localPath: string;
  description: string;
  accessMode?: 'exclusive' | 'multi';
  allowMobileAccess?: boolean;
  createdAt: string;
  passcodeHint: string;
  passcodeUpdatedAt: string;
  passcodeExpiresAt?: string;
  passcodeDuration?: '1h' | '4h' | '24h' | '7d' | 'never';
  ipWhitelist?: string;
}

export interface NetworkInterfaceInfo {
  id: string;
  name: string;
  address: string;
  cidr: string;
  mac: string;
}

export interface ServerLease {
  shareId: string;
  clientIp: string;
  expiresAt: string;
}

export interface ServerTransfer {
  id: number;
  type: 'download' | 'archive';
  shareId: string;
  shareName: string;
  clientIp: string;
  fileName: string;
  sizeBytes: number;
  startedAt: string;
}

export interface RuntimeIdleGuard {
  type: 'prevent-display-sleep';
  active: boolean;
  blockerId: number | null;
  note: string;
}

export interface ServerState {
  running: boolean;
  hostIp: string;
  bindAddress: string;
  port: number;
  error: string;
  urlBase: string;
  accessUrls: string[];
  runtimeIdleGuard: RuntimeIdleGuard;
  activeLeases: ServerLease[];
  activeTransfers: ServerTransfer[];
}

export interface PublicShareInfo {
  id: string;
  name: string;
  description: string;
  accessMode?: 'exclusive' | 'multi';
  allowMobileAccess?: boolean;
  passcodeHint: string;
  passcodeExpiresAt?: string;
  ipWhitelist?: string;
}

export interface PublicShareResponse {
  share: PublicShareInfo;
  clientIp: string;
  ipAllowed: boolean;
  mobileBlocked: boolean;
  passcodeExpired: boolean;
  occupied: boolean;
}

export interface AuthResponse {
  token: string;
  expiresAt: number;
  clientIp: string;
  share: PublicShareInfo;
  files: PhysicalFile[];
}

export interface PreviewResult {
  type: 'text' | 'binary' | 'folder';
  content: string;
  truncated?: boolean;
}

export interface HashResult {
  fileName: string;
  sizeBytes: number;
  sha256: string;
  md5: string;
}

export interface DesktopEnvironment {
  isElectron: boolean;
  platform: string;
  version: string;
}

export interface LanTransferBridge {
  getNetworkInterfaces(): Promise<NetworkInterfaceInfo[]>;
  getServerState(): Promise<ServerState>;
  setServerConfig(config: { hostIp: string; port: number }): Promise<ServerState>;
  chooseDirectory(): Promise<string | null>;
  chooseFile(): Promise<string | null>;
  listShares(): Promise<ShareRecord[]>;
  createShare(payload: {
    name: string;
    localPath: string;
    description?: string;
    passcode: string;
    passcodeExpiresAt?: string;
    passcodeDuration?: ShareRecord['passcodeDuration'];
    ipWhitelist?: string;
    accessMode?: ShareRecord['accessMode'];
    allowMobileAccess?: boolean;
  }): Promise<ShareRecord>;
  updateShare(
    id: string,
    patch: Partial<Pick<ShareRecord, 'description' | 'passcodeExpiresAt' | 'passcodeDuration' | 'ipWhitelist' | 'accessMode' | 'allowMobileAccess'>> & {
      passcode?: string;
    },
  ): Promise<ShareRecord>;
  extendShareExpiry(id: string, addMs: number): Promise<ShareRecord>;
  deleteShare(id: string): Promise<boolean>;
  listFiles(shareId: string): Promise<PhysicalFile[]>;
  previewFile(shareId: string, relativePath: string): Promise<PreviewResult>;
  forceRelease(shareId: string): Promise<ServerState>;
  copyText(text: string): void;
}

declare global {
  interface Window {
    desktopEnvironment?: DesktopEnvironment;
    lanTransfer?: LanTransferBridge;
  }
}
