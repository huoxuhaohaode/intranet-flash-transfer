import React, { useCallback, useEffect, useMemo, useRef, useState, type ErrorInfo, type FormEvent, type ReactNode } from 'react';
import QRCodeLib from 'qrcode';
import {
  Activity,
  AlertTriangle,
  Archive,
  Bluetooth,
  Check,
  Copy,
  Download,
  Eye,
  File,
  FileCode,
  FileSpreadsheet,
  FileText,
  Folder,
  FolderOpen,
  HardDrive,
  Image,
  KeyRound,
  Link2,
  Lock,
  Network,
  LayoutDashboard,
  Pause,
  Play,
  Plus,
  QrCode,
  RefreshCw,
  Search,
  Server,
  Settings,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Sun,
  Moon,
  TimerReset,
  Trash2,
  UploadCloud,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import type {
  AuditEvent,
  AuthResponse,
  DeviceInfo,
  HashResult,
  NetworkInterfaceInfo,
  PhysicalFile,
  PreviewResult,
  PublicShareResponse,
  ServerState,
  ShareRecord,
  UploadReceipt,
} from './types';
import { sha256Bytes } from './utils/hash';
import { convertFileSrc } from '@tauri-apps/api/core';
import { useI18n } from './i18n';

type NoticeTone = 'info' | 'ok' | 'warn' | 'error';
type DownloadPhase = 'idle' | 'connecting' | 'streaming' | 'paused' | 'verifying' | 'complete' | 'error' | 'archiving';
type ShareDuration = '1h' | '4h' | '24h' | '7d' | 'never';
type ShareAccessMode = 'exclusive' | 'multi';

interface Notice {
  tone: NoticeTone;
  text: string;
}

interface DownloadState {
  phase: DownloadPhase;
  fileName: string;
  totalBytes: number;
  downloadedBytes: number;
  percent: number;
  speedBps: number;
  message: string;
  resumeAvailable: boolean;
}

interface UploadTask {
  id: string;
  name: string;
  sizeBytes: number;
  phase: 'pending' | 'uploading' | 'verifying' | 'done' | 'error';
  uploadedBytes: number;
  percent: number;
  speedBps: number;
  message: string;
  verified?: boolean;
}

interface Receipt {
  fileName: string;
  transferId: string;
  sizeBytes: number;
  sha256: string;
  md5?: string;
  verified: boolean;
  finishedAt: string;
}

const DEFAULT_SERVER_STATE: ServerState = {
  running: false,
  hostIp: '127.0.0.1',
  bindAddress: '0.0.0.0',
  port: 8787,
  downloadSpeedLimitMbps: 0,
  tlsEnabled: false,
  error: '',
  urlBase: 'http://127.0.0.1:8787',
  accessUrls: ['http://127.0.0.1:8787'],
  runtimeIdleGuard: {
    type: 'prevent-display-sleep',
    active: false,
    blockerId: null,
    note: '',
  },
  activeLeases: [],
  activeTransfers: [],
};

const EMPTY_DOWNLOAD: DownloadState = {
  phase: 'idle',
  fileName: '',
  totalBytes: 0,
  downloadedBytes: 0,
  percent: 0,
  speedBps: 0,
  message: '尚未开始传输',
  resumeAvailable: false,
};

const DURATION_OPTIONS: Array<{ value: ShareDuration; label: string; ms: number | null }> = [
  { value: '1h', label: '1 小时', ms: 60 * 60 * 1000 },
  { value: '4h', label: '4 小时', ms: 4 * 60 * 60 * 1000 },
  { value: '24h', label: '24 小时', ms: 24 * 60 * 60 * 1000 },
  { value: '7d', label: '7 天', ms: 7 * 24 * 60 * 60 * 1000 },
  { value: 'never', label: '永不过期', ms: null },
];

const EXTEND_OPTIONS = [
  { label: '+1 小时', ms: 60 * 60 * 1000 },
  { label: '+4 小时', ms: 4 * 60 * 60 * 1000 },
  { label: '+24 小时', ms: 24 * 60 * 60 * 1000 },
];

function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return bytes === 0 ? '0 B' : '未知';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  return `${value.toFixed(value >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function formatDate(value?: string) {
  if (!value) return '未设置';
  const time = new Date(value);
  if (Number.isNaN(time.getTime())) return value;
  return time.toLocaleString();
}

function formatTimeLeft(value?: string) {
  if (!value) return '永不过期';
  const diff = new Date(value).getTime() - Date.now();
  if (diff <= 0) return '已过期';
  const minutes = Math.floor(diff / 60000);
  if (minutes < 60) return `${minutes} 分钟内过期`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `剩余 ${hours} 小时 ${minutes % 60} 分钟`;
  return `剩余 ${Math.floor(hours / 24)} 天 ${hours % 24} 小时`;
}

function computeExpiry(duration: ShareDuration) {
  const option = DURATION_OPTIONS.find(item => item.value === duration);
  if (!option || option.ms === null) return undefined;
  return new Date(Date.now() + option.ms).toISOString();
}

function isExpired(value?: string) {
  return !!value && new Date(value).getTime() <= Date.now();
}

function sanitizeShareName(value: string) {
  return value.trim().replace(/[^a-zA-Z0-9_-]/g, '');
}

function noticeClass(tone: NoticeTone) {
  if (tone === 'ok') return 'border-emerald-500 bg-emerald-50 text-emerald-900';
  if (tone === 'warn') return 'border-amber-500 bg-amber-50 text-amber-900';
  if (tone === 'error') return 'border-red-500 bg-red-50 text-red-900';
  return 'border-slate-300 bg-slate-50 text-slate-800';
}

function fileIcon(file: Pick<PhysicalFile, 'type' | 'category'>) {
  const className = 'h-4 w-4';
  if (file.type === 'folder') return <Folder className={className} />;
  if (file.category === 'document') return <FileText className={className} />;
  if (file.category === 'spreadsheet') return <FileSpreadsheet className={className} />;
  if (file.category === 'code') return <FileCode className={className} />;
  if (file.category === 'archive') return <Archive className={className} />;
  if (file.category === 'media') return <Image className={className} />;
  return <File className={className} />;
}

function isImageFile(name: string) {
  return /\.(png|jpe?g|gif|webp|bmp|svg|heic|heif|avif|tiff?)$/i.test(name);
}

function useDialogFocus(open: boolean, onClose: () => void) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (!open) return;
    const container = containerRef.current;
    if (!container) return;
    const previous = document.activeElement as HTMLElement | null;
    const focusables = (): HTMLElement[] => {
      const nodes: NodeListOf<Element> = container.querySelectorAll('button, input, select, textarea, a[href]');
      const result: HTMLElement[] = [];
      nodes.forEach((node: Element) => {
        const element = node as HTMLElement;
        if (!element.hasAttribute('disabled') && element.offsetParent !== null) result.push(element);
      });
      return result;
    };
    focusables()[0]?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== 'Tab') return;
      const items = focusables();
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    container.addEventListener('keydown', onKeyDown);
    return () => {
      container.removeEventListener('keydown', onKeyDown);
      previous?.focus?.();
    };
  }, [open, onClose]);
  return containerRef;
}

async function readJsonError(response: Response) {
  try {
    const body = await response.json();
    return body?.error || response.statusText;
  } catch {
    return response.statusText;
  }
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  if (!response.ok) throw new Error(await readJsonError(response));
  return response.json() as Promise<T>;
}

function authHeaders(token: string): HeadersInit {
  return { Authorization: `Bearer ${token}` };
}

function triggerDownload(blob: Blob, fileName: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

function contentDispositionFileName(header: string | null, fallback: string) {
  if (!header) return fallback;
  const encoded = header.match(/filename\*=UTF-8''([^;]+)/i)?.[1];
  if (encoded) return decodeURIComponent(encoded);
  const plain = header.match(/filename="?([^";]+)"?/i)?.[1];
  return plain || fallback;
}

async function sha256Blob(blob: Blob) {
  const bytes = new Uint8Array(await blob.arrayBuffer());
  if (window.crypto?.subtle) {
    try {
      const digest = await window.crypto.subtle.digest('SHA-256', bytes);
      return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
    } catch {
      return sha256Bytes(bytes);
    }
  }
  return sha256Bytes(bytes);
}

function StatusPill({ ok, children }: { ok: boolean; children: ReactNode }) {
  return (
    <span
      className={`app-status inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-semibold ${
        ok ? 'border-emerald-300 bg-emerald-50 text-emerald-800' : 'border-red-300 bg-red-50 text-red-800'
      }`}
    >
      {ok ? <Check className="h-3.5 w-3.5" /> : <X className="h-3.5 w-3.5" />}
      {children}
    </span>
  );
}

function Panel({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <section className={`app-panel rounded-lg border border-slate-200 bg-white shadow-sm ${className}`}>{children}</section>;
}

function PreviewResultBody({ preview, mediaSrc }: { preview: PreviewResult; mediaSrc?: string }) {
  if (preview.type === 'text') {
    return <pre className="whitespace-pre-wrap break-words">{preview.content}</pre>;
  }
  if (preview.type === 'image' && mediaSrc) {
    return (
      <div className="flex h-full items-center justify-center">
        <img src={mediaSrc} alt="图片预览" className="max-h-full max-w-full object-contain" />
      </div>
    );
  }
  if (preview.type === 'video' && mediaSrc) {
    return (
      <div className="flex h-full items-center justify-center">
        <video src={mediaSrc} controls playsInline preload="metadata" className="max-h-full max-w-full" />
      </div>
    );
  }
  if (preview.type === 'audio' && mediaSrc) {
    return (
      <div className="flex h-full items-center justify-center">
        <audio src={mediaSrc} controls className="w-full" />
      </div>
    );
  }
  return <div className="flex h-full items-center justify-center text-center text-slate-300">{preview.content}</div>;
}

function SectionTitle({ icon, title, action }: { icon: ReactNode; title: string; action?: ReactNode }) {
  return (
    <div className="section-title flex items-center justify-between gap-3 border-b border-slate-200 px-5 py-4">
      <h2 className="flex items-center gap-2 text-sm font-bold text-slate-950">
        {icon}
        {title}
      </h2>
      {action}
    </div>
  );
}

function ShareLinkCard({
  share,
  primaryLink,
  alternateLinks,
  onCopyPrimary,
  onCopyAll,
}: {
  share: ShareRecord;
  primaryLink: string;
  alternateLinks: string[];
  onCopyPrimary: () => void;
  onCopyAll: () => void;
}) {
  const [qrDataUrl, setQrDataUrl] = useState('');

  useEffect(() => {
    let cancelled = false;
    setQrDataUrl('');
    QRCodeLib.toDataURL(primaryLink, {
      errorCorrectionLevel: 'M',
      margin: 2,
      width: 240,
      color: {
        dark: '#020617',
        light: '#ffffff',
      },
    })
      .then(dataUrl => {
        if (!cancelled) setQrDataUrl(dataUrl);
      })
      .catch(() => {
        if (!cancelled) setQrDataUrl('');
      });
    return () => {
      cancelled = true;
    };
  }, [primaryLink]);

  return (
    <div className="share-link-card grid grid-cols-1 gap-4 rounded-lg border border-slate-200 bg-white p-4 lg:grid-cols-[220px_minmax(0,1fr)]">
      <div className="qr-stage flex flex-col items-center justify-center rounded-lg border border-slate-200 bg-slate-50 p-4">
        {qrDataUrl ? (
          <img src={qrDataUrl} alt={`${share.name} 访问二维码`} className="h-44 w-44 rounded-md bg-white p-2" />
        ) : (
          <div className="flex h-44 w-44 flex-col items-center justify-center gap-2 rounded-md bg-white text-xs font-semibold text-slate-400">
            <QrCode className="h-8 w-8" />
            二维码生成中
          </div>
        )}
        {qrDataUrl && (
          <a href={qrDataUrl} download={`${share.name}-qrcode.png`} className="mt-3 inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-xs font-bold">
            <Download className="h-3.5 w-3.5" />
            保存二维码
          </a>
        )}
      </div>
      <div className="min-w-0 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="flex items-center gap-2 text-sm font-black">
              <Share2 className="h-4 w-4" />
              分享给访客
            </p>
            <p className="text-xs text-slate-500">{share.allowMobileAccess ? '移动端已允许，手机扫码可进入认证。' : '移动端默认关闭，扫码设备仍需符合共享策略。'}</p>
          </div>
          <StatusPill ok={!!share.encryptedLinkToken}>加密链接</StatusPill>
        </div>
        <p className="secure-link break-all rounded-md border border-slate-200 bg-slate-50 p-3 font-mono text-xs leading-5">{primaryLink}</p>
        <div className="tech-actions flex flex-wrap gap-2">
          <button type="button" onClick={onCopyPrimary} className="inline-flex items-center gap-2 rounded-md bg-slate-950 px-3 py-2 text-sm font-bold text-white">
            <Copy className="h-4 w-4" />
            复制链接
          </button>
          <button type="button" onClick={onCopyAll} className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold">
            <Link2 className="h-4 w-4" />
            复制全部地址
          </button>
        </div>
        {alternateLinks.length > 0 && (
          <div className="space-y-1 rounded-md border border-slate-200 bg-slate-50 p-3">
            <p className="text-xs font-bold text-slate-500">备用网卡地址</p>
            {alternateLinks.map(link => (
              <p key={link} className="break-all font-mono text-[11px] leading-5 text-slate-500">
                {link}
              </p>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function AdminView() {
  const bridge = window.lanTransfer;
  const { locale, setLocale, t } = useI18n();
  const [theme, setTheme] = useState<'light' | 'dark' | 'system'>(() => (localStorage.getItem('lan-theme') as 'light' | 'dark' | 'system') || 'system');
  useEffect(() => {
    localStorage.setItem('lan-theme', theme);
    const resolved = theme === 'system' ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme;
    document.documentElement.dataset.theme = resolved;
  }, [theme]);
  const [interfaces, setInterfaces] = useState<NetworkInterfaceInfo[]>([]);
  const [server, setServer] = useState<ServerState>(DEFAULT_SERVER_STATE);
  const [shares, setShares] = useState<ShareRecord[]>([]);
  const [files, setFiles] = useState<PhysicalFile[]>([]);
  const [selectedShareId, setSelectedShareId] = useState('');
  const [selectedPreview, setSelectedPreview] = useState<PreviewResult | null>(null);
  const [previewPath, setPreviewPath] = useState('');
  const [notice, setNotice] = useState<Notice | null>(null);
  const [busy, setBusy] = useState(false);
  const [serverForm, setServerForm] = useState({ hostIp: '127.0.0.1', port: 8787, speedLimitMbps: 0, tlsEnabled: false, tlsCertPath: '', tlsKeyPath: '' });
  const [audit, setAudit] = useState<AuditEvent[]>([]);
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [receivedFiles, setReceivedFiles] = useState<PhysicalFile[]>([]);
  const [adminTab, setAdminTab] = useState<'overview' | 'shares' | 'network' | 'audit'>('overview');
  const [createOpen, setCreateOpen] = useState(false);
  const [onboarded, setOnboarded] = useState(() => localStorage.getItem('lan-onboarded') === '1');
  const [shareForm, setShareForm] = useState({
    name: '',
    localPath: '',
    description: '',
    passcode: '',
    duration: '4h' as ShareDuration,
    ipWhitelist: '',
    accessMode: 'exclusive' as ShareAccessMode,
    allowMobileAccess: false,
    allowUpload: false,
    receiveDir: '',
    speedLimitMbps: '',
    oneTimeAccess: false,
    uploadMaxBytes: '',
    uploadExtensions: '',
  });
  const [editForm, setEditForm] = useState({
    description: '',
    passcode: '',
    duration: '4h' as ShareDuration,
    ipWhitelist: '',
    accessMode: 'exclusive' as ShareAccessMode,
    allowMobileAccess: false,
    allowUpload: false,
    receiveDir: '',
    speedLimitMbps: '',
    oneTimeAccess: false,
    uploadMaxBytes: '',
    uploadExtensions: '',
  });
  const [pendingDelete, setPendingDelete] = useState<ShareRecord | null>(null);
  const [confirmAlias, setConfirmAlias] = useState('');
  const [deleteConfirmError, setDeleteConfirmError] = useState('');
  const createDialogRef = useDialogFocus(createOpen, () => setCreateOpen(false));
  const deleteDialogRef = useDialogFocus(!!pendingDelete, () => setPendingDelete(null));

  const selectedShare = shares.find(item => item.id === selectedShareId) || shares[0];
  const adminMediaSrc =
    selectedShare && previewPath
      ? convertFileSrc(`${selectedShare.localPath.replace(/[\\/]+$/, '')}/${previewPath.replace(/\\/g, '/')}`)
      : undefined;

  const setAutoNotice = useCallback((next: Notice) => {
    setNotice(next);
    window.setTimeout(() => setNotice(current => (current?.text === next.text ? null : current)), 5000);
  }, []);

  const reloadAdmin = useCallback(async () => {
    if (!bridge) return;
    const [nicRows, serverState, shareRows] = await Promise.all([
      bridge.getNetworkInterfaces(),
      bridge.getServerState(),
      bridge.listShares(),
    ]);
    setInterfaces(nicRows);
    setServer(serverState);
    setServerForm({
      hostIp: serverState.hostIp,
      port: serverState.port,
      speedLimitMbps: serverState.downloadSpeedLimitMbps || 0,
      tlsEnabled: serverState.tlsEnabled,
      tlsCertPath: serverState.tlsCertPath || '',
      tlsKeyPath: serverState.tlsKeyPath || '',
    });
    setShares(shareRows);
    setSelectedShareId(current => current || shareRows[0]?.id || '');
    setAudit(await bridge.listAuditEvents());
    setDevices(await bridge.listDevices());
  }, [bridge]);

  useEffect(() => {
    reloadAdmin().catch(error => setAutoNotice({ tone: 'error', text: `加载管理端失败：${error.message}` }));
  }, [reloadAdmin, setAutoNotice]);

  useEffect(() => {
    if (!bridge) return undefined;
    const timer = window.setInterval(() => {
      bridge.getServerState().then(setServer).catch(() => {});
    }, 5000);
    return () => window.clearInterval(timer);
  }, [bridge]);

  useEffect(() => {
    if (!selectedShare) {
      setFiles([]);
      setSelectedPreview(null);
      return;
    }
    setEditForm({
      description: selectedShare.description || '',
      passcode: '',
      duration: (selectedShare.passcodeDuration || '4h') as ShareDuration,
      ipWhitelist: selectedShare.ipWhitelist || '',
      accessMode: (selectedShare.accessMode || 'exclusive') as ShareAccessMode,
      allowMobileAccess: selectedShare.allowMobileAccess === true,
      allowUpload: selectedShare.allowUpload === true,
      receiveDir: selectedShare.receiveDir || '',
      speedLimitMbps: selectedShare.speedLimitMbps ? String(selectedShare.speedLimitMbps) : '',
      oneTimeAccess: selectedShare.oneTimeAccess === true,
      uploadMaxBytes: selectedShare.uploadMaxBytes ? String(Math.round(selectedShare.uploadMaxBytes / (1024 * 1024))) : '',
      uploadExtensions: selectedShare.uploadExtensions || '',
    });
    bridge
      ?.listFiles(selectedShare.id)
      .then(setFiles)
      .catch(error => {
        setFiles([]);
        setAutoNotice({ tone: 'error', text: `读取真实目录失败：${error.message}` });
      });
    setSelectedPreview(null);
    setPreviewPath('');
    if (selectedShare.allowUpload && selectedShare.receiveDir) {
      bridge
        ?.listReceivedFiles(selectedShare.id)
        .then(setReceivedFiles)
        .catch(() => setReceivedFiles([]));
    } else {
      setReceivedFiles([]);
    }
  }, [bridge, selectedShare?.id, setAutoNotice]);

  if (!bridge) {
    return (
      <div className="mx-auto flex min-h-screen max-w-3xl items-center justify-center p-6">
        <Panel className="p-8">
          <div className="flex items-start gap-4">
            <ShieldAlert className="mt-1 h-8 w-8 text-red-600" />
            <div className="space-y-3">
              <h1 className="text-2xl font-black text-slate-950">管理端必须在桌面应用中运行</h1>
              <p className="text-sm leading-6 text-slate-600">
                真实网卡枚举、目录选择、口令哈希和本机 HTTP 服务都由桌面端 Rust 后端提供。普通浏览器页面不会获得这些权限。
              </p>
            </div>
          </div>
        </Panel>
      </div>
    );
  }

  async function applyServerConfig(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      const next = await bridge!.setServerConfig({
        hostIp: serverForm.hostIp,
        port: Number(serverForm.port),
        downloadSpeedLimitMbps: Number(serverForm.speedLimitMbps) || 0,
        tlsEnabled: serverForm.tlsEnabled,
        tlsCertPath: serverForm.tlsCertPath.trim() || undefined,
        tlsKeyPath: serverForm.tlsKeyPath.trim() || undefined,
      });
      setServer(next);
      setServerForm(current => ({ ...current, speedLimitMbps: next.downloadSpeedLimitMbps || 0 }));
      setServerForm(current => ({
        ...current,
        tlsEnabled: next.tlsEnabled,
        tlsCertPath: next.tlsCertPath || current.tlsCertPath,
        tlsKeyPath: next.tlsKeyPath || current.tlsKeyPath,
      }));
      setAutoNotice({ tone: next.running ? 'ok' : 'warn', text: next.running ? '内网 HTTP 服务已按真实网卡地址重启。' : next.error });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `服务配置失败：${(error as Error).message}` });
    } finally {
      setBusy(false);
    }
  }

  async function generateCert() {
    try {
      const result = await bridge!.generateSelfSignedCert();
      setServerForm(current => ({ ...current, tlsCertPath: result.certPath, tlsKeyPath: result.keyPath }));
      setAutoNotice({ tone: 'ok', text: '自签名证书已生成，点击“应用并重启内网服务”即可启用 HTTPS。' });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `生成证书失败：${(error as Error).message}` });
    }
  }

  async function chooseDirectory() {
    const directory = await bridge!.chooseDirectory();
    if (directory) setShareForm(current => ({ ...current, localPath: directory }));
  }

  async function chooseFile() {
    const file = await bridge!.chooseFile();
    if (file) setShareForm(current => ({ ...current, localPath: file }));
  }

  async function createShare(event: FormEvent) {
    event.preventDefault();
    const name = sanitizeShareName(shareForm.name);
    if (!name) return setAutoNotice({ tone: 'warn', text: '共享别名只能包含英文、数字、下划线和短横线。' });
    if (!shareForm.localPath.trim()) return setAutoNotice({ tone: 'warn', text: '请先选择一个真实存在的本机文件或目录。' });
    if (!shareForm.passcode.trim()) return setAutoNotice({ tone: 'warn', text: '必须设置访问口令，口令不会明文保存。' });
    if (shareForm.allowUpload && !shareForm.receiveDir.trim()) {
      return setAutoNotice({ tone: 'warn', text: '允许上传时必须选择一个接收目录。' });
    }
    setBusy(true);
    try {
      const created = await bridge!.createShare({
        name,
        localPath: shareForm.localPath.trim(),
        description: shareForm.description.trim(),
        passcode: shareForm.passcode,
        passcodeExpiresAt: computeExpiry(shareForm.duration),
        passcodeDuration: shareForm.duration,
        ipWhitelist: shareForm.ipWhitelist.trim() || undefined,
        accessMode: shareForm.accessMode,
        allowMobileAccess: shareForm.allowMobileAccess,
        allowUpload: shareForm.allowUpload,
        receiveDir: shareForm.receiveDir.trim() || undefined,
        speedLimitMbps: Number(shareForm.speedLimitMbps) > 0 ? Number(shareForm.speedLimitMbps) : undefined,
        oneTimeAccess: shareForm.oneTimeAccess,
        uploadMaxBytes: Number(shareForm.uploadMaxBytes) > 0 ? Math.round(Number(shareForm.uploadMaxBytes) * 1024 * 1024) : undefined,
        uploadExtensions: shareForm.uploadExtensions.trim() || undefined,
      });
      setShareForm({ name: '', localPath: '', description: '', passcode: '', duration: '4h', ipWhitelist: '', accessMode: 'exclusive', allowMobileAccess: false, allowUpload: false, receiveDir: '', speedLimitMbps: '', oneTimeAccess: false, uploadMaxBytes: '', uploadExtensions: '' });
      await reloadAdmin();
      setSelectedShareId(created.id);
      setCreateOpen(false);
      setAutoNotice({ tone: 'ok', text: `共享 ${created.name} 已绑定到真实目录。` });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `创建共享失败：${(error as Error).message}` });
    } finally {
      setBusy(false);
    }
  }

  async function updateShare(event: FormEvent) {
    event.preventDefault();
    if (!selectedShare) return;
    if (editForm.allowUpload && !editForm.receiveDir.trim()) {
      return setAutoNotice({ tone: 'warn', text: '允许上传时必须选择一个接收目录。' });
    }
    setBusy(true);
    try {
      await bridge!.updateShare(selectedShare.id, {
        description: editForm.description.trim(),
        passcode: editForm.passcode.trim() || undefined,
        passcodeExpiresAt: computeExpiry(editForm.duration),
        passcodeDuration: editForm.duration,
        ipWhitelist: editForm.ipWhitelist.trim() || undefined,
        accessMode: editForm.accessMode,
        allowMobileAccess: editForm.allowMobileAccess,
        allowUpload: editForm.allowUpload,
        receiveDir: editForm.receiveDir.trim() || null,
        speedLimitMbps: Number(editForm.speedLimitMbps) > 0 ? Number(editForm.speedLimitMbps) : undefined,
        oneTimeAccess: editForm.oneTimeAccess,
        uploadMaxBytes: Number(editForm.uploadMaxBytes) > 0 ? Math.round(Number(editForm.uploadMaxBytes) * 1024 * 1024) : undefined,
        uploadExtensions: editForm.uploadExtensions.trim() || undefined,
      });
      await reloadAdmin();
      setAutoNotice({ tone: 'ok', text: '共享安全策略已写入本机状态文件，旧明文口令不会保留。' });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `更新失败：${(error as Error).message}` });
    } finally {
      setBusy(false);
    }
  }

  function requestDelete(share: ShareRecord) {
    setConfirmAlias('');
    setDeleteConfirmError('');
    setPendingDelete(share);
  }

  async function confirmDelete() {
    if (!pendingDelete) return;
    if (confirmAlias.trim() !== pendingDelete.name) {
      setDeleteConfirmError(`${t('aliasMismatch')} "${pendingDelete.name}"。`);
      return;
    }
    const share = pendingDelete;
    setBusy(true);
    try {
      await bridge!.deleteShare(share.id);
      setPendingDelete(null);
      setSelectedShareId('');
      await reloadAdmin();
      setAutoNotice({ tone: 'ok', text: '共享已撤销，HTTP 访问端不再能认证。' });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `撤销失败：${(error as Error).message}` });
      setPendingDelete(null);
    } finally {
      setBusy(false);
    }
  }

  async function previewFile(file: PhysicalFile) {
    if (!selectedShare) return;
    try {
      const preview = await bridge!.previewFile(selectedShare.id, file.relativePath);
      setPreviewPath(file.relativePath || file.name);
      setSelectedPreview(preview);
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `预览失败：${(error as Error).message}` });
    }
  }

  const selectedHostIsUsable = interfaces.some(item => item.address === serverForm.hostIp);
  const preferredAccessHost = selectedHostIsUsable ? serverForm.hostIp : server.hostIp;
  const runningPort = Number(server.port) || 8787;
  const scheme = server.tlsEnabled ? 'https' : 'http';
  const preferredAccessBase = `${scheme}://${preferredAccessHost}:${runningPort}`;
  const accessBases = Array.from(
    new Set([
      preferredAccessBase,
      ...(server.accessUrls || []),
      ...interfaces.map(item => `${scheme}://${item.address}:${runningPort}`),
    ].filter(Boolean)),
  );
  const hasPendingPortChange = Number(serverForm.port) !== runningPort;

  function shareLinkForBase(share: ShareRecord, base: string) {
    return `${base.replace(/\/+$/, '')}/?token=${encodeURIComponent(share.encryptedLinkToken)}`;
  }

  async function copyTextWithFallback(text: string) {
    try {
      bridge!.copyText(text);
    } catch (nativeError) {
      try {
        await navigator.clipboard.writeText(text);
      } catch (browserError) {
        const message = (browserError as Error).message || (nativeError as Error).message;
        throw new Error(message);
      }
    }
  }

  async function copyShareLink(share: ShareRecord) {
    const link = shareLinkForBase(share, preferredAccessBase);
    try {
      await copyTextWithFallback(link);
      setAutoNotice({
        tone: hasPendingPortChange ? 'warn' : 'ok',
        text: hasPendingPortChange
          ? `已复制正在监听端口的真实链接：${link}。端口输入框尚未应用，复制时未使用未生效端口。`
          : `已复制真实访问链接：${link}`,
      });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `复制失败：${(error as Error).message}` });
    }
  }

  async function copyAllShareLinks(share: ShareRecord) {
    const links = accessBases.map(base => shareLinkForBase(share, base)).join('\n');
    try {
      await copyTextWithFallback(links);
      setAutoNotice({ tone: 'ok', text: `已复制 ${accessBases.length} 个真实网卡访问链接。` });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `复制失败：${(error as Error).message}` });
    }
  }

  async function forceRelease() {
    if (!selectedShare) return;
    try {
      await bridge!.forceRelease(selectedShare.id);
      await reloadAdmin();
      setAutoNotice({ tone: 'ok', text: '独占租约已释放，下一台授权电脑可重新认证。' });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `释放失败：${(error as Error).message}` });
    }
  }

  async function extendExpiry(addMs: number, label: string) {
    if (!selectedShare) return;
    setBusy(true);
    try {
      const updated = await bridge!.extendShareExpiry(selectedShare.id, addMs);
      setShares(current => current.map(share => (share.id === updated.id ? updated : share)));
      setSelectedShareId(updated.id);
      setServer(await bridge!.getServerState());
      setAutoNotice({
        tone: 'ok',
        text: `${updated.name} 已加时 ${label.replace('+', '')}，不会重置口令、独占锁或正在下载的访客任务。`,
      });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `加时失败：${(error as Error).message}` });
    } finally {
      setBusy(false);
    }
  }

  const totalSize = files.reduce((sum, file) => sum + (file.type === 'file' ? file.sizeBytes : 0), 0);
  const activeLease = selectedShare ? server.activeLeases.find(item => item.shareId === selectedShare.id) : undefined;
  const primaryShareLink = selectedShare ? shareLinkForBase(selectedShare, preferredAccessBase) : '';
  const alternateShareLinks = selectedShare ? accessBases.slice(1).map(base => shareLinkForBase(selectedShare, base)) : [];
  const bluetoothInterfaces = interfaces.filter(item => item.bluetooth);
  const bluetoothBases = bluetoothInterfaces.map(item => `http://${item.address}:${runningPort}`);

  return (
    <div className="app-shell admin-shell min-h-screen bg-slate-100 text-slate-950">
      <a
        href="#admin-main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-slate-950 focus:px-3 focus:py-2 focus:text-sm focus:font-bold focus:text-white"
      >
        跳到主内容
      </a>
      <header className="app-header border-b border-slate-200 bg-white">
        <div className="app-header-inner flex w-full flex-col gap-4 px-6 py-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-3">
            <div className="brand-mark flex h-12 w-12 items-center justify-center rounded-lg bg-slate-950 text-white">
              <UploadCloud className="h-7 w-7" />
            </div>
            <div>
              <h1 className="text-2xl font-black tracking-tight">{t('appName')}</h1>
              <p className="text-sm text-slate-600">{t('tagline')}</p>
            </div>
          </div>
          <div className="status-deck flex flex-wrap items-center gap-2">
            <StatusPill ok={server.running}>{server.running ? t('httpRunning') : t('httpStopped')}</StatusPill>
            <StatusPill ok={!server.error}>{server.error ? t('serviceError') : t('noError')}</StatusPill>
            <StatusPill ok={server.activeTransfers.length === 0}>
              {server.activeTransfers.length > 0 ? `${t('transferringN')} ${server.activeTransfers.length}` : t('noTransfers')}
            </StatusPill>
            <StatusPill ok={server.runtimeIdleGuard.active}>{t('idleGuard')}</StatusPill>
            <span className="endpoint-chip rounded-full border border-slate-300 bg-slate-50 px-3 py-1 text-xs font-mono font-semibold">
              {preferredAccessBase}
            </span>
            <button
              type="button"
              onClick={() => setCreateOpen(true)}
              className="inline-flex items-center gap-2 rounded-md bg-slate-950 px-3 py-2 text-sm font-bold text-white"
            >
              <Plus className="h-4 w-4" />
              {t('newShare')}
            </button>
            <button
              type="button"
              onClick={() => setTheme(current => (current === 'dark' ? 'light' : 'dark'))}
              title={theme === 'dark' ? '切换到浅色模式' : '切换到深色模式'}
              className="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-slate-950 px-3 py-2 text-sm font-bold text-white"
            >
              {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
              {theme === 'dark' ? t('light') : t('dark')}
            </button>
            <button
              type="button"
              onClick={() => setLocale(current => (current === 'zh' ? 'en' : 'zh'))}
              className="inline-flex items-center gap-2 rounded-md border border-slate-300 bg-slate-950 px-3 py-2 text-sm font-bold text-white"
            >
              {locale === 'zh' ? 'EN' : '中文'}
            </button>
          </div>
        </div>
      </header>

      <nav className="admin-tabs sticky top-[64px] z-20 flex gap-1 overflow-x-auto border-b border-slate-200 bg-white/95 px-6 py-2 shadow-sm backdrop-blur">
        <button
          type="button"
          onClick={() => setAdminTab('overview')}
          aria-current={adminTab === 'overview' ? 'page' : undefined}
          className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-2 text-sm font-bold ${
            adminTab === 'overview' ? 'bg-slate-950 text-white' : 'text-slate-500 hover:bg-slate-100 hover:text-slate-900'
          }`}
        >
          <LayoutDashboard className="h-4 w-4" />
          {t('navOverview')}
        </button>
        <button
          type="button"
          onClick={() => setAdminTab('shares')}
          aria-current={adminTab === 'shares' ? 'page' : undefined}
          className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-2 text-sm font-bold ${
            adminTab === 'shares' ? 'bg-slate-950 text-white' : 'text-slate-500 hover:bg-slate-100 hover:text-slate-900'
          }`}
        >
          <FolderOpen className="h-4 w-4" />
          {t('navShares')}
        </button>
        <button
          type="button"
          onClick={() => setAdminTab('network')}
          aria-current={adminTab === 'network' ? 'page' : undefined}
          className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-2 text-sm font-bold ${
            adminTab === 'network' ? 'bg-slate-950 text-white' : 'text-slate-500 hover:bg-slate-100 hover:text-slate-900'
          }`}
        >
          <Network className="h-4 w-4" />
          {t('navNetwork')}
        </button>
        <button
          type="button"
          onClick={() => setAdminTab('audit')}
          aria-current={adminTab === 'audit' ? 'page' : undefined}
          className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-lg px-3 py-2 text-sm font-bold ${
            adminTab === 'audit' ? 'bg-slate-950 text-white' : 'text-slate-500 hover:bg-slate-100 hover:text-slate-900'
          }`}
        >
          <ShieldCheck className="h-4 w-4" />
          {t('navAudit')}
        </button>
      </nav>

      <main id="admin-main" className="app-workspace admin-workspace w-full px-6 py-5">
        {notice && (
          <div aria-live="polite" className={`app-notice mb-5 rounded-lg border px-4 py-3 text-sm font-semibold ${noticeClass(notice.tone)}`}>
            {notice.text}
          </div>
        )}

        {adminTab === 'overview' && (
          <div className="overview-view space-y-5">
            {!onboarded && (
              <div className="flex items-start justify-between gap-4 rounded-xl border border-emerald-300 bg-emerald-50 p-5">
                <div>
                  <p className="font-black">{t('onboardingTitle')}</p>
                  <ol className="mt-2 list-decimal space-y-1 pl-5 text-sm leading-6 text-slate-600">
                    <li>{t('onboardingStep1')}</li>
                    <li>{t('onboardingStep2')}</li>
                    <li>{t('onboardingStep3')}</li>
                  </ol>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    localStorage.setItem('lan-onboarded', '1');
                    setOnboarded(true);
                  }}
                  className="shrink-0 rounded-md border border-emerald-300 bg-white px-3 py-2 text-sm font-bold"
                >
                  {t('gotIt')}
                </button>
              </div>
            )}
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                <p className="text-xs font-semibold text-slate-500">{t('httpService')}</p>
                <p className={`mt-1 text-xl font-black ${server.running ? 'text-emerald-600' : 'text-red-600'}`}>{server.running ? t('running') : t('stopped')}</p>
              </div>
              <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                <p className="text-xs font-semibold text-slate-500">{t('accessUrl')}</p>
                <p className="mt-1 truncate font-mono text-sm font-bold">{preferredAccessBase}</p>
              </div>
              <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                <p className="text-xs font-semibold text-slate-500">{t('shares')}</p>
                <p className="mt-1 text-xl font-black">{shares.length}</p>
              </div>
              <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
                <p className="text-xs font-semibold text-slate-500">{t('transferring')}</p>
                <p className="mt-1 text-xl font-black">{server.activeTransfers.length}</p>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
              <Panel>
                <SectionTitle icon={<Plus className="h-4 w-4" />} title={t('quickStart')} />
                <div className="space-y-3 p-5">
                  <button
                    type="button"
                    onClick={() => setCreateOpen(true)}
                    className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-slate-950 px-4 py-3 text-sm font-bold text-white"
                  >
                    <Plus className="h-4 w-4" />
                    {t('newShare')}
                  </button>
                  <button
                    type="button"
                    onClick={() => setAdminTab('shares')}
                    className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-slate-300 px-4 py-3 text-sm font-bold"
                  >
                    <FolderOpen className="h-4 w-4" />
                    {t('manageShares')}
                  </button>
                  {selectedShare && (
                    <button
                      type="button"
                      onClick={() => copyShareLink(selectedShare)}
                      className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-slate-300 px-4 py-3 text-sm font-bold"
                    >
                      <Copy className="h-4 w-4" />
                      {t('copyLink')}
                    </button>
                  )}
                </div>
              </Panel>

              <Panel>
                <SectionTitle icon={<Network className="h-4 w-4" />} title={t('networkStatus')} />
                <div className="space-y-3 p-5 text-sm">
                  {interfaces.length === 0 ? (
                    <p className="text-slate-500">未发现可用网卡。</p>
                  ) : (
                    interfaces.slice(0, 4).map(item => (
                      <div key={item.id} className="flex items-center justify-between gap-3 rounded-md bg-slate-50 px-3 py-2">
                        <span className="font-mono font-bold">{item.address}</span>
                        <span className="flex items-center gap-2 text-xs text-slate-500">
                          {item.name}
                          {item.bluetooth && <Bluetooth className="h-3.5 w-3.5 text-emerald-600" />}
                        </span>
                      </div>
                    ))
                  )}
                  <div className="flex flex-wrap gap-2">
                    <StatusPill ok={server.running}>HTTP 服务</StatusPill>
                    <StatusPill ok={bluetoothInterfaces.length > 0}>
                      {bluetoothInterfaces.length > 0 ? `蓝牙网络 ${bluetoothInterfaces.length}` : '蓝牙网络未连接'}
                    </StatusPill>
                  </div>
                  <button
                    type="button"
                    onClick={() => setAdminTab('network')}
                    className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold"
                  >
                    <Settings className="h-4 w-4" />
                    打开网络设置
                  </button>
                </div>
              </Panel>
            </div>

            <Panel>
              <SectionTitle
                icon={<FolderOpen className="h-4 w-4" />}
                title={t('recentShares')}
                action={
                  shares.length > 0 ? (
                    <button
                      type="button"
                      onClick={() => setAdminTab('shares')}
                      className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-bold"
                    >
                      {t('viewAll')}
                    </button>
                  ) : undefined
                }
              />
              <div>
                {shares.length === 0 ? (
                  <div className="p-8 text-center text-sm text-slate-500">
                    <FolderOpen className="mx-auto mb-2 h-7 w-7 opacity-40" />
                    {t('noShares')}
                  </div>
                ) : (
                  shares.slice(0, 5).map(share => (
                    <button
                      key={share.id}
                      type="button"
                      onClick={() => {
                        setSelectedShareId(share.id);
                        setAdminTab('shares');
                      }}
                      className="flex w-full items-center justify-between gap-3 border-t border-slate-100 px-5 py-4 text-left hover:bg-slate-50"
                    >
                      <span className="min-w-0">
                        <span className="block truncate font-bold">{share.name}</span>
                        <span className="block truncate text-xs text-slate-500">{share.localPath}</span>
                      </span>
                      <span className="shrink-0 text-xs font-semibold text-slate-500">
                        {isExpired(share.passcodeExpiresAt) ? '已过期' : formatTimeLeft(share.passcodeExpiresAt)}
                      </span>
                    </button>
                  ))
                )}
              </div>
            </Panel>
          </div>
        )}

        {adminTab === 'network' && (
          <div className="grid w-full grid-cols-1 gap-5 xl:grid-cols-[390px_minmax(0,1fr)]">
            <div className="space-y-5">
              <Panel>
            <SectionTitle icon={<Network className="h-4 w-4" />} title={t('networkEntry')} />
            <form onSubmit={applyServerConfig} className="space-y-4 p-5">
              <label className="block space-y-2 text-sm font-semibold">
                <span>{t('bindIp')}</span>
                <select
                  value={serverForm.hostIp}
                  onChange={event => setServerForm(current => ({ ...current, hostIp: event.target.value }))}
                  className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-slate-950"
                >
                  {interfaces.map(item => (
                    <option key={item.id} value={item.address}>
                      {item.address} · {item.name}{item.bluetooth ? ' · 蓝牙网络' : ''} · {item.cidr || '无 CIDR'}
                    </option>
                  ))}
                  {interfaces.length === 0 && <option value="127.0.0.1">127.0.0.1 · 未发现外部网卡</option>}
                </select>
              </label>
              <label className="block space-y-2 text-sm font-semibold">
                <span>{t('servicePort')}</span>
                <input
                  type="number"
                  min={1024}
                  max={65535}
                  value={serverForm.port}
                  onChange={event => setServerForm(current => ({ ...current, port: Number(event.target.value) }))}
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-950"
                />
              </label>
              <label className="block space-y-2 text-sm font-semibold">
                <span>{t('speedLimitLabel')}</span>
                <input
                  type="number"
                  min={0}
                  max={100000}
                  value={serverForm.speedLimitMbps}
                  onChange={event => setServerForm(current => ({ ...current, speedLimitMbps: Number(event.target.value) }))}
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-950"
                />
                <span className="block text-xs font-normal leading-5 text-slate-500">
                  {t('speedLimitHint')}
                </span>
              </label>
              <div className="space-y-3 rounded-md border border-slate-200 bg-slate-50 p-3">
                <label className="toggle-row flex items-center justify-between gap-3 rounded-md border border-slate-200 bg-white p-3 text-sm font-semibold">
                  <span className="flex min-w-0 items-center gap-2">
                    <Lock className="h-4 w-4" />
                    <span>{t('tlsEnable')}</span>
                  </span>
                  <input
                    type="checkbox"
                    checked={serverForm.tlsEnabled}
                    onChange={event => setServerForm(current => ({ ...current, tlsEnabled: event.target.checked }))}
                    className="toggle-control"
                  />
                </label>
                {serverForm.tlsEnabled && (
                  <>
                    <label className="block space-y-1 text-sm font-semibold">
                      <span>{t('tlsCert')}</span>
                      <div className="flex gap-2">
                        <input
                          value={serverForm.tlsCertPath}
                          readOnly
                          placeholder={t('tlsChooseCert')}
                          className="min-w-0 flex-1 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm"
                        />
                        <button
                          type="button"
                          onClick={async () => {
                            const path = await bridge!.chooseFile();
                            if (path) setServerForm(current => ({ ...current, tlsCertPath: path }));
                          }}
                          className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-bold"
                        >
                          <File className="h-3.5 w-3.5" />
                          {t('chooseDir')}
                        </button>
                      </div>
                    </label>
                    <label className="block space-y-1 text-sm font-semibold">
                      <span>{t('tlsKey')}</span>
                      <div className="flex gap-2">
                        <input
                          value={serverForm.tlsKeyPath}
                          readOnly
                          placeholder={t('tlsChooseKey')}
                          className="min-w-0 flex-1 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm"
                        />
                        <button
                          type="button"
                          onClick={async () => {
                            const path = await bridge!.chooseFile();
                            if (path) setServerForm(current => ({ ...current, tlsKeyPath: path }));
                          }}
                          className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-bold"
                        >
                          <File className="h-3.5 w-3.5" />
                          {t('chooseDir')}
                        </button>
                      </div>
                    </label>
                    <button
                      type="button"
                      onClick={() => void generateCert()}
                      className="inline-flex w-full items-center justify-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm font-bold"
                    >
                      <RefreshCw className="h-4 w-4" />
                      {t('tlsGenerate')}
                    </button>
                    <p className="text-xs leading-5 text-slate-500">
                      {t('tlsHint')}
                    </p>
                  </>
                )}
              </div>
              <button
                type="submit"
                disabled={busy}
                className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-slate-950 px-3 py-2.5 text-sm font-bold text-white disabled:opacity-50"
              >
                <RefreshCw className="h-4 w-4" />
                {t('applyRestart')}
              </button>
            </form>
          </Panel>

          <Panel>
            <SectionTitle icon={<Bluetooth className="h-4 w-4" />} title={t('bluetoothPanel')} />
            <div className="space-y-3 p-5 text-sm">
              {bluetoothInterfaces.length > 0 ? (
                <>
                  <div className="flex items-start gap-2 rounded-md border border-emerald-300 bg-emerald-50 px-3 py-2 text-emerald-900">
                    <Bluetooth className="mt-0.5 h-4 w-4 shrink-0" />
                    <span>
                      {t('bluetoothDetected')} <span className="font-mono font-bold">{bluetoothInterfaces.map(item => item.address).join(', ')}</span>
                    </span>
                  </div>
                  <p className="text-xs leading-5 text-slate-600">
                    {t('bluetoothHint')}
                  </p>
                  {selectedShare ? (
                    bluetoothBases.map(base => (
                      <button
                        key={base}
                        type="button"
                        onClick={() => copyShareLink(selectedShare)}
                        className="inline-flex w-full items-center justify-between gap-2 rounded-md border border-slate-300 bg-white px-3 py-2 text-left text-xs font-bold hover:border-slate-950"
                      >
                        <span className="min-w-0 truncate font-mono">{base}</span>
                        <span className="inline-flex shrink-0 items-center gap-1 text-slate-500">
                          <Copy className="h-3.5 w-3.5" />
                          {t('bluetoothCopyLink')}
                        </span>
                      </button>
                    ))
                  ) : (
                    <p className="text-xs text-slate-500">{t('bluetoothCreateFirst')}</p>
                  )}
                </>
              ) : (
                <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-xs leading-5 text-slate-600">
                  <p className="font-bold text-slate-800">{t('bluetoothNotDetected')}</p>
                  <ol className="mt-2 list-decimal space-y-1 pl-4">
                    <li>{t('bluetoothStep1')}</li>
                    <li>{t('bluetoothStep2')}</li>
                    <li>{t('bluetoothStep3')}</li>
                  </ol>
                </div>
              )}
            </div>
          </Panel>

            </div>

            <div className="content-stack space-y-5">
              <Panel className="p-5">
                <h2 className="text-base font-black">{t('networkNotesTitle')}</h2>
                <ul className="mt-3 list-disc space-y-2 pl-5 text-sm leading-6 text-slate-600">
                  <li>{t('networkNote1')}</li>
                  <li>{t('networkNote2')}</li>
                  <li>{t('networkNote3')}</li>
                  <li>{t('networkNote4')}</li>
                </ul>
              </Panel>
            </div>
          </div>
        )}

        {adminTab === 'shares' && (
          <div className="content-stack space-y-5">
          <Panel className="share-command-panel">
            <SectionTitle
              icon={<Server className="h-4 w-4" />}
              title={t('shareStatus')}
              action={
                <button type="button" onClick={() => reloadAdmin()} className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-bold">
                  <RefreshCw className="h-3.5 w-3.5" />
                  刷新
                </button>
              }
            />
            <div className="grid grid-cols-1 border-b border-slate-200 lg:grid-cols-3">
              <div className="share-list max-h-[420px] overflow-auto border-b border-slate-200 lg:border-b-0 lg:border-r">
                {shares.length === 0 ? (
                  <div className="p-5 text-sm text-slate-500">还没有共享。请先选择本机真实目录并创建口令。</div>
                ) : (
                  shares.map(share => (
                    <button
                      type="button"
                      key={share.id}
                      onClick={() => setSelectedShareId(share.id)}
                      className={`share-row block w-full border-b border-slate-100 px-5 py-4 text-left transition ${
                        selectedShare?.id === share.id ? 'is-active bg-slate-950 text-white' : 'hover:bg-slate-50'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-bold">{share.name}</span>
                        {isExpired(share.passcodeExpiresAt) && <AlertTriangle className="h-4 w-4 text-amber-500" />}
                      </div>
                      <p className="mt-1 truncate text-xs opacity-80">{share.localPath}</p>
                    </button>
                  ))
                )}
              </div>

              <div className="lg:col-span-2">
                {selectedShare ? (
                  <div className="share-detail space-y-5 p-5">
                    <div className="metric-grid grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
                      <div className="rounded-md border border-slate-200 p-3">
                        <p className="text-xs text-slate-500">{t('realFiles')}</p>
                        <p className="mt-1 text-xl font-black">{files.length}</p>
                      </div>
                      <div className="rounded-md border border-slate-200 p-3">
                        <p className="text-xs text-slate-500">{t('fileTotal')}</p>
                        <p className="mt-1 text-xl font-black">{formatBytes(totalSize)}</p>
                      </div>
                      <div className="rounded-md border border-slate-200 p-3">
                        <p className="text-xs text-slate-500">{t('passcodeState')}</p>
                        <p className="mt-1 text-sm font-black">{formatTimeLeft(selectedShare.passcodeExpiresAt)}</p>
                      </div>
                      <div className="rounded-md border border-slate-200 p-3">
                        <p className="text-xs text-slate-500">{t('lease')}</p>
                        <p className="mt-1 text-sm font-black">{activeLease ? activeLease.clientIp : t('notOccupied')}</p>
                      </div>
                      <div className="rounded-md border border-slate-200 p-3">
                        <p className="text-xs text-slate-500">访问模式</p>
                        <p className="mt-1 text-sm font-black">{(selectedShare.accessMode || 'exclusive') === 'multi' ? '一对多' : '独占'}</p>
                      </div>
                      <div className="rounded-md border border-slate-200 p-3">
                        <p className="text-xs text-slate-500">{t('mobile')}</p>
                        <p className="mt-1 text-sm font-black">{selectedShare.allowMobileAccess ? t('allowed') : t('disabled')}</p>
                      </div>
                    </div>

                    {(selectedShare.oneTimeAccess || selectedShare.speedLimitMbps || selectedShare.uploadMaxBytes || selectedShare.uploadExtensions) && (
                      <div className="flex flex-wrap gap-2 text-xs">
                        {selectedShare.oneTimeAccess && <StatusPill ok={false}>一次性链接</StatusPill>}
                        {selectedShare.speedLimitMbps ? <StatusPill ok>限速 {selectedShare.speedLimitMbps} MB/s</StatusPill> : null}
                        {selectedShare.uploadMaxBytes ? <StatusPill ok>上传 ≤ {formatBytes(selectedShare.uploadMaxBytes)}</StatusPill> : null}
                        {selectedShare.uploadExtensions ? (
                          <StatusPill ok>白名单 .{selectedShare.uploadExtensions.split(',').join(' .')}</StatusPill>
                        ) : null}
                      </div>
                    )}

                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        disabled={(selectedShare.accessMode || 'exclusive') === 'multi'}
                        onClick={forceRelease}
                        className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <TimerReset className="h-4 w-4" />
                        {t('releaseLease')}
                      </button>
                      <button type="button" onClick={() => requestDelete(selectedShare)} className="inline-flex items-center gap-2 rounded-md border border-red-300 px-3 py-2 text-sm font-bold text-red-700">
                        <Trash2 className="h-4 w-4" />
                        {t('revokeShare')}
                      </button>
                    </div>

                    <ShareLinkCard
                      share={selectedShare}
                      primaryLink={primaryShareLink}
                      alternateLinks={alternateShareLinks}
                      onCopyPrimary={() => copyShareLink(selectedShare)}
                      onCopyAll={() => copyAllShareLinks(selectedShare)}
                    />

                    <div className="rounded-md border border-slate-200 bg-white p-3">
                      <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                        <div>
                          <p className="text-sm font-black">{t('extendExpiry')}</p>
                          <p className="text-xs text-slate-500">{t('extendHint')}</p>
                        </div>
                        <span className="text-xs font-semibold text-slate-500">{formatTimeLeft(selectedShare.passcodeExpiresAt)}</span>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {EXTEND_OPTIONS.map(option => (
                          <button
                            key={option.label}
                            type="button"
                            disabled={busy || !selectedShare.passcodeExpiresAt}
                            onClick={() => extendExpiry(option.ms, option.label)}
                            className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-bold disabled:cursor-not-allowed disabled:opacity-50"
                          >
                            <Plus className="h-3.5 w-3.5" />
                            {option.label}
                          </button>
                        ))}
                        {!selectedShare.passcodeExpiresAt && <span className="text-xs font-semibold text-emerald-700">{t('alwaysValid')}</span>}
                      </div>
                    </div>

                    <form onSubmit={updateShare} className="grid grid-cols-1 gap-3 rounded-md border border-slate-200 bg-slate-50 p-4 md:grid-cols-2">
                      <label className="space-y-1 text-sm font-semibold">
                        <span>{t('description')}</span>
                        <input
                          value={editForm.description}
                          onChange={event => setEditForm(current => ({ ...current, description: event.target.value }))}
                          className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                        />
                      </label>
                      <label className="space-y-1 text-sm font-semibold">
                        <span>{t('resetPasscode')}</span>
                        <input
                          type="password"
                          value={editForm.passcode}
                          onChange={event => setEditForm(current => ({ ...current, passcode: event.target.value }))}
                          placeholder={t('keepPasscode')}
                          className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                        />
                      </label>
                      <label className="space-y-1 text-sm font-semibold">
                        <span>{t('validUntil')}</span>
                        <select
                          value={editForm.duration}
                          onChange={event => setEditForm(current => ({ ...current, duration: event.target.value as ShareDuration }))}
                          className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                        >
                          {DURATION_OPTIONS.map(item => (
                            <option key={item.value} value={item.value}>
                              {item.label}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="space-y-1 text-sm font-semibold">
                        <span>{t('ipWhitelist')}</span>
                        <input
                          value={editForm.ipWhitelist}
                          onChange={event => setEditForm(current => ({ ...current, ipWhitelist: event.target.value }))}
                          placeholder="192.0.2.10, 192.0.2.11"
                          className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                        />
                        <span className="block text-xs font-normal leading-5 text-slate-500">{t('ipWhitelistHint')}</span>
                      </label>
                      <label className="space-y-1 text-sm font-semibold md:col-span-2">
                        <span>{t('accessMode')}</span>
                        <select
                          value={editForm.accessMode}
                          onChange={event => setEditForm(current => ({ ...current, accessMode: event.target.value as ShareAccessMode }))}
                          className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm"
                        >
                          <option value="exclusive">{t('exclusiveOption')}</option>
                          <option value="multi">{t('multiOption')}</option>
                        </select>
                      </label>
                      <label className="toggle-row flex items-center justify-between gap-3 rounded-md border border-slate-200 bg-white p-3 text-sm font-semibold md:col-span-2">
                        <span className="flex min-w-0 items-center gap-2">
                          <Smartphone className="h-4 w-4" />
                          <span>{t('allowMobile')}</span>
                        </span>
                        <input
                          type="checkbox"
                          checked={editForm.allowMobileAccess}
                          onChange={event => setEditForm(current => ({ ...current, allowMobileAccess: event.target.checked }))}
                          className="toggle-control"
                        />
                      </label>
                      <label className="toggle-row flex items-center justify-between gap-3 rounded-md border border-slate-200 bg-white p-3 text-sm font-semibold md:col-span-2">
                        <span className="flex min-w-0 items-center gap-2">
                          <UploadCloud className="h-4 w-4" />
                          <span>{t('allowUpload')}</span>
                        </span>
                        <input
                          type="checkbox"
                          checked={editForm.allowUpload}
                          onChange={event => setEditForm(current => ({ ...current, allowUpload: event.target.checked }))}
                          className="toggle-control"
                        />
                      </label>
                      {editForm.allowUpload && (
                        <label className="block space-y-1 text-sm font-semibold md:col-span-2">
                          <span>{t('receiveDir')}</span>
                          <div className="flex gap-2">
                            <input
                              value={editForm.receiveDir}
                              readOnly
                              placeholder={t('receiveDirPlaceholder')}
                              className="min-w-0 flex-1 rounded-md border border-slate-300 bg-slate-50 px-3 py-2 text-sm"
                            />
                            <button
                              type="button"
                              onClick={async () => {
                                const dir = await bridge!.chooseDirectory();
                                if (dir) setEditForm(current => ({ ...current, receiveDir: dir }));
                              }}
                              className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold"
                            >
                              <FolderOpen className="h-4 w-4" />
                              {t('chooseDir')}
                            </button>
                          </div>
                        </label>
                      )}
                      {editForm.allowUpload && (
                        <div className="grid grid-cols-1 gap-3 md:col-span-2 sm:grid-cols-2">
                          <label className="block space-y-1 text-sm font-semibold">
                            <span>{t('uploadMaxMb')}</span>
                            <input
                              type="number"
                              min={1}
                              value={editForm.uploadMaxBytes}
                              onChange={event => setEditForm(current => ({ ...current, uploadMaxBytes: event.target.value }))}
                              placeholder="默认 4096"
                              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                            />
                          </label>
                          <label className="block space-y-1 text-sm font-semibold">
                            <span>{t('extWhitelist')}</span>
                            <input
                              value={editForm.uploadExtensions}
                              onChange={event => setEditForm(current => ({ ...current, uploadExtensions: event.target.value }))}
                              placeholder="jpg, png, pdf（留空=不限）"
                              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                            />
                          </label>
                        </div>
                      )}
                      <label className="toggle-row flex items-center justify-between gap-3 rounded-md border border-slate-200 bg-white p-3 text-sm font-semibold md:col-span-2">
                        <span className="flex min-w-0 items-center gap-2">
                          <Link2 className="h-4 w-4" />
                          <span>{t('oneTimeLink')}</span>
                        </span>
                        <input
                          type="checkbox"
                          checked={editForm.oneTimeAccess}
                          onChange={event => setEditForm(current => ({ ...current, oneTimeAccess: event.target.checked }))}
                          className="toggle-control"
                        />
                      </label>
                      <label className="block space-y-1 text-sm font-semibold md:col-span-2">
                        <span>{t('perShareLimit')}</span>
                        <input
                          type="number"
                          min={0}
                          value={editForm.speedLimitMbps}
                          onChange={event => setEditForm(current => ({ ...current, speedLimitMbps: event.target.value }))}
                          placeholder="使用全局限速"
                          className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                        />
                      </label>
                      <button type="submit" disabled={busy} className="inline-flex items-center justify-center gap-2 rounded-md bg-slate-950 px-3 py-2 text-sm font-bold text-white md:col-span-2">
                        <Settings className="h-4 w-4" />
                        {t('savePolicy')}
                      </button>
                    </form>
                  </div>
                ) : (
                  <div className="p-5 text-sm text-slate-500">请选择一个共享查看闭环状态。</div>
                )}
              </div>
            </div>
          </Panel>

          <Panel>
            <SectionTitle icon={<HardDrive className="h-4 w-4" />} title="文件与预览" />
            <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px]">
              <div className="max-h-[520px] overflow-auto">
                <table className="data-table w-full text-left text-sm">
                  <thead className="sticky top-0 bg-slate-50 text-xs uppercase text-slate-500">
                    <tr>
                      <th className="px-4 py-3">名称</th>
                      <th className="px-4 py-3">大小</th>
                      <th className="px-4 py-3">修改时间</th>
                      <th className="px-4 py-3"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {files.map(file => (
                      <tr key={file.id} className="border-t border-slate-100">
                        <td className="min-w-0 px-4 py-3">
                          <div className="flex items-center gap-2">
                            {file.type === 'file' && isImageFile(file.name) && selectedShare ? (
                              <img
                                src={convertFileSrc(`${selectedShare.localPath.replace(/[\\/]+$/, '')}/${file.relativePath.replace(/\\/g, '/')}`)}
                                alt=""
                                loading="lazy"
                                className="h-9 w-9 shrink-0 rounded-md object-cover"
                              />
                            ) : (
                              fileIcon(file)
                            )}
                            <div className="min-w-0">
                              <p className="truncate font-semibold">{file.name}</p>
                              <p className="truncate text-xs text-slate-500">{file.relativePath || '.'}</p>
                            </div>
                          </div>
                        </td>
                        <td className="whitespace-nowrap px-4 py-3 font-mono text-xs">{file.type === 'folder' ? '目录' : file.size}</td>
                        <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">{formatDate(file.lastModified)}</td>
                        <td className="px-4 py-3 text-right">
                          <button type="button" onClick={() => previewFile(file)} className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2 py-1 text-xs font-bold">
                            <Eye className="h-3.5 w-3.5" />
                            预览
                          </button>
                        </td>
                      </tr>
                    ))}
                    {files.length === 0 && (
                      <tr>
                        <td colSpan={4} className="px-4 py-10 text-center text-sm text-slate-500">
                          目录为空，或当前目录读取失败。
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              <aside className="border-t border-slate-200 p-4 lg:border-l lg:border-t-0">
                <p className="mb-2 text-xs font-bold uppercase text-slate-500">只读预览</p>
                <p className="mb-3 truncate text-sm font-semibold">{previewPath || '未选择文件'}</p>
                <div className="h-80 overflow-auto rounded-md border border-slate-200 bg-slate-950 p-3 font-mono text-xs leading-5 text-slate-100">
                  {selectedPreview ? (
                    <PreviewResultBody preview={selectedPreview} mediaSrc={adminMediaSrc} />
                  ) : (
                    <div className="flex h-full items-center justify-center text-slate-400">选择文件后从真实磁盘读取预览</div>
                  )}
                </div>
              </aside>
            </div>
          </Panel>

          {selectedShare?.allowUpload && selectedShare.receiveDir && (
            <Panel>
              <SectionTitle
                icon={<UploadCloud className="h-4 w-4" />}
                title={t('receivedFiles')}
                action={
                  <button
                    type="button"
                    onClick={() => bridge!.listReceivedFiles(selectedShare.id).then(setReceivedFiles).catch(() => {})}
                    className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-bold"
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                    {t('refresh')}
                  </button>
                }
              />
              <div className="max-h-[320px] overflow-auto">
                {receivedFiles.length === 0 ? (
                  <div className="p-8 text-center text-sm text-slate-500">{t('receivedEmpty')}</div>
                ) : (
                  <table className="data-table w-full text-left text-xs">
                    <thead className="sticky top-0 bg-slate-50 uppercase text-slate-500">
                      <tr>
                        <th scope="col" className="px-4 py-3">{t('relativePath')}</th>
                        <th scope="col" className="px-4 py-3">{t('fileSize')}</th>
                        <th scope="col" className="px-4 py-3">{t('modifyTime')}</th>
                        <th scope="col" className="px-4 py-3"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {receivedFiles.map(file => (
                        <tr key={file.id} className="border-t border-slate-100">
                          <td className="px-4 py-2 font-semibold">{file.relativePath}</td>
                          <td className="px-4 py-2 font-mono">{file.size}</td>
                          <td className="px-4 py-2 text-slate-500">{formatDate(file.lastModified)}</td>
                          <td className="px-4 py-2 text-right">
                            {file.type === 'file' && (
                              <button
                                type="button"
                                onClick={async () => {
                                  if (!window.confirm(`确认删除回传文件 ${file.relativePath}？此操作不可恢复。`)) return;
                                  try {
                                    await bridge!.deleteReceivedFile(selectedShare.id, file.relativePath);
                                    setReceivedFiles(current => current.filter(item => item.id !== file.id));
                                    setAutoNotice({ tone: 'ok', text: `已删除回传文件 ${file.relativePath}。` });
                                  } catch (error) {
                                    setAutoNotice({ tone: 'error', text: `删除失败：${(error as Error).message}` });
                                  }
                                }}
                                className="inline-flex items-center gap-1 rounded-md border border-red-300 px-2 py-1 font-bold text-red-700"
                              >
                                <Trash2 className="h-3 w-3" />
                                {t('delete')}
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </Panel>
          )}
          </div>
        )}

        {adminTab === 'audit' && (
          <div className="content-stack space-y-5">
          <Panel>
            <SectionTitle
              icon={<ShieldCheck className="h-4 w-4" />}
              title={t('auditPanel')}
              action={
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={async () => {
                      try {
                        const csv = await bridge!.exportAuditCsv();
                        await copyTextWithFallback(csv);
                        setAutoNotice({ tone: 'ok', text: '审计 CSV 已复制到剪贴板。' });
                      } catch (error) {
                        setAutoNotice({ tone: 'error', text: `导出审计失败：${(error as Error).message}` });
                      }
                    }}
                    className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-bold"
                  >
                    <Copy className="h-3.5 w-3.5" />
                      {t('copyCsv')}
                  </button>
                  <button
                    type="button"
                    onClick={() => bridge!.listAuditEvents().then(setAudit).catch(() => {})}
                    className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-bold"
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                      {t('refresh')}
                  </button>
                </div>
              }
            />
            <div className="max-h-[420px] overflow-auto">
              {audit.length === 0 ? (
                <div className="p-8 text-center text-sm text-slate-500">{t('noAudit')}</div>
              ) : (
                <table className="data-table w-full text-left text-xs">
                  <thead className="sticky top-0 bg-slate-50 uppercase text-slate-500">
                    <tr>
                      <th scope="col" className="px-4 py-3">{t('time')}</th>
                      <th scope="col" className="px-4 py-3">{t('event')}</th>
                      <th scope="col" className="px-4 py-3">{t('share')}</th>
                      <th scope="col" className="px-4 py-3">{t('client')}</th>
                      <th scope="col" className="px-4 py-3">{t('object')}</th>
                      <th scope="col" className="px-4 py-3">{t('result')}</th>
                      <th scope="col" className="px-4 py-3">{t('detail')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {audit.slice(0, 60).map((event, index) => (
                      <tr key={`${event.timestamp}-${index}`} className="border-t border-slate-100">
                        <td className="whitespace-nowrap px-4 py-2 font-mono">{formatDate(event.timestamp)}</td>
                        <td className="px-4 py-2 font-semibold">{event.kind}</td>
                        <td className="px-4 py-2">{event.shareName || '-'}</td>
                        <td className="whitespace-nowrap px-4 py-2 font-mono">{event.clientIp}</td>
                        <td className="max-w-[160px] truncate px-4 py-2">{event.fileName || '-'}</td>
                        <td className="px-4 py-2">
                          <StatusPill ok={event.outcome === 'ok'}>{event.outcome}</StatusPill>
                        </td>
                        <td className="max-w-[220px] truncate px-4 py-2 text-slate-500">{event.detail}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
            <p className="border-t border-slate-200 px-4 py-3 text-xs text-slate-500">
              {t('auditFooter')}
            </p>
          </Panel>

          <Panel>
            <SectionTitle
              icon={<Smartphone className="h-4 w-4" />}
              title={t('authenticatedDevices')}
              action={
                <button
                  type="button"
                  onClick={() => bridge!.listDevices().then(setDevices).catch(() => {})}
                  className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-bold"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                  {t('refresh')}
                </button>
              }
            />
            <div className="max-h-[280px] overflow-auto">
              {devices.length === 0 ? (
                <div className="p-8 text-center text-sm text-slate-500">{t('noActiveDevices')}</div>
              ) : (
                <table className="data-table w-full text-left text-xs">
                  <thead className="sticky top-0 bg-slate-50 uppercase text-slate-500">
                    <tr>
                      <th scope="col" className="px-4 py-3">{t('deviceClient')}</th>
                      <th scope="col" className="px-4 py-3">{t('deviceShare')}</th>
                      <th scope="col" className="px-4 py-3">{t('deviceFingerprint')}</th>
                      <th scope="col" className="px-4 py-3">{t('deviceExpiry')}</th>
                      <th scope="col" className="px-4 py-3"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {devices.map(device => (
                      <tr key={device.token} className="border-t border-slate-100">
                        <td className="whitespace-nowrap px-4 py-2 font-mono">{device.clientIp}</td>
                        <td className="px-4 py-2 font-semibold">{device.shareName || '-'}</td>
                        <td className="px-4 py-2 font-mono text-slate-500">{device.fingerprint}…</td>
                        <td className="whitespace-nowrap px-4 py-2 text-slate-500">{formatDate(new Date(device.expiresAt).toISOString())}</td>
                        <td className="px-4 py-2 text-right">
                          <button
                            type="button"
                            onClick={async () => {
                              try {
                                await bridge!.kickDevice(device.token);
                                setDevices(current => current.filter(item => item.token !== device.token));
                                setAutoNotice({ tone: 'ok', text: `已踢下线 ${device.clientIp} 的访客会话。` });
                              } catch (error) {
                                setAutoNotice({ tone: 'error', text: `踢下线失败：${(error as Error).message}` });
                              }
                            }}
                            className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2 py-1 font-bold"
                          >
                            <X className="h-3 w-3" />
                            {t('kickOffline')}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Panel>
          </div>
        )}
      </main>

      {createOpen && (
        <div
          ref={createDialogRef}
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 p-6"
          role="dialog"
          aria-modal="true"
          aria-label={t('newShareTitle')}
        >
          <Panel className="max-h-[90vh] w-full max-w-xl overflow-auto p-6">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-950 text-white">
                  <Plus className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="text-lg font-black">{t('newShareTitle')}</h2>
                  <p className="text-xs text-slate-500">{t('newShareHint')}</p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setCreateOpen(false)}
                className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2 py-1.5 text-xs font-bold"
              >
                <X className="h-3.5 w-3.5" />
                {t('close')}
              </button>
            </div>
            <form onSubmit={createShare} className="space-y-4">
              <label className="block space-y-2 text-sm font-semibold">
                <span>{t('alias')}</span>
                <input
                  value={shareForm.name}
                  onChange={event => setShareForm(current => ({ ...current, name: sanitizeShareName(event.target.value) }))}
                  placeholder="FinanceReports"
                  autoFocus
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-950"
                />
              </label>
              <label className="block space-y-2 text-sm font-semibold">
                <span>{t('localPath')}</span>
                <div className="flex gap-2">
                  <input
                    value={shareForm.localPath}
                    readOnly
                    placeholder={t('localPathPlaceholder')}
                    className="min-w-0 flex-1 rounded-md border border-slate-300 bg-slate-50 px-3 py-2 text-sm"
                  />
                  <button
                    type="button"
                    onClick={chooseFile}
                    className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold"
                  >
                    <File className="h-4 w-4" />
                    {t('file')}
                  </button>
                  <button
                    type="button"
                    onClick={chooseDirectory}
                    className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold"
                  >
                    <FolderOpen className="h-4 w-4" />
                    {t('folderBtn')}
                  </button>
                </div>
              </label>
              <label className="block space-y-2 text-sm font-semibold">
                <span>{t('passcode')}</span>
                <input
                  type="password"
                  value={shareForm.passcode}
                  onChange={event => setShareForm(current => ({ ...current, passcode: event.target.value }))}
                  placeholder={t('noPlaintext')}
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-950"
                />
              </label>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label className="block space-y-2 text-sm font-semibold">
                  <span>{t('passcodeExpiry')}</span>
                  <select
                    value={shareForm.duration}
                    onChange={event => setShareForm(current => ({ ...current, duration: event.target.value as ShareDuration }))}
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                  >
                    {DURATION_OPTIONS.map(item => (
                      <option key={item.value} value={item.value}>
                        {item.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="block space-y-2 text-sm font-semibold">
                  <span>{t('ipWhitelist')}</span>
                  <input
                    value={shareForm.ipWhitelist}
                    onChange={event => setShareForm(current => ({ ...current, ipWhitelist: event.target.value }))}
                    placeholder="192.0.2.10, 192.0.2.11"
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                  />
                </label>
              </div>
              <label className="block space-y-2 text-sm font-semibold">
                <span>{t('accessMode')}</span>
                <select
                  value={shareForm.accessMode}
                  onChange={event => setShareForm(current => ({ ...current, accessMode: event.target.value as ShareAccessMode }))}
                  className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm"
                >
                  <option value="exclusive">{t('exclusiveOption')}</option>
                  <option value="multi">{t('multiOption')}</option>
                </select>
              </label>
              <label className="toggle-row flex items-center justify-between gap-3 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm font-semibold">
                <span className="flex min-w-0 items-center gap-2">
                  <Smartphone className="h-4 w-4" />
                  <span>{t('allowMobile')}</span>
                </span>
                <input
                  type="checkbox"
                  checked={shareForm.allowMobileAccess}
                  onChange={event => setShareForm(current => ({ ...current, allowMobileAccess: event.target.checked }))}
                  className="toggle-control"
                />
              </label>
              <label className="toggle-row flex items-center justify-between gap-3 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm font-semibold">
                <span className="flex min-w-0 items-center gap-2">
                  <UploadCloud className="h-4 w-4" />
                  <span>{t('allowUpload')}</span>
                </span>
                <input
                  type="checkbox"
                  checked={shareForm.allowUpload}
                  onChange={event => setShareForm(current => ({ ...current, allowUpload: event.target.checked }))}
                  className="toggle-control"
                />
              </label>
              {shareForm.allowUpload && (
                <label className="block space-y-2 text-sm font-semibold">
                  <span>{t('receiveDir')}</span>
                  <div className="flex gap-2">
                    <input
                      value={shareForm.receiveDir}
                      readOnly
                      placeholder={t('receiveDirPlaceholder')}
                      className="min-w-0 flex-1 rounded-md border border-slate-300 bg-slate-50 px-3 py-2 text-sm"
                    />
                    <button
                      type="button"
                      onClick={async () => {
                        const dir = await bridge!.chooseDirectory();
                        if (dir) setShareForm(current => ({ ...current, receiveDir: dir }));
                      }}
                      className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold"
                    >
                      <FolderOpen className="h-4 w-4" />
                      {t('chooseDir')}
                    </button>
                  </div>
                </label>
              )}
              {shareForm.allowUpload && (
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <label className="block space-y-2 text-sm font-semibold">
                    <span>{t('uploadMaxMb')}</span>
                    <input
                      type="number"
                      min={1}
                      value={shareForm.uploadMaxBytes}
                      onChange={event => setShareForm(current => ({ ...current, uploadMaxBytes: event.target.value }))}
                      placeholder={t('default4096')}
                      className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                    />
                  </label>
                  <label className="block space-y-2 text-sm font-semibold">
                    <span>{t('extWhitelist')}</span>
                    <input
                      value={shareForm.uploadExtensions}
                      onChange={event => setShareForm(current => ({ ...current, uploadExtensions: event.target.value }))}
                      placeholder={t('extHint')}
                      className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                    />
                  </label>
                </div>
              )}
              <label className="toggle-row flex items-center justify-between gap-3 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm font-semibold">
                <span className="flex min-w-0 items-center gap-2">
                  <Link2 className="h-4 w-4" />
                  <span>{t('oneTimeLink')}</span>
                </span>
                <input
                  type="checkbox"
                  checked={shareForm.oneTimeAccess}
                  onChange={event => setShareForm(current => ({ ...current, oneTimeAccess: event.target.checked }))}
                  className="toggle-control"
                />
              </label>
              <label className="block space-y-2 text-sm font-semibold">
                <span>{t('perShareLimit')}</span>
                <input
                  type="number"
                  min={0}
                  value={shareForm.speedLimitMbps}
                  onChange={event => setShareForm(current => ({ ...current, speedLimitMbps: event.target.value }))}
                  placeholder={t('globalLimit')}
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <label className="block space-y-2 text-sm font-semibold">
                <span>{t('description')}</span>
                <textarea
                  value={shareForm.description}
                  onChange={event => setShareForm(current => ({ ...current, description: event.target.value }))}
                  rows={3}
                  className="w-full resize-none rounded-md border border-slate-300 px-3 py-2 text-sm"
                />
              </label>
              <button
                type="submit"
                disabled={busy}
                className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-slate-950 px-3 py-2.5 text-sm font-bold text-white disabled:opacity-50"
              >
                <Lock className="h-4 w-4" />
                {t('createShareSubmit')}
              </button>
            </form>
          </Panel>
        </div>
      )}

      {pendingDelete && (
        <div
          ref={deleteDialogRef}
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 p-6"
          role="dialog"
          aria-modal="true"
          aria-label={t('confirmRevoke')}
        >
          <Panel className="w-full max-w-md p-6">
            <form
              onSubmit={event => {
                event.preventDefault();
                confirmDelete();
              }}
              className="space-y-4"
            >
              <div className="flex items-start gap-3">
                <ShieldAlert className="mt-0.5 h-6 w-6 shrink-0 text-red-600" />
                <div className="space-y-1">
                  <h2 className="text-lg font-black">{t('confirmRevoke')}</h2>
                  <p className="text-sm leading-6 text-slate-600">
                    {t('confirmRevokeHint')}
                    <span className="mx-1 rounded bg-slate-100 px-1.5 py-0.5 font-mono font-bold">{pendingDelete.name}</span>
                    {t('confirmRevokeName')}
                  </p>
                </div>
              </div>
              <input
                type="text"
                value={confirmAlias}
                aria-describedby={deleteConfirmError ? 'delete-alias-error' : undefined}
                aria-invalid={deleteConfirmError ? true : undefined}
                onChange={event => {
                  setConfirmAlias(event.target.value);
                  setDeleteConfirmError('');
                }}
                placeholder={t('inputAlias')}
                autoFocus
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-950"
              />
                  {deleteConfirmError && (
                    <p id="delete-alias-error" className="text-xs font-semibold text-red-600">
                      {deleteConfirmError}
                    </p>
                  )}
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setPendingDelete(null)}
                  disabled={busy}
                  className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold disabled:opacity-50"
                >
                  {t('cancel')}
                </button>
                <button
                  type="submit"
                  disabled={busy || !confirmAlias.trim()}
                  className="inline-flex items-center gap-2 rounded-md bg-red-700 px-3 py-2 text-sm font-bold text-white disabled:opacity-50"
                >
                  <Trash2 className="h-4 w-4" />
                  {busy ? t('deleting') : t('confirmDelete')}
                </button>
              </div>
            </form>
          </Panel>
        </div>
      )}
    </div>
  );
}

function VisitorView({ accessValue, accessMode }: { accessValue: string; accessMode: 'share' | 'token' }) {
  const { t } = useI18n();
  const tokenKey = `lan-transfer-session:${accessMode}:${accessValue}`;
  const [token, setToken] = useState(() => sessionStorage.getItem(tokenKey) || '');
  const [publicInfo, setPublicInfo] = useState<PublicShareResponse | null>(null);
  const [files, setFiles] = useState<PhysicalFile[]>([]);
  const [passcode, setPasscode] = useState('');
  const [query, setQuery] = useState('');
  const [notice, setNotice] = useState<Notice | null>(null);
  const [uploads, setUploads] = useState<UploadTask[]>([]);
  const uploadXhrRef = useRef(new Map<string, XMLHttpRequest>());
  const [preview, setPreview] = useState<{ path: string; result: PreviewResult } | null>(null);
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());
  const [download, setDownload] = useState<DownloadState>(EMPTY_DOWNLOAD);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [online, setOnline] = useState(() => navigator.onLine);
  const abortRef = useRef<AbortController | null>(null);
  const chunksRef = useRef<Uint8Array[]>([]);
  const downloadedRef = useRef(0);
  const activeFileRef = useRef<PhysicalFile | null>(null);
  const chunkMapRef = useRef<Map<number, Uint8Array>>(new Map());
  const chunkControllersRef = useRef<Map<number, AbortController>>(new Map());
  const queueAbortRef = useRef(false);
  const singleFallbackTriedRef = useRef(false);
  const chunkUploadXhrsRef = useRef(new Map<string, XMLHttpRequest[]>());
  const [receiveDirs, setReceiveDirs] = useState<string[]>([]);
  const [uploadDir, setUploadDir] = useState('');
  const [queueTasks, setQueueTasks] = useState<Array<{ name: string; status: 'pending' | 'downloading' | 'done' | 'error' }>>([]);

  const setAutoNotice = useCallback((next: Notice) => {
    setNotice(next);
    window.setTimeout(() => setNotice(current => (current?.text === next.text ? null : current)), 5000);
  }, []);

  useEffect(() => {
    if (!token || !publicInfo?.share.uploadAllowed) {
      setReceiveDirs([]);
      return;
    }
    fetch('/api/receive-dirs', { headers: authHeaders(token) })
      .then(response => (response.ok ? response.json() : []))
      .then(setReceiveDirs)
      .catch(() => setReceiveDirs([]));
  }, [token, publicInfo?.share.uploadAllowed]);

  const entryQuery = useCallback(() => {
    const params = new URLSearchParams();
    params.set(accessMode, accessValue);
    return params.toString();
  }, [accessMode, accessValue]);

  const loadPublicInfo = useCallback(async () => {
    const info = await fetchJson<PublicShareResponse>(`/api/public-share?${entryQuery()}`);
    setPublicInfo(info);
  }, [entryQuery]);

  const loadFiles = useCallback(
    async (authToken = token) => {
      if (!authToken) return;
      const body = await fetchJson<{ files: PhysicalFile[] }>('/api/files', {
        headers: authHeaders(authToken),
      });
      setFiles(body.files);
    },
    [token],
  );

  useEffect(() => {
    loadPublicInfo().catch(error => setAutoNotice({ tone: 'error', text: `读取共享入口失败：${error.message}` }));
  }, [loadPublicInfo, setAutoNotice]);

  useEffect(() => {
    if (!token) return;
    loadFiles(token).catch(error => {
      sessionStorage.removeItem(tokenKey);
      setToken('');
      setFiles([]);
      setAutoNotice({ tone: 'warn', text: `会话已失效，请重新认证：${error.message}` });
    });
  }, [loadFiles, setAutoNotice, token, tokenKey]);

  useEffect(() => {
    const onOnline = () => setOnline(true);
    const onOffline = () => setOnline(false);
    window.addEventListener('online', onOnline);
    window.addEventListener('offline', onOffline);
    return () => {
      window.removeEventListener('online', onOnline);
      window.removeEventListener('offline', onOffline);
    };
  }, []);

  useEffect(() => {
    if (!token) return;
    const beat = async () => {
      try {
        const body = await fetchJson<{ ok: true; expiresAt: number; share: PublicShareResponse['share'] }>('/api/heartbeat', {
          method: 'POST',
          headers: authHeaders(token),
        });
        setPublicInfo(current => current ? { ...current, share: body.share, passcodeExpired: false } : current);
      } catch (error) {
        setAutoNotice({ tone: 'warn', text: `会话续租失败：${(error as Error).message}` });
      }
    };
    beat();
    const timer = window.setInterval(beat, 15_000);
    return () => window.clearInterval(timer);
  }, [setAutoNotice, token]);

  async function authenticate(event: FormEvent) {
    event.preventDefault();
    try {
      const body = await fetchJson<AuthResponse>('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ [accessMode]: accessValue, passcode }),
      });
      sessionStorage.setItem(tokenKey, body.token);
      setToken(body.token);
      setFiles(body.files);
      setSelectedPaths(new Set());
      setPasscode('');
      setPublicInfo(current => ({
        share: body.share,
        clientIp: body.clientIp,
        ipAllowed: current?.ipAllowed ?? true,
        mobileBlocked: current?.mobileBlocked ?? false,
        passcodeExpired: false,
        occupied: (body.share.accessMode || 'exclusive') !== 'multi',
      }));
      setAutoNotice({ tone: 'ok', text: (body.share.accessMode || 'exclusive') === 'multi' ? '认证成功，已建立只读下载会话。' : '认证成功，独占租约已建立。' });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `认证失败：${(error as Error).message}` });
    }
  }

  async function previewFile(file: PhysicalFile) {
    if (!token) return;
    try {
      const result = await fetchJson<PreviewResult>(`/api/preview?path=${encodeURIComponent(file.relativePath)}`, {
        headers: authHeaders(token),
      });
      setPreview({ path: file.relativePath || file.name, result });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `预览失败：${(error as Error).message}` });
    }
  }

  async function enqueueUploads(fileList: FileList | null, directory = false) {
    if (!fileList || !token) return;
    const files = Array.from(fileList);
    for (const file of files) {
      const relative = directory ? (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name : file.name;
      const parts = relative.split('/');
      const uploadName = parts.pop() || file.name;
      const uploadPath = parts.join('/');
      const effectivePath = uploadPath || uploadDir;
      if (file.size > 4 * 1024 * 1024 * 1024) {
        setUploads(current => [
          ...current,
          { id: crypto.randomUUID(), name: relative, sizeBytes: file.size, phase: 'error', uploadedBytes: 0, percent: 0, speedBps: 0, message: '超过 4 GiB 上传上限' },
        ]);
        continue;
      }
      if (file.size > 8 * 1024 * 1024) {
        void startChunkedUpload(file, effectivePath, uploadName, relative);
        continue;
      }
      const id = crypto.randomUUID();
      const clientShaPromise = file.size <= 64 * 1024 * 1024 ? sha256Blob(file) : Promise.resolve('');
      setUploads(current => [
        ...current,
        { id, name: relative, sizeBytes: file.size, phase: 'pending', uploadedBytes: 0, percent: 0, speedBps: 0, message: '等待上传' },
      ]);
      const xhr = new XMLHttpRequest();
      const query = new URLSearchParams({ token, name: uploadName });
      if (effectivePath) query.set('path', effectivePath);
      xhr.open('POST', `/api/upload?${query.toString()}`);
      xhr.setRequestHeader('Content-Type', 'application/octet-stream');
      const startedAt = Date.now();
      xhr.upload.onprogress = event => {
        if (!event.lengthComputable) return;
        const uploadedBytes = event.loaded;
        const elapsed = Math.max(0.5, (Date.now() - startedAt) / 1000);
        setUploads(current =>
          current.map(item =>
            item.id === id
              ? {
                  ...item,
                  phase: 'uploading',
                  uploadedBytes,
                  percent: Math.min(100, Math.round((uploadedBytes / file.size) * 100)),
                  speedBps: uploadedBytes / elapsed,
                  message: `${formatBytes(uploadedBytes)} / ${formatBytes(file.size)}`,
                }
              : item,
          ),
        );
      };
      xhr.onload = async () => {
        uploadXhrRef.current.delete(id);
        if (xhr.status !== 200) {
          let message = `上传失败（HTTP ${xhr.status}）`;
          try {
            const parsed = JSON.parse(xhr.responseText);
            if (parsed?.error) message = `上传失败：${parsed.error}`;
          } catch {
            // 保留默认错误信息
          }
          setUploads(current => current.map(item => (item.id === id ? { ...item, phase: 'error', message } : item)));
          return;
        }
        setUploads(current =>
          current.map(item => (item.id === id ? { ...item, phase: 'verifying', uploadedBytes: file.size, percent: 100, message: '正在校验 SHA-256' } : item)),
        );
        const receipt = JSON.parse(xhr.responseText) as UploadReceipt;
        const clientSha = await clientShaPromise;
        const verified = !!clientSha && clientSha.toLowerCase() === receipt.sha256.toLowerCase();
        setUploads(current =>
          current.map(item =>
            item.id === id
              ? { ...item, phase: 'done', verified, message: verified ? '回传完成且校验通过' : `已保存（服务端 SHA-256 ${receipt.sha256.slice(0, 12)}…）` }
              : item,
          ),
        );
        setAutoNotice({
          tone: verified ? 'ok' : 'warn',
          text: verified ? `回传完成：${receipt.name}` : `回传已保存但未执行客户端校验：${receipt.name}`,
        });
      };
      xhr.onerror = () => {
        uploadXhrRef.current.delete(id);
        setUploads(current => current.map(item => (item.id === id ? { ...item, phase: 'error', message: '网络错误，上传中断' } : item)));
      };
      xhr.onabort = () => {
        uploadXhrRef.current.delete(id);
        setUploads(current => current.map(item => (item.id === id ? { ...item, phase: 'error', message: '已取消' } : item)));
      };
      uploadXhrRef.current.set(id, xhr);
      xhr.send(file);
    }
  }

  async function startChunkedUpload(file: File, uploadPath: string, uploadName: string, displayName: string) {
    if (!token) return;
    const id = crypto.randomUUID();
    const uploadId = crypto.randomUUID();
    const chunkSize = 4 * 1024 * 1024;
    const total = file.size;
    const query = new URLSearchParams({ token, name: uploadName, uploadId });
    if (uploadPath) query.set('path', uploadPath);
    const base = `/api/upload-chunk?${query.toString()}`;
    setUploads(current => [
      ...current,
      { id, name: displayName, sizeBytes: total, phase: 'pending', uploadedBytes: 0, percent: 0, speedBps: 0, message: '准备分片上传' },
    ]);
    const xhrs: XMLHttpRequest[] = [];
    chunkUploadXhrsRef.current.set(id, xhrs);
    const startedAt = Date.now();
    const update = (uploadedBytes: number, message: string, phase: UploadTask['phase'] = 'uploading') => {
      const elapsed = Math.max(0.5, (Date.now() - startedAt) / 1000);
      setUploads(current =>
        current.map(item =>
          item.id === id
            ? {
                ...item,
                phase,
                uploadedBytes,
                percent: total ? Math.min(100, Math.round((uploadedBytes / total) * 100)) : 0,
                speedBps: uploadedBytes / elapsed,
                message,
              }
            : item,
        ),
      );
    };
    const fail = (message: string) => {
      chunkUploadXhrsRef.current.delete(id);
      setUploads(current => current.map(item => (item.id === id ? { ...item, phase: 'error', message } : item)));
    };
    try {
      let offset = 0;
      try {
        const statusQuery = new URLSearchParams({ token, name: uploadName, uploadId });
        if (uploadPath) statusQuery.set('path', uploadPath);
        const statusResponse = await fetch(`/api/upload-chunk/status?${statusQuery.toString()}`);
        if (statusResponse.ok) {
          const status = (await statusResponse.json()) as { offset?: number };
          offset = Math.min(Number(status.offset) || 0, total);
        }
      } catch {
        // 忽略状态查询失败，从头开始
      }
      if (offset > 0) update(offset, `检测到已上传 ${formatBytes(offset)}，继续分片续传`);
      let finalResponse = '';
      while (offset < total) {
        const end = Math.min(offset + chunkSize, total);
        const chunk = file.slice(offset, end);
        const isFinal = end === total;
        let responseText = '';
        let attempts = 0;
        while (attempts < 3) {
          attempts += 1;
          responseText = await new Promise<string>(resolve => {
            const xhr = new XMLHttpRequest();
            xhrs.push(xhr);
            xhr.open('PUT', `${base}&offset=${offset}&final=${isFinal ? 'true' : 'false'}`);
            xhr.setRequestHeader('Content-Type', 'application/octet-stream');
            xhr.upload.onprogress = event => {
              if (event.lengthComputable) update(offset + event.loaded, `分片上传中 ${formatBytes(offset + event.loaded)} / ${formatBytes(total)}`);
            };
            xhr.onload = () => resolve(xhr.status === 200 ? xhr.responseText : '');
            xhr.onerror = () => resolve('');
            xhr.onabort = () => resolve('');
            xhr.send(chunk);
          });
          if (responseText) break;
          await new Promise(resolve => window.setTimeout(resolve, 500 * attempts));
        }
        if (!responseText) throw new Error('分片上传失败，请重试');
        offset = end;
        update(offset, `已上传 ${formatBytes(offset)} / ${formatBytes(total)}`);
        if (isFinal) finalResponse = responseText;
      }
      if (!finalResponse) throw new Error('分片上传未完成');
      const receipt = JSON.parse(finalResponse) as UploadReceipt;
      setUploads(current =>
        current.map(item => (item.id === id ? { ...item, phase: 'verifying', uploadedBytes: total, percent: 100, message: '正在校验 SHA-256' } : item)),
      );
      const clientSha = file.size <= 64 * 1024 * 1024 ? await sha256Blob(file) : '';
      const verified = !!clientSha && clientSha.toLowerCase() === receipt.sha256.toLowerCase();
      chunkUploadXhrsRef.current.delete(id);
      setUploads(current =>
        current.map(item =>
          item.id === id
            ? { ...item, phase: 'done', verified, message: verified ? '回传完成且校验通过' : `已保存（服务端 SHA-256 ${receipt.sha256.slice(0, 12)}…）` }
            : item,
        ),
      );
      setAutoNotice({ tone: verified ? 'ok' : 'warn', text: verified ? `回传完成：${receipt.name}` : `回传已保存但未执行客户端校验：${receipt.name}` });
    } catch (error) {
      fail(`分片上传失败：${(error as Error).message}`);
    }
  }

  function cancelUpload(id: string) {
    uploadXhrRef.current.get(id)?.abort();
    (chunkUploadXhrsRef.current.get(id) || []).forEach(xhr => xhr.abort());
    chunkUploadXhrsRef.current.delete(id);
  }

  function toggleSelected(path: string) {
    setSelectedPaths(current => {
      const next = new Set(current);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  }

  function pauseDownload() {
    abortRef.current?.abort();
    chunkControllersRef.current.forEach(controller => controller.abort());
  }

  function chunkedRanges(total: number, count: number) {
    if (total <= 0) return [] as Array<{ start: number; end: number }>;
    const chunkSize = Math.ceil(total / count);
    const ranges: Array<{ start: number; end: number }> = [];
    for (let index = 0; index < count; index += 1) {
      const start = index * chunkSize;
      const end = Math.min(start + chunkSize - 1, total - 1);
      if (start > end) break;
      ranges.push({ start, end });
    }
    return ranges;
  }

  function recalcDownloaded() {
    let total = 0;
    chunkMapRef.current.forEach(bytes => {
      total += bytes.byteLength;
    });
    downloadedRef.current = total;
    return total;
  }

  async function fetchChunk(file: PhysicalFile, total: number, range: { start: number; end: number }, index: number, startedAt: number, rangeCount: number) {
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const controller = new AbortController();
      chunkControllersRef.current.set(index, controller);
      try {
        const response = await fetch(`/api/download?path=${encodeURIComponent(file.relativePath)}`, {
          headers: { Authorization: `Bearer ${token}`, Range: `bytes=${range.start}-${range.end}` },
          signal: controller.signal,
        });
        if (response.status !== 206) throw new Error(await readJsonError(response));
        const bytes = new Uint8Array(await response.arrayBuffer());
        const expected = range.end - range.start + 1;
        if (bytes.byteLength !== expected) throw new Error(`分块 ${range.start}-${range.end} 长度不符`);
        chunkMapRef.current.set(index, bytes);
        chunkControllersRef.current.delete(index);
        const downloaded = recalcDownloaded();
        const elapsed = Math.max(0.5, (Date.now() - startedAt) / 1000);
        setDownload(current => ({
          ...current,
          phase: 'streaming',
          downloadedBytes: downloaded,
          totalBytes: total,
          percent: total ? Math.min(100, Math.round((downloaded / total) * 100)) : 0,
          speedBps: downloaded / elapsed,
          message: `并发分片 ${chunkMapRef.current.size}/${rangeCount} · ${formatBytes(downloaded)} / ${formatBytes(total)}`,
        }));
        return;
      } catch (error) {
        if (controller.signal.aborted) throw error;
        if (attempt === 3) throw error;
        await new Promise(resolve => window.setTimeout(resolve, 250 * attempt));
      }
    }
  }

  async function downloadSingleStream(file: PhysicalFile, hash: HashResult) {
    const controller = new AbortController();
    abortRef.current = controller;
    const response = await fetch(`/api/download?path=${encodeURIComponent(file.relativePath)}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(await readJsonError(response));
    const bytes = new Uint8Array(await response.arrayBuffer());
    chunksRef.current = [bytes];
    downloadedRef.current = bytes.byteLength;
    setDownload(current => ({ ...current, phase: 'streaming', downloadedBytes: bytes.byteLength, totalBytes: hash.sizeBytes, percent: 100, message: '单流下载完成，开始校验' }));
  }

  async function downloadFile(file: PhysicalFile, resume = false): Promise<boolean> {
    if (!token || file.type === 'folder') return false;
    activeFileRef.current = file;
    if (!resume) {
      chunksRef.current = [];
      downloadedRef.current = 0;
      chunkMapRef.current = new Map();
      chunkControllersRef.current = new Map();
      singleFallbackTriedRef.current = false;
      setReceipt(null);
    }
    const startedAt = Date.now();
    try {
      setDownload({
        ...EMPTY_DOWNLOAD,
        phase: 'connecting',
        fileName: file.name,
        downloadedBytes: downloadedRef.current,
        message: resume ? '正在恢复并发分片下载' : '正在请求文件指纹和下载通道',
      });
      const hash = await fetchJson<HashResult>(`/api/hash?path=${encodeURIComponent(file.relativePath)}`, {
        headers: authHeaders(token),
      });
      const total = hash.sizeBytes;

      if (total <= 512 * 1024) {
        await downloadSingleStream(file, hash);
      } else {
        abortRef.current = null;
        const ranges = chunkedRanges(total, total < 8 * 1024 * 1024 ? 2 : 4);
        setDownload(current => ({ ...current, phase: 'streaming', totalBytes: total, percent: 0, message: `正在建立 ${ranges.length} 路并发分片下载` }));
        let chunkedFailed = false;
        try {
          await Promise.all(ranges.map((range, index) => fetchChunk(file, total, range, index, startedAt, ranges.length)));
        } catch (error) {
          const chunkAborted = [...chunkControllersRef.current.values()].some((controller: AbortController) => controller.signal.aborted);
          if (chunkAborted || abortRef.current?.signal.aborted === true) throw error;
          if (!singleFallbackTriedRef.current) {
            singleFallbackTriedRef.current = true;
            chunkedFailed = true;
            setDownload(current => ({ ...current, phase: 'connecting', message: '分片下载不稳定，已切换为单流重试' }));
            await downloadSingleStream(file, hash);
          } else {
            throw error;
          }
        }
        if (!chunkedFailed) {
          chunksRef.current = [];
          for (let index = 0; index < ranges.length; index += 1) {
            const bytes = chunkMapRef.current.get(index);
            if (bytes) chunksRef.current.push(bytes);
          }
        }
      }

      setDownload(current => ({ ...current, phase: 'verifying', percent: 100, message: '正在进行 SHA-256 真实校验' }));
      const blob = new Blob(chunksRef.current, { type: 'application/octet-stream' });
      const clientSha256 = await sha256Blob(blob);
      const verified = clientSha256.toLowerCase() === hash.sha256.toLowerCase() && blob.size === hash.sizeBytes;
      const receiptNext = {
        fileName: file.name,
        transferId: `LAN-${Date.now().toString(36).toUpperCase()}`,
        sizeBytes: blob.size,
        sha256: clientSha256,
        md5: hash.md5,
        verified,
        finishedAt: new Date().toLocaleString(),
      };
      setReceipt(receiptNext);
      if (!verified) {
        setDownload(current => ({ ...current, phase: 'error', message: '文件校验失败，已阻止自动保存。', resumeAvailable: false }));
        setAutoNotice({ tone: 'error', text: '服务端与客户端 SHA-256 或大小不一致，下载未落盘。' });
        return false;
      }
      triggerDownload(blob, receiptNext.fileName);
      setDownload(current => ({ ...current, phase: 'complete', message: '校验通过，浏览器已保存文件。', resumeAvailable: false }));
      setAutoNotice({ tone: 'ok', text: `${file.name} 已完成真实传输和指纹校验。` });
      return true;
    } catch (error) {
      const chunkAborted = [...chunkControllersRef.current.values()].some((controller: AbortController) => controller.signal.aborted);
      const singleAborted = abortRef.current?.signal.aborted === true;
      if (chunkAborted || singleAborted) {
        const downloaded = recalcDownloaded();
        setDownload(current => ({
          ...current,
          phase: 'paused',
          downloadedBytes: downloaded,
          resumeAvailable: downloaded > 0,
          message: `已暂停在 ${formatBytes(downloaded)}，续传会跳过已完成分片。`,
        }));
        return false;
      }
      const downloaded = recalcDownloaded();
      setDownload(current => ({ ...current, phase: 'error', message: (error as Error).message, resumeAvailable: downloaded > 0 }));
      setAutoNotice({ tone: 'error', text: `下载失败：${(error as Error).message}` });
      return false;
    }
  }

  async function resumeDownload() {
    if (activeFileRef.current) await downloadFile(activeFileRef.current, true);
  }

  async function downloadSelectedQueue() {
    if (!token) return;
    const files = filteredFiles.filter(file => file.type === 'file' && selectedPaths.has(file.relativePath));
    if (files.length === 0) {
      setAutoNotice({ tone: 'warn', text: '请先勾选至少一个文件。' });
      return;
    }
    queueAbortRef.current = false;
    setQueueTasks(files.map(file => ({ name: file.name, status: 'pending' as const })));
    setAutoNotice({ tone: 'info', text: `已加入 ${files.length} 个文件到批量下载队列。` });
    for (let index = 0; index < files.length; index += 1) {
      const file = files[index];
      if (queueAbortRef.current) break;
      setQueueTasks(current => current.map(task => (task.name === file.name ? { ...task, status: 'downloading' } : task)));
      const ok = await downloadFile(file);
      setQueueTasks(current => current.map(task => (task.name === file.name ? { ...task, status: ok ? 'done' : 'error' } : task)));
      if (!ok) break;
    }
  }

  function cancelQueue() {
    queueAbortRef.current = true;
    pauseDownload();
  }

  async function downloadArchive() {
    if (!token || selectedPaths.size === 0) return;
    const controller = new AbortController();
    abortRef.current = controller;
    const paths = Array.from(selectedPaths);
    const startedAt = Date.now();
    chunksRef.current = [];
    downloadedRef.current = 0;
    try {
      setReceipt(null);
      const archiveBaseName = publicInfo?.share.name || 'EncryptedShare';
      setDownload({
        ...EMPTY_DOWNLOAD,
        phase: 'archiving',
        fileName: `${archiveBaseName}.zip`,
        message: '正在创建打包任务…',
      });
      const startResponse = await fetch('/api/archive/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders(token) },
        body: JSON.stringify({ paths }),
        signal: controller.signal,
      });
      if (!startResponse.ok) throw new Error(await readJsonError(startResponse));
      const job = (await startResponse.json()) as { jobId: string };
      const jobId = job.jobId;

      let jobState: { status: string; totalBytes: number; doneBytes: number; sha256: string; md5: string; error?: string };
      while (true) {
        const progressResponse = await fetch(`/api/archive/progress?jobId=${encodeURIComponent(jobId)}`, {
          headers: authHeaders(token),
          signal: controller.signal,
        });
        if (!progressResponse.ok) throw new Error(await readJsonError(progressResponse));
        jobState = (await progressResponse.json()) as typeof jobState;
        if (jobState.status === 'error') throw new Error(jobState.error || '打包失败');
        if (jobState.status === 'ready') break;
        const percent = jobState.totalBytes ? Math.min(99, Math.round((jobState.doneBytes / jobState.totalBytes) * 100)) : 0;
        setDownload(current => ({
          ...current,
          phase: 'archiving',
          percent,
          message: `服务端打包中 ${formatBytes(jobState.doneBytes)} / ${formatBytes(jobState.totalBytes)}`,
        }));
        await new Promise(resolve => window.setTimeout(resolve, 400));
      }

      const response = await fetch(`/api/archive/download?jobId=${encodeURIComponent(jobId)}`, {
        headers: authHeaders(token),
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(await readJsonError(response));
      const total = Number(response.headers.get('Content-Length') || 0);
      const fileName = contentDispositionFileName(response.headers.get('Content-Disposition'), `${archiveBaseName}.zip`);
      if (!response.body) {
        const bytes = new Uint8Array(await response.arrayBuffer());
        chunksRef.current.push(bytes);
        downloadedRef.current += bytes.byteLength;
      } else {
        const reader = response.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            chunksRef.current.push(value);
            downloadedRef.current += value.byteLength;
            const elapsed = Math.max(0.5, (Date.now() - startedAt) / 1000);
            setDownload(current => ({
              ...current,
              phase: 'streaming',
              fileName,
              totalBytes: total,
              downloadedBytes: downloadedRef.current,
              percent: total ? Math.min(100, Math.round((downloadedRef.current / total) * 100)) : 0,
              speedBps: downloadedRef.current / elapsed,
              message: `ZIP 实际下发 ${formatBytes(downloadedRef.current)}${total ? ` / ${formatBytes(total)}` : ''}`,
            }));
          }
        }
      }
      setDownload(current => ({ ...current, phase: 'verifying', percent: 100, message: '正在校验 ZIP 指纹' }));
      const blob = new Blob(chunksRef.current, { type: 'application/zip' });
      const clientSha256 = await sha256Blob(blob);
      const serverSha256 = response.headers.get('X-Content-SHA256') || '';
      const serverMd5 = response.headers.get('X-Content-MD5') || '';
      const verified = !!serverSha256 && clientSha256.toLowerCase() === serverSha256.toLowerCase() && (!total || blob.size === total);
      setReceipt({
        fileName,
        transferId: `ZIP-${Date.now().toString(36).toUpperCase()}`,
        sizeBytes: blob.size,
        sha256: clientSha256,
        md5: serverMd5,
        verified,
        finishedAt: new Date().toLocaleString(),
      });
      if (!verified) {
        setDownload(current => ({ ...current, phase: 'error', message: 'ZIP 指纹不一致，已阻止保存。' }));
        return;
      }
      triggerDownload(blob, fileName);
      setDownload(current => ({ ...current, phase: 'complete', message: 'ZIP 包已完成真实打包与校验。' }));
    } catch (error) {
      if (controller.signal.aborted) {
        setDownload(current => ({ ...current, phase: 'paused', message: '打包任务已取消，服务端会在超时后自动清理。' }));
        return;
      }
      setDownload(current => ({ ...current, phase: 'error', message: (error as Error).message }));
      setAutoNotice({ tone: 'error', text: `打包下载失败：${(error as Error).message}` });
    }
  }

  const filteredFiles = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return files;
    return files.filter(file => `${file.name} ${file.relativePath}`.toLowerCase().includes(q));
  }, [files, query]);
  const visibleSelectablePaths = useMemo(() => filteredFiles.map(file => file.relativePath), [filteredFiles]);
  const allVisibleSelected = visibleSelectablePaths.length > 0 && visibleSelectablePaths.every(path => selectedPaths.has(path));

  useEffect(() => {
    const validPaths = new Set(files.map(file => file.relativePath));
    setSelectedPaths(current => {
      const next = new Set(Array.from(current).filter(path => validPaths.has(path)));
      return next.size === current.size ? current : next;
    });
  }, [files]);

  function toggleAllVisible() {
    setSelectedPaths(current => {
      const next = new Set(current);
      if (allVisibleSelected) visibleSelectablePaths.forEach(path => next.delete(path));
      else visibleSelectablePaths.forEach(path => next.add(path));
      return next;
    });
  }

  const canUseShare =
    !!publicInfo &&
    publicInfo.ipAllowed &&
    !publicInfo.mobileBlocked &&
    !publicInfo.passcodeExpired &&
    (!publicInfo.occupied || !!token);
  const visitorMediaSrc = preview ? `/api/preview-media?${new URLSearchParams({ path: preview.path, token }).toString()}` : undefined;
  const visitorFileCount = files.filter(file => file.type === 'file').length;
  const visitorTotalSize = files.reduce((sum, file) => sum + (file.type === 'file' ? file.sizeBytes : 0), 0);

  return (
    <div className="app-shell visitor-shell min-h-screen bg-[#f3f6f8] text-slate-950">
      <a
        href="#visitor-main"
        className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-slate-950 focus:px-3 focus:py-2 focus:text-sm focus:font-bold focus:text-white"
      >
        {t('skipToContent')}
      </a>
      <header className="app-header visitor-header border-b border-slate-200 bg-white">
        <div className="app-header-inner flex w-full flex-col gap-4 px-6 py-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-3">
            <div className="brand-mark flex h-12 w-12 items-center justify-center rounded-lg bg-slate-950 text-white">
              <Download className="h-7 w-7" />
            </div>
            <div>
              <h1 className="text-2xl font-black tracking-tight">{publicInfo?.share.name || (accessMode === 'token' ? '加密访问链接' : accessValue)}</h1>
              <p className="text-sm text-slate-600">{t('visitorTagline')}</p>
            </div>
          </div>
          <div className="status-deck flex flex-wrap items-center gap-2">
            <StatusPill ok={online}>{online ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />} {t('localNetwork')}</StatusPill>
            <StatusPill ok={!!token}>{t('authSession')}</StatusPill>
            {publicInfo && (
              <span className="endpoint-chip rounded-full border border-slate-300 bg-slate-50 px-3 py-1 text-xs font-mono font-semibold">
                {t('clientIp')} {publicInfo.clientIp}
              </span>
            )}
          </div>
        </div>
      </header>

      <main id="visitor-main" className="app-workspace visitor-workspace grid w-full grid-cols-1 gap-5 px-6 py-5 xl:grid-cols-[340px_minmax(0,1fr)]">
        <div className="visitor-rail space-y-5">
          {notice && (
            <div aria-live="polite" className={`app-notice rounded-lg border px-4 py-3 text-sm font-semibold ${noticeClass(notice.tone)}`}>
              {notice.text}
            </div>
          )}

          <Panel className="access-panel overflow-hidden">
            <div className="access-panel-head bg-slate-950 p-5 text-white">
              <div className="flex items-center gap-3">
                <ShieldCheck className="h-6 w-6" />
                <div>
                  <h2 className="font-black">{t('entryStatus')}</h2>
                  <p className="text-xs text-slate-300">{token ? t('established') : t('waitingAuth')}</p>
                </div>
              </div>
            </div>
            {publicInfo ? (
              <div className="space-y-3 p-5 text-sm">
                <div className="flex items-center justify-between gap-3 rounded-md bg-slate-50 px-3 py-2">
                  <span className="text-slate-500">{t('shareDesc')}</span>
                  <span className="text-right font-semibold">{publicInfo.share.description || t('noneDesc')}</span>
                </div>
                <div className="flex items-center justify-between gap-3 rounded-md bg-slate-50 px-3 py-2">
                  <span className="text-slate-500">{t('passcodeHint')}</span>
                  <span className="font-semibold">{publicInfo.share.passcodeHint}</span>
                </div>
                <div className="flex items-center justify-between gap-3 rounded-md bg-slate-50 px-3 py-2">
                  <span className="text-slate-500">{t('passcodeExpiry')}</span>
                  <span className="font-semibold">{formatTimeLeft(publicInfo.share.passcodeExpiresAt)}</span>
                </div>
                <div className="flex items-center justify-between gap-3 rounded-md bg-slate-50 px-3 py-2">
                  <span className="text-slate-500">{t('accessMode')}</span>
                  <span className="font-semibold">{(publicInfo.share.accessMode || 'exclusive') === 'multi' ? t('multiMode') : t('exclusiveMode')}</span>
                </div>
                <div className="flex flex-wrap gap-2 pt-2">
                  <StatusPill ok={publicInfo.ipAllowed}>IP 白名单</StatusPill>
                  <StatusPill ok={!publicInfo.mobileBlocked}>
                    {publicInfo.share.allowMobileAccess ? '移动端允许' : publicInfo.mobileBlocked ? '移动端关闭' : '桌面访问'}
                  </StatusPill>
                  <StatusPill ok={!publicInfo.passcodeExpired}>口令有效</StatusPill>
                  <StatusPill ok={(publicInfo.share.accessMode || 'exclusive') === 'multi' || !publicInfo.occupied || !!token}>
                    {(publicInfo.share.accessMode || 'exclusive') === 'multi' ? '一对多' : '独占锁'}
                  </StatusPill>
                </div>
              </div>
            ) : (
              <div className="p-5 text-sm text-slate-500">正在读取服务端入口策略...</div>
            )}
          </Panel>

          {publicInfo && !canUseShare && !token && (
            <Panel className="border-red-200 bg-red-50 p-5">
              <div className="flex items-start gap-3">
                <ShieldAlert className="mt-0.5 h-5 w-5 text-red-700" />
                <div className="space-y-2 text-sm text-red-900">
                  <p className="font-black">当前请求被服务端策略阻断</p>
                  {!publicInfo.ipAllowed && <p>你的真实请求 IP 不在白名单中。</p>}
                  {publicInfo.mobileBlocked && <p>手机和平板访问未被这个共享的开关允许。</p>}
                  {publicInfo.passcodeExpired && <p>共享口令已经过期。</p>}
                  {publicInfo.occupied && <p>该共享正在被另一台电脑独占访问。</p>}
                </div>
              </div>
            </Panel>
          )}

          {!token && (
            <Panel>
              <SectionTitle icon={<KeyRound className="h-4 w-4" />} title={t('securityAuth')} />
              <form onSubmit={authenticate} className="space-y-4 p-5">
                <input
                  type="password"
                  value={passcode}
                  disabled={!publicInfo || !canUseShare}
                  onChange={event => setPasscode(event.target.value)}
                  placeholder={t('enterPasscode')}
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-950 disabled:bg-slate-100"
                />
                <button
                  type="submit"
                  disabled={!publicInfo || !canUseShare || !passcode.trim()}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-slate-950 px-3 py-2.5 text-sm font-bold text-white disabled:opacity-50"
                >
                  <Lock className="h-4 w-4" />
                  {t('enterFiles')}
                </button>
              </form>
            </Panel>
          )}

          {token && (
            <Panel>
              <SectionTitle icon={<Activity className="h-4 w-4" />} title={t('transferProgress')} />
              <div className="space-y-4 p-5">
                <div>
                  <div className="mb-2 flex items-center justify-between text-xs font-semibold text-slate-500">
                    <span>{download.fileName || t('noFileSelected')}</span>
                    <span>{download.percent}%</span>
                  </div>
                  <div
                    className="transfer-track h-2 overflow-hidden rounded-full bg-slate-200"
                    role="progressbar"
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={download.percent}
                    aria-label={download.fileName || t('transferProgress')}
                  >
                    <div className="transfer-fill h-full bg-slate-950 transition-all" style={{ width: `${download.percent}%` }} />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="rounded-md border border-slate-200 p-3">
                    <p className="text-slate-500">{t('received')}</p>
                    <p className="mt-1 font-mono font-bold">{formatBytes(download.downloadedBytes)}</p>
                  </div>
                  <div className="rounded-md border border-slate-200 p-3">
                    <p className="text-slate-500">{t('speed')}</p>
                    <p className="mt-1 font-mono font-bold">{download.speedBps ? `${formatBytes(download.speedBps)}/s` : t('waiting')}</p>
                  </div>
                </div>
                <p className="text-sm text-slate-600">{download.message}</p>
                <div className="flex flex-wrap gap-2">
                  {download.phase === 'streaming' && (
                    <button type="button" onClick={pauseDownload} className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold">
                      <Pause className="h-4 w-4" />
                      {t('pause')}
                    </button>
                  )}
                  {download.phase === 'archiving' && (
                    <button type="button" onClick={pauseDownload} className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold">
                      <X className="h-4 w-4" />
                      {t('cancelPacking')}
                    </button>
                  )}
                  {download.resumeAvailable && (
                    <button type="button" onClick={resumeDownload} className="inline-flex items-center gap-2 rounded-md bg-slate-950 px-3 py-2 text-sm font-bold text-white">
                      <Play className="h-4 w-4" />
                      {t('resume')}
                    </button>
                  )}
                  {selectedPaths.size > 0 && (
                    <button type="button" onClick={downloadArchive} className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold">
                      <Archive className="h-4 w-4" />
                      {t('zipDownload')}
                    </button>
                  )}
                </div>
                {queueTasks.length > 0 && (
                  <div className="space-y-2">
                    {queueTasks.map(task => (
                      <div key={task.name} className="flex items-center justify-between gap-2 text-xs">
                        <span className="min-w-0 truncate font-semibold">{task.name}</span>
                        <span className="flex shrink-0 items-center gap-1 text-slate-500">
                          {task.status === 'done' && <Check className="h-3.5 w-3.5 text-emerald-600" />}
                          {task.status === 'error' && <AlertTriangle className="h-3.5 w-3.5 text-red-500" />}
                          {task.status === 'downloading' && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
                          {task.status === 'pending' ? '等待中' : task.status === 'downloading' ? '下载中' : task.status === 'done' ? '完成' : '失败'}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Panel>
          )}

          {token && publicInfo?.share.uploadAllowed && (
            <Panel>
              <SectionTitle icon={<UploadCloud className="h-4 w-4" />} title={t('uploadBack')} />
              <div className="space-y-3 p-5">
                {receiveDirs.length > 0 && (
                  <label className="block space-y-1 text-xs font-semibold text-slate-500">
                    <span>{t('uploadTargetDir')}</span>
                    <select
                      value={uploadDir}
                      onChange={event => setUploadDir(event.target.value)}
                      className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900"
                    >
                      <option value="">{t('uploadRoot')}</option>
                      {receiveDirs.map(dir => (
                        <option key={dir} value={dir}>
                          {dir}
                        </option>
                      ))}
                    </select>
                  </label>
                )}
                <label className="flex cursor-pointer items-center justify-center gap-2 rounded-md border border-dashed border-slate-300 px-3 py-4 text-sm font-bold text-slate-600 hover:border-slate-950 focus-within:ring-2 focus-within:ring-slate-950/30">
                  <UploadCloud className="h-4 w-4" />
                  {t('chooseFiles')}
                  <input
                    type="file"
                    multiple
                    className="sr-only"
                    onChange={event => {
                      void enqueueUploads(event.target.files);
                      event.target.value = '';
                    }}
                  />
                </label>
                <label className="flex cursor-pointer items-center justify-center gap-2 rounded-md border border-dashed border-slate-300 px-3 py-4 text-sm font-bold text-slate-600 hover:border-slate-950 focus-within:ring-2 focus-within:ring-slate-950/30">
                  <FolderOpen className="h-4 w-4" />
                  {t('chooseFolder')}
                  <input
                    type="file"
                    multiple
                    webkitdirectory=""
                    className="sr-only"
                    onChange={event => {
                      void enqueueUploads(event.target.files, true);
                      event.target.value = '';
                    }}
                  />
                </label>
                <p className="text-xs leading-5 text-slate-500">
                  {t('uploadLimitHint')}
                </p>
                {uploads.length > 0 && (
                  <div className="space-y-3">
                    {uploads.map(task => (
                      <div key={task.id} className="rounded-md border border-slate-200 p-3">
                        <div className="flex items-center justify-between gap-2 text-xs">
                          <span className="min-w-0 truncate font-semibold">{task.name}</span>
                          <span className="shrink-0 text-slate-500">{task.percent}%</span>
                        </div>
                        <div
                          className="mt-2 h-1.5 overflow-hidden rounded-full bg-slate-200"
                          role="progressbar"
                          aria-valuemin={0}
                          aria-valuemax={100}
                          aria-valuenow={task.percent}
                          aria-label={task.name}
                        >
                          <div
                            className={`h-full transition-all ${task.phase === 'error' ? 'bg-red-500' : task.phase === 'done' ? 'bg-emerald-500' : 'bg-slate-950'}`}
                            style={{ width: `${task.percent}%` }}
                          />
                        </div>
                        <div className="mt-2 flex items-center justify-between gap-2 text-xs text-slate-500">
                          <span className="min-w-0 truncate">{task.message}</span>
                          <div className="flex shrink-0 items-center gap-2">
                            {(task.phase === 'pending' || task.phase === 'uploading') && (
                              <button
                                type="button"
                                onClick={() => cancelUpload(task.id)}
                                className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2 py-1 font-bold"
                              >
                                <X className="h-3 w-3" />
                                取消
                              </button>
                            )}
                            {task.phase === 'done' && <Check className={`h-4 w-4 ${task.verified ? 'text-emerald-600' : 'text-amber-500'}`} />}
                            {task.phase === 'error' && <AlertTriangle className="h-4 w-4 text-red-500" />}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </Panel>
          )}

          {receipt && (
            <Panel className="p-5">
              <div className="mb-3 flex items-center gap-2">
                <Check className={`h-5 w-5 ${receipt.verified ? 'text-emerald-600' : 'text-red-600'}`} />
                <h2 className="font-black">{t('receipt')}</h2>
              </div>
              <dl className="space-y-2 text-xs">
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500">{t('fileName')}</dt>
                  <dd className="truncate font-semibold">{receipt.fileName}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500">{t('fileSize')}</dt>
                  <dd className="font-mono">{formatBytes(receipt.sizeBytes)}</dd>
                </div>
                <div className="space-y-1">
                  <dt className="text-slate-500">SHA-256</dt>
                  <dd className="break-all rounded bg-slate-50 p-2 font-mono">{receipt.sha256}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500">{t('status')}</dt>
                  <dd className={receipt.verified ? 'font-bold text-emerald-700' : 'font-bold text-red-700'}>{receipt.verified ? t('verified') : t('verifyFailed')}</dd>
                </div>
              </dl>
              <button
                type="button"
                onClick={async () => {
                  const text = `文件：${receipt.fileName}\n大小：${formatBytes(receipt.sizeBytes)}\nSHA-256：${receipt.sha256}\n状态：${receipt.verified ? '校验通过' : '校验失败'}\n时间：${receipt.finishedAt}`;
                  try {
                    await navigator.clipboard.writeText(text);
                    setAutoNotice({ tone: 'ok', text: '传输回执已复制。' });
                  } catch {
                    setAutoNotice({ tone: 'warn', text: '复制回执失败，请手动选择。' });
                  }
                }}
                className="mt-3 inline-flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-bold"
              >
                <Copy className="h-3.5 w-3.5" />
                  {t('copyReceipt')}
              </button>
            </Panel>
          )}
        </div>

        <div className="visitor-content space-y-5">
          {token && (
            <div className="visitor-metrics grid grid-cols-2 gap-3 md:grid-cols-4">
              <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
                <p className="text-xs font-semibold text-slate-500">{t('files')}</p>
                <p className="mt-1 text-2xl font-black">{visitorFileCount}</p>
              </div>
              <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
                <p className="text-xs font-semibold text-slate-500">{t('totalSize')}</p>
                <p className="mt-1 text-2xl font-black">{formatBytes(visitorTotalSize)}</p>
              </div>
              <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
                <p className="text-xs font-semibold text-slate-500">{t('selectedCount')}</p>
                <p className="mt-1 text-2xl font-black">{selectedPaths.size}</p>
              </div>
              <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
                <p className="text-xs font-semibold text-slate-500">{t('status')}</p>
                <p className="mt-1 text-lg font-black">{download.phase === 'idle' ? t('pending') : download.phase === 'complete' ? t('complete') : t('inProgress')}</p>
              </div>
            </div>
          )}
          <Panel>
            <SectionTitle
              icon={<FolderOpen className="h-4 w-4" />}
              title={t('realFileList')}
              action={
                token && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-500">{t('selectedCount')} {selectedPaths.size}</span>
                    <button
                      type="button"
                      onClick={() => void downloadSelectedQueue()}
                      className="inline-flex items-center gap-1 rounded-md bg-slate-950 px-2.5 py-1.5 text-xs font-bold text-white"
                    >
                      <Download className="h-3.5 w-3.5" />
                      {t('batchDownload')}
                    </button>
                    <button type="button" onClick={() => loadFiles()} className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-bold">
                      <RefreshCw className="h-3.5 w-3.5" />
                      {t('refresh')}
                    </button>
                  </div>
                )
              }
            />
            {!token ? (
              <div className="p-8 text-center text-sm text-slate-500">认证通过后才会从服务端读取真实目录清单。</div>
            ) : (
              <>
                <div className="border-b border-slate-200 p-4">
                  <label className="flex items-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-2">
                    <Search className="h-4 w-4 text-slate-400" />
                    <input
                      value={query}
                      onChange={event => setQuery(event.target.value)}
                      placeholder={t('searchHint')}
                      className="min-w-0 flex-1 bg-transparent text-sm outline-none"
                    />
                  </label>
                </div>
                <div className="hidden max-h-[620px] overflow-auto md:block">
                  <table className="data-table w-full text-left text-sm">
                    <thead className="sticky top-0 bg-slate-50 text-xs uppercase text-slate-500">
                      <tr>
                        <th scope="col" className="w-10 px-4 py-3">
                          <input
                            type="checkbox"
                            checked={allVisibleSelected}
                            disabled={visibleSelectablePaths.length === 0}
                            onChange={toggleAllVisible}
                            className="h-4 w-4"
                            aria-label="全选当前列表"
                          />
                        </th>
                        <th scope="col" className="px-4 py-3">{t('fileName')}</th>
                        <th scope="col" className="px-4 py-3">{t('fileSize')}</th>
                        <th scope="col" className="px-4 py-3">修改时间</th>
                        <th scope="col" className="px-4 py-3"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFiles.map(file => (
                        <tr key={file.id} className="border-t border-slate-100">
                          <td className="px-4 py-3">
                            <input
                              type="checkbox"
                              checked={selectedPaths.has(file.relativePath)}
                              onChange={() => toggleSelected(file.relativePath)}
                              className="h-4 w-4"
                            />
                          </td>
                          <td className="min-w-0 px-4 py-3">
                            <div className="flex items-center gap-2">
                              {file.type === 'file' && isImageFile(file.name) ? (
                                <img
                                  src={`/api/preview-media?${new URLSearchParams({ path: file.relativePath, token }).toString()}`}
                                  alt=""
                                  loading="lazy"
                                  className="h-9 w-9 shrink-0 rounded-md object-cover"
                                />
                              ) : (
                                fileIcon(file)
                              )}
                              <div className="min-w-0">
                                <p className="truncate font-semibold">{file.name}</p>
                                <p className="truncate text-xs text-slate-500">{file.relativePath || '.'}</p>
                              </div>
                            </div>
                          </td>
                          <td className="whitespace-nowrap px-4 py-3 font-mono text-xs">{file.type === 'folder' ? t('folder') : file.size}</td>
                          <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">{formatDate(file.lastModified)}</td>
                          <td className="px-4 py-3 text-right">
                            <div className="flex justify-end gap-2">
                              <button type="button" onClick={() => previewFile(file)} className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2 py-1 text-xs font-bold">
                                <Eye className="h-3.5 w-3.5" />
                                {t('preview')}
                              </button>
                              {file.type === 'file' && (
                                <button type="button" onClick={() => downloadFile(file)} className="inline-flex items-center gap-1 rounded-md bg-slate-950 px-2 py-1 text-xs font-bold text-white">
                                  <Download className="h-3.5 w-3.5" />
                                  {t('download')}
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                      {filteredFiles.length === 0 && (
                        <tr>
                          <td colSpan={5} className="px-4 py-10 text-center text-sm text-slate-500">
                            <FolderOpen className="mx-auto mb-2 h-7 w-7 opacity-40" />
                            {t('noMatch')}
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                <div className="md:hidden">
                  <div className="flex items-center justify-between border-b border-slate-100 px-4 py-2 text-xs text-slate-500">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={allVisibleSelected}
                        disabled={visibleSelectablePaths.length === 0}
                        onChange={toggleAllVisible}
                        className="h-4 w-4"
                        aria-label="全选当前列表"
                      />
                      {t('selectAll')}
                    </label>
                    <span>{t('selectedCount')} {selectedPaths.size}</span>
                  </div>
                  <div className="divide-y divide-slate-100">
                    {filteredFiles.map(file => (
                      <div key={file.id} className="flex items-center gap-3 px-4 py-3">
                        <input
                          type="checkbox"
                          checked={selectedPaths.has(file.relativePath)}
                          onChange={() => toggleSelected(file.relativePath)}
                          className="h-4 w-4 shrink-0"
                          aria-label={`选择 ${file.name}`}
                        />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            {file.type === 'file' && isImageFile(file.name) ? (
                              <img
                                src={`/api/preview-media?${new URLSearchParams({ path: file.relativePath, token }).toString()}`}
                                alt=""
                                loading="lazy"
                                className="h-9 w-9 shrink-0 rounded-md object-cover"
                              />
                            ) : (
                              fileIcon(file)
                            )}
                            <p className="truncate font-semibold">{file.name}</p>
                          </div>
                          <p className="truncate text-xs text-slate-500">
                            {file.type === 'folder' ? t('folder') : file.size}
                            {file.lastModified ? ` · ${formatDate(file.lastModified)}` : ''}
                          </p>
                        </div>
                        <button
                          type="button"
                          onClick={() => previewFile(file)}
                          className="inline-flex shrink-0 items-center gap-1 rounded-md border border-slate-300 px-2 py-1.5 text-xs font-bold"
                        >
                          <Eye className="h-3.5 w-3.5" />
                          {t('preview')}
                        </button>
                        {file.type === 'file' && (
                          <button
                            type="button"
                            onClick={() => downloadFile(file)}
                            className="inline-flex shrink-0 items-center gap-1 rounded-md bg-slate-950 px-2 py-1.5 text-xs font-bold text-white"
                          >
                            <Download className="h-3.5 w-3.5" />
                            {t('download')}
                          </button>
                        )}
                      </div>
                    ))}
                    {filteredFiles.length === 0 && (
                      <div className="px-4 py-10 text-center text-sm text-slate-500">
                        <FolderOpen className="mx-auto mb-2 h-7 w-7 opacity-40" />
                        {t('noMatch')}
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}
          </Panel>

          <Panel>
            <SectionTitle icon={<Eye className="h-4 w-4" />} title={t('readonlyPreview')} />
            <div className="grid grid-cols-1 lg:grid-cols-[1fr_280px]">
              <div className="h-96 overflow-auto bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-100">
                {preview ? (
                  <PreviewResultBody preview={preview.result} mediaSrc={visitorMediaSrc} />
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">{t('previewHint')}</div>
                )}
              </div>
              <div className="border-t border-slate-200 p-4 text-sm lg:border-l lg:border-t-0">
                <p className="mb-2 text-xs font-bold uppercase text-slate-500">{t('currentObject')}</p>
                <p className="break-all font-semibold">{preview?.path || t('notSelected')}</p>
                <div className="mt-4 rounded-md border border-slate-200 bg-slate-50 p-3 text-xs leading-5 text-slate-600">
                  预览接口只读取文本白名单类型，二进制文件不会伪造内容。下载校验以服务端 SHA-256 和客户端实际接收字节为准。
                </div>
              </div>
            </div>
          </Panel>
        </div>
      </main>
    </div>
  );
}

function BrowserEntryHelp() {
  return (
    <div className="flex min-h-screen w-full items-center justify-center bg-slate-100 p-6 text-slate-950">
      <Panel className="max-w-3xl p-8">
        <div className="flex items-start gap-4">
          <ShieldAlert className="mt-1 h-8 w-8 text-amber-600" />
          <div className="space-y-3">
            <h1 className="text-2xl font-black">缺少加密访问链接</h1>
            <p className="text-sm leading-6 text-slate-600">
              这台电脑正在用普通浏览器访问共享主机根地址。访客端需要使用管理端复制出来的加密链接，链接格式应包含
              <code className="mx-1 rounded bg-slate-100 px-1.5 py-0.5 font-mono">?token=...</code>
              。裸地址不会进入管理端，也不会暴露文件列表。
            </p>
            <div className="rounded-md border border-slate-200 bg-slate-50 p-3 text-xs leading-5 text-slate-600">
              在共享主机的桌面管理端选择共享项，点击“复制加密链接”，再把完整链接发到这台电脑打开。
            </div>
          </div>
        </div>
      </Panel>
    </div>
  );
}

class RenderErrorBoundary extends React.Component<{ children: ReactNode }, { error: string }> {
  declare props: Readonly<{ children: ReactNode }>;

  state = { error: '' };

  static getDerivedStateFromError(error: Error) {
    return { error: error.message || '页面渲染异常' };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Render failed', error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="flex min-h-screen w-full items-center justify-center bg-slate-100 p-6 text-slate-950">
        <Panel className="max-w-xl p-8">
          <div className="flex items-start gap-4">
            <ShieldAlert className="mt-1 h-7 w-7 text-red-700" />
            <div className="space-y-4">
              <div>
                <h1 className="text-xl font-black">页面状态异常</h1>
                <p className="mt-2 text-sm leading-6 text-slate-600">
                  当前会话没有丢失，刷新页面后会从服务端重新读取共享状态和文件清单。
                </p>
              </div>
              <div className="break-all rounded-md border border-red-200 bg-red-50 p-3 text-xs font-semibold text-red-900">{this.state.error}</div>
              <button
                type="button"
                onClick={() => window.location.reload()}
                className="inline-flex items-center gap-2 rounded-md bg-slate-950 px-3 py-2 text-sm font-bold text-white"
              >
                <RefreshCw className="h-4 w-4" />
                重新载入
              </button>
            </div>
          </div>
        </Panel>
      </div>
    );
  }
}

function AppContent() {
  const access = useMemo(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get('token') || '';
    const share = params.get('share') || '';
    if (token) return { mode: 'token' as const, value: token };
    if (share) return { mode: 'share' as const, value: share };
    return null;
  }, []);
  if (access) return <VisitorView accessMode={access.mode} accessValue={access.value} />;
  if (window.lanTransfer) return <AdminView />;
  return <BrowserEntryHelp />;
}

function App() {
  return (
    <RenderErrorBoundary>
      <AppContent />
    </RenderErrorBoundary>
  );
}

export default App;
