import React, { useCallback, useEffect, useMemo, useRef, useState, type ErrorInfo, type FormEvent, type ReactNode } from 'react';
import QRCodeLib from 'qrcode';
import {
  Activity,
  AlertTriangle,
  Archive,
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
  TimerReset,
  Trash2,
  UploadCloud,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react';
import type {
  AuthResponse,
  HashResult,
  NetworkInterfaceInfo,
  PhysicalFile,
  PreviewResult,
  PublicShareResponse,
  ServerState,
  ShareRecord,
} from './types';
import { sha256Bytes } from './utils/hash';

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
  const [interfaces, setInterfaces] = useState<NetworkInterfaceInfo[]>([]);
  const [server, setServer] = useState<ServerState>(DEFAULT_SERVER_STATE);
  const [shares, setShares] = useState<ShareRecord[]>([]);
  const [files, setFiles] = useState<PhysicalFile[]>([]);
  const [selectedShareId, setSelectedShareId] = useState('');
  const [selectedPreview, setSelectedPreview] = useState<PreviewResult | null>(null);
  const [previewPath, setPreviewPath] = useState('');
  const [notice, setNotice] = useState<Notice | null>(null);
  const [busy, setBusy] = useState(false);
  const [serverForm, setServerForm] = useState({ hostIp: '127.0.0.1', port: 8787 });
  const [shareForm, setShareForm] = useState({
    name: '',
    localPath: '',
    description: '',
    passcode: '',
    duration: '4h' as ShareDuration,
    ipWhitelist: '',
    accessMode: 'exclusive' as ShareAccessMode,
    allowMobileAccess: false,
  });
  const [editForm, setEditForm] = useState({
    description: '',
    passcode: '',
    duration: '4h' as ShareDuration,
    ipWhitelist: '',
    accessMode: 'exclusive' as ShareAccessMode,
    allowMobileAccess: false,
  });

  const selectedShare = shares.find(item => item.id === selectedShareId) || shares[0];

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
    setServerForm({ hostIp: serverState.hostIp, port: serverState.port });
    setShares(shareRows);
    setSelectedShareId(current => current || shareRows[0]?.id || '');
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
                真实网卡枚举、目录选择、口令哈希和本机 HTTP 服务都由 Electron 主进程提供。普通浏览器页面不会获得这些权限。
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
      const next = await bridge!.setServerConfig({ hostIp: serverForm.hostIp, port: Number(serverForm.port) });
      setServer(next);
      setAutoNotice({ tone: next.running ? 'ok' : 'warn', text: next.running ? '内网 HTTP 服务已按真实网卡地址重启。' : next.error });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `服务配置失败：${(error as Error).message}` });
    } finally {
      setBusy(false);
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
      });
      setShareForm({ name: '', localPath: '', description: '', passcode: '', duration: '4h', ipWhitelist: '', accessMode: 'exclusive', allowMobileAccess: false });
      await reloadAdmin();
      setSelectedShareId(created.id);
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
      });
      await reloadAdmin();
      setAutoNotice({ tone: 'ok', text: '共享安全策略已写入本机状态文件，旧明文口令不会保留。' });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `更新失败：${(error as Error).message}` });
    } finally {
      setBusy(false);
    }
  }

  async function deleteShare(share: ShareRecord) {
    const confirmed = window.confirm('确认撤销这个共享？访问口令、加密链接和独占租约会立即失效。');
    if (!confirmed) return;

    const typedName = window.prompt(`请再次输入共享别名 "${share.name}" 来确认撤销。`);
    if (typedName !== share.name) {
      setAutoNotice({ tone: 'warn', text: '撤销已取消：二次确认的共享别名不匹配。' });
      return;
    }

    setBusy(true);
    try {
      await bridge!.deleteShare(share.id);
      setSelectedShareId('');
      await reloadAdmin();
      setAutoNotice({ tone: 'ok', text: '共享已撤销，HTTP 访问端不再能认证。' });
    } catch (error) {
      setAutoNotice({ tone: 'error', text: `撤销失败：${(error as Error).message}` });
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
  const preferredAccessBase = `http://${preferredAccessHost}:${runningPort}`;
  const accessBases = Array.from(
    new Set([
      preferredAccessBase,
      ...(server.accessUrls || []),
      ...interfaces.map(item => `http://${item.address}:${runningPort}`),
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

  return (
    <div className="app-shell admin-shell min-h-screen bg-slate-100 text-slate-950">
      <header className="app-header border-b border-slate-200 bg-white">
        <div className="app-header-inner flex w-full flex-col gap-4 px-6 py-5 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-3">
            <div className="brand-mark flex h-12 w-12 items-center justify-center rounded-lg bg-slate-950 text-white">
              <UploadCloud className="h-7 w-7" />
            </div>
            <div>
              <h1 className="text-2xl font-black tracking-tight">内网闪传</h1>
              <p className="text-sm text-slate-600">本地文件直达，连接、授权与传输状态一屏掌握。</p>
            </div>
          </div>
          <div className="status-deck flex flex-wrap items-center gap-2">
            <StatusPill ok={server.running}>HTTP {server.running ? '运行中' : '未运行'}</StatusPill>
            <StatusPill ok={!server.error}>{server.error ? '服务异常' : '无启动错误'}</StatusPill>
            <StatusPill ok={server.activeTransfers.length === 0}>
              {server.activeTransfers.length > 0 ? `传输中 ${server.activeTransfers.length}` : '无传输任务'}
            </StatusPill>
            <StatusPill ok={server.runtimeIdleGuard.active}>运行期防锁屏</StatusPill>
            <span className="endpoint-chip rounded-full border border-slate-300 bg-slate-50 px-3 py-1 text-xs font-mono font-semibold">
              {preferredAccessBase}
            </span>
          </div>
        </div>
      </header>

      <main className="app-workspace admin-workspace grid w-full grid-cols-1 gap-5 px-6 py-5 xl:grid-cols-[390px_minmax(0,1fr)]">
        <div className="control-rail space-y-5">
          <Panel>
            <SectionTitle icon={<Network className="h-4 w-4" />} title="网络入口" />
            <form onSubmit={applyServerConfig} className="space-y-4 p-5">
              <label className="block space-y-2 text-sm font-semibold">
                <span>绑定访问 IP</span>
                <select
                  value={serverForm.hostIp}
                  onChange={event => setServerForm(current => ({ ...current, hostIp: event.target.value }))}
                  className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm outline-none focus:border-slate-950"
                >
                  {interfaces.map(item => (
                    <option key={item.id} value={item.address}>
                      {item.address} · {item.name} · {item.cidr || '无 CIDR'}
                    </option>
                  ))}
                  {interfaces.length === 0 && <option value="127.0.0.1">127.0.0.1 · 未发现外部网卡</option>}
                </select>
              </label>
              <label className="block space-y-2 text-sm font-semibold">
                <span>服务端口</span>
                <input
                  type="number"
                  min={1024}
                  max={65535}
                  value={serverForm.port}
                  onChange={event => setServerForm(current => ({ ...current, port: Number(event.target.value) }))}
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-950"
                />
              </label>
              <button
                type="submit"
                disabled={busy}
                className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-slate-950 px-3 py-2.5 text-sm font-bold text-white disabled:opacity-50"
              >
                <RefreshCw className="h-4 w-4" />
                应用并重启内网服务
              </button>
            </form>
          </Panel>

          <Panel>
            <SectionTitle icon={<Plus className="h-4 w-4" />} title="创建共享" />
            <form onSubmit={createShare} className="space-y-4 p-5">
              <label className="block space-y-2 text-sm font-semibold">
                <span>共享别名</span>
                <input
                  value={shareForm.name}
                  onChange={event => setShareForm(current => ({ ...current, name: sanitizeShareName(event.target.value) }))}
                  placeholder="FinanceReports"
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-950"
                />
              </label>
              <label className="block space-y-2 text-sm font-semibold">
                <span>本机物理文件或目录</span>
                <div className="flex gap-2">
                  <input
                    value={shareForm.localPath}
                    readOnly
                    placeholder="请选择真实文件或目录"
                    className="min-w-0 flex-1 rounded-md border border-slate-300 bg-slate-50 px-3 py-2 text-sm"
                  />
                  <button
                    type="button"
                    onClick={chooseFile}
                    className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold"
                  >
                    <File className="h-4 w-4" />
                    文件
                  </button>
                  <button
                    type="button"
                    onClick={chooseDirectory}
                    className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold"
                  >
                    <FolderOpen className="h-4 w-4" />
                    文件夹
                  </button>
                </div>
              </label>
              <label className="block space-y-2 text-sm font-semibold">
                <span>访问口令</span>
                <input
                  type="password"
                  value={shareForm.passcode}
                  onChange={event => setShareForm(current => ({ ...current, passcode: event.target.value }))}
                  placeholder="不会明文保存"
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-950"
                />
              </label>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label className="block space-y-2 text-sm font-semibold">
                  <span>口令有效期</span>
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
                  <span>IP 白名单</span>
                  <input
                    value={shareForm.ipWhitelist}
                    onChange={event => setShareForm(current => ({ ...current, ipWhitelist: event.target.value }))}
                    placeholder="172.27.60.96, 172.27.60.97"
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                  />
                </label>
              </div>
              <label className="block space-y-2 text-sm font-semibold">
                <span>访问模式</span>
                <select
                  value={shareForm.accessMode}
                  onChange={event => setShareForm(current => ({ ...current, accessMode: event.target.value as ShareAccessMode }))}
                  className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm"
                >
                  <option value="exclusive">独占访问：同一时间只允许一台电脑</option>
                  <option value="multi">一对多下载：多台授权电脑可同时访问</option>
                </select>
              </label>
              <label className="toggle-row flex items-center justify-between gap-3 rounded-md border border-slate-200 bg-slate-50 p-3 text-sm font-semibold">
                <span className="flex min-w-0 items-center gap-2">
                  <Smartphone className="h-4 w-4" />
                  <span>允许移动端访问</span>
                </span>
                <input
                  type="checkbox"
                  checked={shareForm.allowMobileAccess}
                  onChange={event => setShareForm(current => ({ ...current, allowMobileAccess: event.target.checked }))}
                  className="toggle-control"
                />
              </label>
              <label className="block space-y-2 text-sm font-semibold">
                <span>说明</span>
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
                创建共享并写入口令哈希
              </button>
            </form>
          </Panel>
        </div>

        <div className="content-stack space-y-5">
          {notice && (
            <div className={`app-notice rounded-lg border px-4 py-3 text-sm font-semibold ${noticeClass(notice.tone)}`}>{notice.text}</div>
          )}

          <Panel className="share-command-panel">
            <SectionTitle
              icon={<Server className="h-4 w-4" />}
              title="共享与状态"
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
                        <p className="text-xs text-slate-500">真实文件</p>
                        <p className="mt-1 text-xl font-black">{files.length}</p>
                      </div>
                      <div className="rounded-md border border-slate-200 p-3">
                        <p className="text-xs text-slate-500">文件总量</p>
                        <p className="mt-1 text-xl font-black">{formatBytes(totalSize)}</p>
                      </div>
                      <div className="rounded-md border border-slate-200 p-3">
                        <p className="text-xs text-slate-500">口令状态</p>
                        <p className="mt-1 text-sm font-black">{formatTimeLeft(selectedShare.passcodeExpiresAt)}</p>
                      </div>
                      <div className="rounded-md border border-slate-200 p-3">
                        <p className="text-xs text-slate-500">独占租约</p>
                        <p className="mt-1 text-sm font-black">{activeLease ? activeLease.clientIp : '未占用'}</p>
                      </div>
                      <div className="rounded-md border border-slate-200 p-3">
                        <p className="text-xs text-slate-500">访问模式</p>
                        <p className="mt-1 text-sm font-black">{(selectedShare.accessMode || 'exclusive') === 'multi' ? '一对多' : '独占'}</p>
                      </div>
                      <div className="rounded-md border border-slate-200 p-3">
                        <p className="text-xs text-slate-500">移动端</p>
                        <p className="mt-1 text-sm font-black">{selectedShare.allowMobileAccess ? '允许' : '关闭'}</p>
                      </div>
                    </div>

                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        disabled={(selectedShare.accessMode || 'exclusive') === 'multi'}
                        onClick={forceRelease}
                        className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        <TimerReset className="h-4 w-4" />
                        释放独占锁
                      </button>
                      <button type="button" onClick={() => deleteShare(selectedShare)} className="inline-flex items-center gap-2 rounded-md border border-red-300 px-3 py-2 text-sm font-bold text-red-700">
                        <Trash2 className="h-4 w-4" />
                        撤销共享
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
                          <p className="text-sm font-black">有效期一键加时</p>
                          <p className="text-xs text-slate-500">仅延长访问有效期，不重置口令、不释放独占锁、不影响正在下载的访客。</p>
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
                        {!selectedShare.passcodeExpiresAt && <span className="text-xs font-semibold text-emerald-700">当前已永不过期</span>}
                      </div>
                    </div>

                    <form onSubmit={updateShare} className="grid grid-cols-1 gap-3 rounded-md border border-slate-200 bg-slate-50 p-4 md:grid-cols-2">
                      <label className="space-y-1 text-sm font-semibold">
                        <span>说明</span>
                        <input
                          value={editForm.description}
                          onChange={event => setEditForm(current => ({ ...current, description: event.target.value }))}
                          className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                        />
                      </label>
                      <label className="space-y-1 text-sm font-semibold">
                        <span>重置口令</span>
                        <input
                          type="password"
                          value={editForm.passcode}
                          onChange={event => setEditForm(current => ({ ...current, passcode: event.target.value }))}
                          placeholder="留空表示不改口令"
                          className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                        />
                      </label>
                      <label className="space-y-1 text-sm font-semibold">
                        <span>有效期</span>
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
                        <span>IP 白名单</span>
                        <input
                          value={editForm.ipWhitelist}
                          onChange={event => setEditForm(current => ({ ...current, ipWhitelist: event.target.value }))}
                          placeholder="172.27.60.96, 172.27.60.97"
                          className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                        />
                        <span className="block text-xs font-normal leading-5 text-slate-500">多个特定 IP 用逗号、空格或换行分隔；也兼容 CIDR 和通配段。</span>
                      </label>
                      <label className="space-y-1 text-sm font-semibold md:col-span-2">
                        <span>访问模式</span>
                        <select
                          value={editForm.accessMode}
                          onChange={event => setEditForm(current => ({ ...current, accessMode: event.target.value as ShareAccessMode }))}
                          className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm"
                        >
                          <option value="exclusive">独占访问：同一时间只允许一台电脑</option>
                          <option value="multi">一对多下载：多台授权电脑可同时访问</option>
                        </select>
                      </label>
                      <label className="toggle-row flex items-center justify-between gap-3 rounded-md border border-slate-200 bg-white p-3 text-sm font-semibold md:col-span-2">
                        <span className="flex min-w-0 items-center gap-2">
                          <Smartphone className="h-4 w-4" />
                          <span>允许移动端访问</span>
                        </span>
                        <input
                          type="checkbox"
                          checked={editForm.allowMobileAccess}
                          onChange={event => setEditForm(current => ({ ...current, allowMobileAccess: event.target.checked }))}
                          className="toggle-control"
                        />
                      </label>
                      <button type="submit" disabled={busy} className="inline-flex items-center justify-center gap-2 rounded-md bg-slate-950 px-3 py-2 text-sm font-bold text-white md:col-span-2">
                        <Settings className="h-4 w-4" />
                        保存安全策略
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
                            {fileIcon(file)}
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
                    selectedPreview.type === 'text' ? (
                      <pre className="whitespace-pre-wrap break-words">{selectedPreview.content}</pre>
                    ) : (
                      <div className="flex h-full items-center justify-center text-center text-slate-300">{selectedPreview.content}</div>
                    )
                  ) : (
                    <div className="flex h-full items-center justify-center text-slate-400">选择文件后从真实磁盘读取预览</div>
                  )}
                </div>
              </aside>
            </div>
          </Panel>
        </div>
      </main>
    </div>
  );
}

function VisitorView({ accessValue, accessMode }: { accessValue: string; accessMode: 'share' | 'token' }) {
  const tokenKey = `lan-transfer-session:${accessMode}:${accessValue}`;
  const [token, setToken] = useState(() => sessionStorage.getItem(tokenKey) || '');
  const [publicInfo, setPublicInfo] = useState<PublicShareResponse | null>(null);
  const [files, setFiles] = useState<PhysicalFile[]>([]);
  const [passcode, setPasscode] = useState('');
  const [query, setQuery] = useState('');
  const [notice, setNotice] = useState<Notice | null>(null);
  const [preview, setPreview] = useState<{ path: string; result: PreviewResult } | null>(null);
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());
  const [download, setDownload] = useState<DownloadState>(EMPTY_DOWNLOAD);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [online, setOnline] = useState(() => navigator.onLine);
  const abortRef = useRef<AbortController | null>(null);
  const chunksRef = useRef<Uint8Array[]>([]);
  const downloadedRef = useRef(0);
  const activeFileRef = useRef<PhysicalFile | null>(null);

  const setAutoNotice = useCallback((next: Notice) => {
    setNotice(next);
    window.setTimeout(() => setNotice(current => (current?.text === next.text ? null : current)), 5000);
  }, []);

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
  }

  async function downloadFile(file: PhysicalFile, resume = false) {
    if (!token || file.type === 'folder') return;
    const controller = new AbortController();
    abortRef.current = controller;
    activeFileRef.current = file;

    if (!resume) {
      chunksRef.current = [];
      downloadedRef.current = 0;
      setReceipt(null);
    }

    const offset = resume ? downloadedRef.current : 0;
    const startedAt = Date.now();
    try {
      setDownload({
        ...EMPTY_DOWNLOAD,
        phase: 'connecting',
        fileName: file.name,
        downloadedBytes: offset,
        message: offset > 0 ? `从 ${formatBytes(offset)} 继续请求 Range 分块` : '正在请求文件指纹和下载通道',
      });
      const hash = await fetchJson<HashResult>(`/api/hash?path=${encodeURIComponent(file.relativePath)}`, {
        headers: authHeaders(token),
      });
      const headers: Record<string, string> = { Authorization: `Bearer ${token}` };
      if (offset > 0) headers.Range = `bytes=${offset}-`;
      const response = await fetch(`/api/download?path=${encodeURIComponent(file.relativePath)}`, {
        headers,
        signal: controller.signal,
      });
      if (!response.ok && response.status !== 206) throw new Error(await readJsonError(response));

      const total = hash.sizeBytes;
      setDownload(current => ({
        ...current,
        phase: 'streaming',
        totalBytes: total,
        percent: total ? Math.round((offset / total) * 100) : 0,
        message: response.status === 206 ? '断点续传已命中服务端 Range 响应' : '开始接收真实文件流',
      }));

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
              downloadedBytes: downloadedRef.current,
              totalBytes: total,
              percent: total ? Math.min(100, Math.round((downloadedRef.current / total) * 100)) : 0,
              speedBps: Math.max(0, (downloadedRef.current - offset) / elapsed),
              message: `${formatBytes(downloadedRef.current)} / ${formatBytes(total)}`,
            }));
          }
        }
      }

      setDownload(current => ({ ...current, phase: 'verifying', percent: 100, message: '正在进行 SHA-256 真实校验' }));
      const blob = new Blob(chunksRef.current, { type: 'application/octet-stream' });
      const clientSha256 = await sha256Blob(blob);
      const serverSha256 = response.headers.get('X-Content-SHA256') || hash.sha256;
      const serverMd5 = response.headers.get('X-Content-MD5') || hash.md5;
      const verified = clientSha256.toLowerCase() === serverSha256.toLowerCase() && blob.size === hash.sizeBytes;
      const receiptNext = {
        fileName: contentDispositionFileName(response.headers.get('Content-Disposition'), file.name),
        transferId: `LAN-${Date.now().toString(36).toUpperCase()}`,
        sizeBytes: blob.size,
        sha256: clientSha256,
        md5: serverMd5,
        verified,
        finishedAt: new Date().toLocaleString(),
      };
      setReceipt(receiptNext);
      if (!verified) {
        setDownload(current => ({ ...current, phase: 'error', message: '文件校验失败，已阻止自动保存。', resumeAvailable: false }));
        setAutoNotice({ tone: 'error', text: '服务端与客户端 SHA-256 或大小不一致，下载未落盘。' });
        return;
      }
      triggerDownload(blob, receiptNext.fileName);
      setDownload(current => ({ ...current, phase: 'complete', message: '校验通过，浏览器已保存文件。', resumeAvailable: false }));
      setAutoNotice({ tone: 'ok', text: `${file.name} 已完成真实传输和指纹校验。` });
    } catch (error) {
      if (controller.signal.aborted) {
        setDownload(current => ({
          ...current,
          phase: 'paused',
          downloadedBytes: downloadedRef.current,
          resumeAvailable: downloadedRef.current > 0,
          message: `已暂停在 ${formatBytes(downloadedRef.current)}，可继续使用 Range 续传。`,
        }));
        return;
      }
      setDownload(current => ({ ...current, phase: 'error', message: (error as Error).message, resumeAvailable: downloadedRef.current > 0 }));
      setAutoNotice({ tone: 'error', text: `下载失败：${(error as Error).message}` });
    }
  }

  async function resumeDownload() {
    if (activeFileRef.current) await downloadFile(activeFileRef.current, true);
  }

  async function downloadArchive() {
    if (!token || selectedPaths.size === 0) return;
    const controller = new AbortController();
    abortRef.current = controller;
    const params = new URLSearchParams();
    selectedPaths.forEach(path => params.append('path', path));
    const startedAt = Date.now();
    chunksRef.current = [];
    downloadedRef.current = 0;
    try {
      setReceipt(null);
      const archiveBaseName = publicInfo?.share.name || 'EncryptedShare';
      setDownload({ ...EMPTY_DOWNLOAD, phase: 'archiving', fileName: `${archiveBaseName}.zip`, message: '服务端正在按真实目录生成 ZIP 包' });
      const response = await fetch(`/api/archive?${params.toString()}`, {
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
        setDownload(current => ({ ...current, phase: 'paused', message: 'ZIP 下载已暂停，ZIP 任务需要重新开始。' }));
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
  const visitorFileCount = files.filter(file => file.type === 'file').length;
  const visitorTotalSize = files.reduce((sum, file) => sum + (file.type === 'file' ? file.sizeBytes : 0), 0);

  return (
    <div className="app-shell visitor-shell min-h-screen bg-[#f3f6f8] text-slate-950">
      <header className="app-header visitor-header border-b border-slate-200 bg-white">
        <div className="app-header-inner flex w-full flex-col gap-4 px-6 py-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex items-center gap-3">
            <div className="brand-mark flex h-12 w-12 items-center justify-center rounded-lg bg-slate-950 text-white">
              <Download className="h-7 w-7" />
            </div>
            <div>
              <h1 className="text-2xl font-black tracking-tight">{publicInfo?.share.name || (accessMode === 'token' ? '加密访问链接' : accessValue)}</h1>
              <p className="text-sm text-slate-600">来自局域网的安全文件投递，认证后即可预览与下载。</p>
            </div>
          </div>
          <div className="status-deck flex flex-wrap items-center gap-2">
            <StatusPill ok={online}>{online ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />} 本机网络</StatusPill>
            <StatusPill ok={!!token}>认证会话</StatusPill>
            {publicInfo && <span className="endpoint-chip rounded-full border border-slate-300 bg-slate-50 px-3 py-1 text-xs font-mono font-semibold">客户端 IP {publicInfo.clientIp}</span>}
          </div>
        </div>
      </header>

      <main className="app-workspace visitor-workspace grid w-full grid-cols-1 gap-5 px-6 py-5 xl:grid-cols-[340px_minmax(0,1fr)]">
        <div className="visitor-rail space-y-5">
          {notice && <div className={`app-notice rounded-lg border px-4 py-3 text-sm font-semibold ${noticeClass(notice.tone)}`}>{notice.text}</div>}

          <Panel className="access-panel overflow-hidden">
            <div className="access-panel-head bg-slate-950 p-5 text-white">
              <div className="flex items-center gap-3">
                <ShieldCheck className="h-6 w-6" />
                <div>
                  <h2 className="font-black">入口状态</h2>
                  <p className="text-xs text-slate-300">{token ? '已建立只读会话' : '等待口令认证'}</p>
                </div>
              </div>
            </div>
            {publicInfo ? (
              <div className="space-y-3 p-5 text-sm">
                <div className="flex items-center justify-between gap-3 rounded-md bg-slate-50 px-3 py-2">
                  <span className="text-slate-500">共享说明</span>
                  <span className="text-right font-semibold">{publicInfo.share.description || '无说明'}</span>
                </div>
                <div className="flex items-center justify-between gap-3 rounded-md bg-slate-50 px-3 py-2">
                  <span className="text-slate-500">口令提示</span>
                  <span className="font-semibold">{publicInfo.share.passcodeHint}</span>
                </div>
                <div className="flex items-center justify-between gap-3 rounded-md bg-slate-50 px-3 py-2">
                  <span className="text-slate-500">口令有效期</span>
                  <span className="font-semibold">{formatTimeLeft(publicInfo.share.passcodeExpiresAt)}</span>
                </div>
                <div className="flex items-center justify-between gap-3 rounded-md bg-slate-50 px-3 py-2">
                  <span className="text-slate-500">访问模式</span>
                  <span className="font-semibold">{(publicInfo.share.accessMode || 'exclusive') === 'multi' ? '一对多下载' : '独占访问'}</span>
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
              <SectionTitle icon={<KeyRound className="h-4 w-4" />} title="安全认证" />
              <form onSubmit={authenticate} className="space-y-4 p-5">
                <input
                  type="password"
                  value={passcode}
                  disabled={!publicInfo || !canUseShare}
                  onChange={event => setPasscode(event.target.value)}
                  placeholder="输入共享口令"
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-slate-950 disabled:bg-slate-100"
                />
                <button
                  type="submit"
                  disabled={!publicInfo || !canUseShare || !passcode.trim()}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-slate-950 px-3 py-2.5 text-sm font-bold text-white disabled:opacity-50"
                >
                  <Lock className="h-4 w-4" />
                  进入文件列表
                </button>
              </form>
            </Panel>
          )}

          {token && (
            <Panel>
              <SectionTitle icon={<Activity className="h-4 w-4" />} title="传输进度" />
              <div className="space-y-4 p-5">
                <div>
                  <div className="mb-2 flex items-center justify-between text-xs font-semibold text-slate-500">
                    <span>{download.fileName || '未选择文件'}</span>
                    <span>{download.percent}%</span>
                  </div>
                  <div className="transfer-track h-2 overflow-hidden rounded-full bg-slate-200">
                    <div className="transfer-fill h-full bg-slate-950 transition-all" style={{ width: `${download.percent}%` }} />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="rounded-md border border-slate-200 p-3">
                    <p className="text-slate-500">已接收</p>
                    <p className="mt-1 font-mono font-bold">{formatBytes(download.downloadedBytes)}</p>
                  </div>
                  <div className="rounded-md border border-slate-200 p-3">
                    <p className="text-slate-500">速度</p>
                    <p className="mt-1 font-mono font-bold">{download.speedBps ? `${formatBytes(download.speedBps)}/s` : '等待中'}</p>
                  </div>
                </div>
                <p className="text-sm text-slate-600">{download.message}</p>
                <div className="flex flex-wrap gap-2">
                  {download.phase === 'streaming' && (
                    <button type="button" onClick={pauseDownload} className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold">
                      <Pause className="h-4 w-4" />
                      暂停
                    </button>
                  )}
                  {download.resumeAvailable && (
                    <button type="button" onClick={resumeDownload} className="inline-flex items-center gap-2 rounded-md bg-slate-950 px-3 py-2 text-sm font-bold text-white">
                      <Play className="h-4 w-4" />
                      续传
                    </button>
                  )}
                  {selectedPaths.size > 0 && (
                    <button type="button" onClick={downloadArchive} className="inline-flex items-center gap-2 rounded-md border border-slate-300 px-3 py-2 text-sm font-bold">
                      <Archive className="h-4 w-4" />
                      ZIP 打包下载
                    </button>
                  )}
                </div>
              </div>
            </Panel>
          )}

          {receipt && (
            <Panel className="p-5">
              <div className="mb-3 flex items-center gap-2">
                <Check className={`h-5 w-5 ${receipt.verified ? 'text-emerald-600' : 'text-red-600'}`} />
                <h2 className="font-black">传输回执</h2>
              </div>
              <dl className="space-y-2 text-xs">
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500">文件</dt>
                  <dd className="truncate font-semibold">{receipt.fileName}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500">大小</dt>
                  <dd className="font-mono">{formatBytes(receipt.sizeBytes)}</dd>
                </div>
                <div className="space-y-1">
                  <dt className="text-slate-500">SHA-256</dt>
                  <dd className="break-all rounded bg-slate-50 p-2 font-mono">{receipt.sha256}</dd>
                </div>
                <div className="flex justify-between gap-3">
                  <dt className="text-slate-500">状态</dt>
                  <dd className={receipt.verified ? 'font-bold text-emerald-700' : 'font-bold text-red-700'}>{receipt.verified ? '校验通过' : '校验失败'}</dd>
                </div>
              </dl>
            </Panel>
          )}
        </div>

        <div className="visitor-content space-y-5">
          {token && (
            <div className="visitor-metrics grid grid-cols-2 gap-3 md:grid-cols-4">
              <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
                <p className="text-xs font-semibold text-slate-500">文件</p>
                <p className="mt-1 text-2xl font-black">{visitorFileCount}</p>
              </div>
              <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
                <p className="text-xs font-semibold text-slate-500">总量</p>
                <p className="mt-1 text-2xl font-black">{formatBytes(visitorTotalSize)}</p>
              </div>
              <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
                <p className="text-xs font-semibold text-slate-500">已选</p>
                <p className="mt-1 text-2xl font-black">{selectedPaths.size}</p>
              </div>
              <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
                <p className="text-xs font-semibold text-slate-500">状态</p>
                <p className="mt-1 text-lg font-black">{download.phase === 'idle' ? '待下载' : download.phase === 'complete' ? '完成' : '进行中'}</p>
              </div>
            </div>
          )}
          <Panel>
            <SectionTitle
              icon={<FolderOpen className="h-4 w-4" />}
              title="真实文件列表"
              action={
                token && (
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-semibold text-slate-500">已选 {selectedPaths.size}</span>
                    <button type="button" onClick={() => loadFiles()} className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2.5 py-1.5 text-xs font-bold">
                      <RefreshCw className="h-3.5 w-3.5" />
                      刷新
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
                      placeholder="搜索文件名或相对路径"
                      className="min-w-0 flex-1 bg-transparent text-sm outline-none"
                    />
                  </label>
                </div>
                <div className="max-h-[620px] overflow-auto">
                  <table className="data-table w-full text-left text-sm">
                    <thead className="sticky top-0 bg-slate-50 text-xs uppercase text-slate-500">
                      <tr>
                        <th className="w-10 px-4 py-3">
                          <input
                            type="checkbox"
                            checked={allVisibleSelected}
                            disabled={visibleSelectablePaths.length === 0}
                            onChange={toggleAllVisible}
                            className="h-4 w-4"
                            aria-label="全选当前列表"
                          />
                        </th>
                        <th className="px-4 py-3">文件</th>
                        <th className="px-4 py-3">大小</th>
                        <th className="px-4 py-3">修改时间</th>
                        <th className="px-4 py-3"></th>
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
                              {fileIcon(file)}
                              <div className="min-w-0">
                                <p className="truncate font-semibold">{file.name}</p>
                                <p className="truncate text-xs text-slate-500">{file.relativePath || '.'}</p>
                              </div>
                            </div>
                          </td>
                          <td className="whitespace-nowrap px-4 py-3 font-mono text-xs">{file.type === 'folder' ? '目录' : file.size}</td>
                          <td className="whitespace-nowrap px-4 py-3 text-xs text-slate-500">{formatDate(file.lastModified)}</td>
                          <td className="px-4 py-3 text-right">
                            <div className="flex justify-end gap-2">
                              <button type="button" onClick={() => previewFile(file)} className="inline-flex items-center gap-1 rounded-md border border-slate-300 px-2 py-1 text-xs font-bold">
                                <Eye className="h-3.5 w-3.5" />
                                预览
                              </button>
                              {file.type === 'file' && (
                                <button type="button" onClick={() => downloadFile(file)} className="inline-flex items-center gap-1 rounded-md bg-slate-950 px-2 py-1 text-xs font-bold text-white">
                                  <Download className="h-3.5 w-3.5" />
                                  下载
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                      {filteredFiles.length === 0 && (
                        <tr>
                          <td colSpan={5} className="px-4 py-10 text-center text-sm text-slate-500">
                            没有匹配文件。
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </Panel>

          <Panel>
            <SectionTitle icon={<Eye className="h-4 w-4" />} title="只读预览" />
            <div className="grid grid-cols-1 lg:grid-cols-[1fr_280px]">
              <div className="h-96 overflow-auto bg-slate-950 p-4 font-mono text-xs leading-5 text-slate-100">
                {preview ? (
                  preview.result.type === 'text' ? (
                    <pre className="whitespace-pre-wrap break-words">{preview.result.content}</pre>
                  ) : (
                    <div className="flex h-full items-center justify-center text-center text-slate-300">{preview.result.content}</div>
                  )
                ) : (
                  <div className="flex h-full items-center justify-center text-slate-400">选择文件后通过服务端读取预览</div>
                )}
              </div>
              <div className="border-t border-slate-200 p-4 text-sm lg:border-l lg:border-t-0">
                <p className="mb-2 text-xs font-bold uppercase text-slate-500">当前对象</p>
                <p className="break-all font-semibold">{preview?.path || '未选择'}</p>
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
