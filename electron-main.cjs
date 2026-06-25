/**
 * Electron Main Process Entry Point
 * -------------------------------------------------------------
 * Runs the native shell, owns all OS/file-system access, and starts the
 * real LAN HTTP service used by other machines on the intranet.
 */

const { app, BrowserWindow, Menu, session, ipcMain, dialog, powerSaveBlocker } = require('electron');
const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const os = require('os');
const crypto = require('crypto');
const express = require('express');
const http = require('http');

let mainWindow = null;
let lanServer = null;
let serverState = {
  running: false,
  hostIp: '',
  bindAddress: '0.0.0.0',
  port: 8787,
  error: '',
};
let appState = {
  server: { hostIp: '', port: 8787 },
  security: { linkSecret: '' },
  shares: [],
};
const activeTokens = new Map();
const shareLeases = new Map();
const activeTransfers = new Map();
const rateLimits = new Map();
let nextTransferId = 1;
let quitConfirmed = false;
const DESKTOP_GATE_COOKIE = 'lan_desktop_gate';
const DESKTOP_GATE_MAX_AGE_MS = 12 * 60 * 60 * 1000;
const AUTH_MAX_FAILURES = 5;
const AUTH_LOCK_MS = 10 * 60 * 1000;
let statePath = '';
let logPath = '';
let runtimeIdleGuardId = null;
let runtimeIdleGuardWatchTimer = null;

function logEvent(message, details = {}) {
  try {
    const target = logPath || path.join(app.getPath('userData'), 'lan-transfer.log');
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.appendFileSync(target, `${JSON.stringify({ time: new Date().toISOString(), message, ...details })}\n`, 'utf8');
  } catch {
    // Diagnostic logging must never block the transfer service.
  }
}

process.on('uncaughtException', error => {
  logEvent('process:uncaughtException', { error: error.message, stack: error.stack });
});

process.on('unhandledRejection', reason => {
  logEvent('process:unhandledRejection', { error: reason instanceof Error ? reason.message : String(reason) });
});

function ensureRuntimeIdleGuard() {
  if (runtimeIdleGuardId !== null && powerSaveBlocker.isStarted(runtimeIdleGuardId)) return;
  runtimeIdleGuardId = powerSaveBlocker.start('prevent-display-sleep');
  logEvent('runtime-idle-guard:start', {
    blockerId: runtimeIdleGuardId,
    type: 'prevent-display-sleep',
  });
}

function startRuntimeIdleGuard() {
  ensureRuntimeIdleGuard();
  if (!runtimeIdleGuardWatchTimer) {
    runtimeIdleGuardWatchTimer = setInterval(ensureRuntimeIdleGuard, 30_000);
    runtimeIdleGuardWatchTimer.unref?.();
  }
}

function stopRuntimeIdleGuard() {
  if (runtimeIdleGuardWatchTimer) {
    clearInterval(runtimeIdleGuardWatchTimer);
    runtimeIdleGuardWatchTimer = null;
  }
  if (runtimeIdleGuardId !== null && powerSaveBlocker.isStarted(runtimeIdleGuardId)) {
    powerSaveBlocker.stop(runtimeIdleGuardId);
    logEvent('runtime-idle-guard:stop', { blockerId: runtimeIdleGuardId });
  }
  runtimeIdleGuardId = null;
}

function getRuntimeIdleGuardState() {
  return {
    type: 'prevent-display-sleep',
    active: runtimeIdleGuardId !== null && powerSaveBlocker.isStarted(runtimeIdleGuardId),
    blockerId: runtimeIdleGuardId,
    note: 'Keeps the display awake while the app is running; manual OS lock shortcuts remain under user control.',
  };
}

function assetPath(fileName) {
  return path.join(__dirname, 'assets', fileName);
}

function loadFailureHtml() {
  return `data:text/html;charset=utf-8,${encodeURIComponent(`
    <body style="font-family:system-ui;margin:40px;line-height:1.6">
      <h2>内网闪传无法启动</h2>
      <p>未找到已构建的前端资源。请先运行 npm run build，再重新启动桌面程序。</p>
    </body>
  `)}`;
}

function getDistDir() {
  return path.join(__dirname, 'dist');
}

function getPreloadPath() {
  const externalPreload = path.join(process.resourcesPath || '', 'electron-preload.cjs');
  if (app.isPackaged && fs.existsSync(externalPreload)) return externalPreload;
  return path.join(__dirname, 'electron-preload.cjs');
}

function getStatePath() {
  return path.join(app.getPath('userData'), 'lan-transfer-state.json');
}

function getNetworkInterfaces() {
  const rows = [];
  const interfaces = os.networkInterfaces();
  for (const [name, addresses] of Object.entries(interfaces)) {
    for (const item of addresses || []) {
      if (item.family !== 'IPv4' || item.internal) continue;
      rows.push({
        id: `${name}-${item.address}`,
        name,
        address: item.address,
        cidr: item.cidr || '',
        mac: item.mac || '',
      });
    }
  }
  return rows.sort((a, b) => a.name.localeCompare(b.name) || a.address.localeCompare(b.address));
}

function firstUsableIp() {
  return getNetworkInterfaces()[0]?.address || '127.0.0.1';
}

function getUsableIpSet() {
  const addresses = getNetworkInterfaces().map(item => item.address);
  if (addresses.length === 0) addresses.push('127.0.0.1');
  return new Set(addresses);
}

function normalizeHostIp(input) {
  const clean = String(input || '').trim();
  const usable = getUsableIpSet();
  if (usable.has(clean)) return clean;
  return firstUsableIp();
}

function accessUrlsForPort(port, preferredHostIp) {
  const addresses = getNetworkInterfaces().map(item => item.address);
  if (addresses.length === 0) addresses.push('127.0.0.1');
  const preferred = normalizeHostIp(preferredHostIp);
  const ordered = [preferred, ...addresses].filter((address, index, all) => address && all.indexOf(address) === index);
  return ordered.map(address => `http://${address}:${port}`);
}

async function loadAppState() {
  statePath = getStatePath();
  logPath = path.join(path.dirname(statePath), 'lan-transfer.log');
  logEvent('load-state:start', { statePath });
  try {
    const raw = await fsp.readFile(statePath, 'utf8');
    const parsed = JSON.parse(raw);
    appState = {
      server: {
        hostIp: normalizeHostIp(parsed.server?.hostIp || firstUsableIp()),
        port: Number(parsed.server?.port) || 8787,
      },
      security: {
        linkSecret: parsed.security?.linkSecret || crypto.randomBytes(32).toString('base64url'),
      },
      shares: Array.isArray(parsed.shares) ? parsed.shares : [],
    };
    if (!parsed.security?.linkSecret || appState.server.hostIp !== parsed.server?.hostIp) await saveAppState();
    logEvent('load-state:ok', { shareCount: appState.shares.length });
  } catch {
    appState = {
      server: { hostIp: normalizeHostIp(firstUsableIp()), port: 8787 },
      security: { linkSecret: crypto.randomBytes(32).toString('base64url') },
      shares: [],
    };
    await saveAppState();
    logEvent('load-state:created-default');
  }
  serverState.hostIp = normalizeHostIp(appState.server.hostIp || firstUsableIp());
  serverState.port = Number(appState.server.port) || 8787;
  logEvent('load-state:active-server', { hostIp: serverState.hostIp, port: serverState.port });
}

async function saveAppState() {
  if (!statePath) statePath = getStatePath();
  await fsp.mkdir(path.dirname(statePath), { recursive: true });
  await fsp.writeFile(statePath, JSON.stringify(appState, null, 2), 'utf8');
}

function publicShare(share) {
  return {
    id: share.id,
    name: share.name,
    description: share.description,
    accessMode: share.accessMode || 'exclusive',
    allowMobileAccess: share.allowMobileAccess === true,
    passcodeHint: share.passcodeHint,
    passcodeExpiresAt: share.passcodeExpiresAt,
  };
}

function adminShare(share) {
  return {
    ...publicShare(share),
    encryptedLinkToken: createEncryptedLinkToken(share),
    localPath: share.localPath,
    createdAt: share.createdAt,
    passcodeUpdatedAt: share.passcodeUpdatedAt,
    passcodeDuration: share.passcodeDuration,
    ipWhitelist: share.ipWhitelist,
  };
}

function linkCipherKey() {
  if (!appState.security?.linkSecret) {
    appState.security = { ...(appState.security || {}), linkSecret: crypto.randomBytes(32).toString('base64url') };
  }
  return crypto.createHash('sha256').update(appState.security.linkSecret).digest();
}

function createEncryptedLinkToken(share) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', linkCipherKey(), iv);
  const payload = Buffer.from(JSON.stringify({
    purpose: 'share-link',
    shareId: share.id,
    issuedAt: Date.now(),
  }));
  const encrypted = Buffer.concat([cipher.update(payload), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64url');
}

function shareFromEncryptedLinkToken(token) {
  try {
    const raw = Buffer.from(String(token || ''), 'base64url');
    if (raw.length <= 28) return null;
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const encrypted = raw.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', linkCipherKey(), iv);
    decipher.setAuthTag(tag);
    const payload = JSON.parse(Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8'));
    if (payload.purpose !== 'share-link' || !payload.shareId) return null;
    return findShareById(payload.shareId);
  } catch {
    return null;
  }
}

function findShareFromAccess(input = {}) {
  if (input.token) return shareFromEncryptedLinkToken(input.token);
  return findShareByName(input.share);
}

function findShareByName(name) {
  const clean = String(name || '').toLowerCase();
  return appState.shares.find(share => share.name.toLowerCase() === clean);
}

function findShareById(id) {
  return appState.shares.find(share => share.id === id);
}

function makePasscodeRecord(passcode) {
  const clean = String(passcode || '').trim();
  if (!clean) throw new Error('访问口令不能为空');
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(clean, salt, 32).toString('hex');
  return {
    passcodeHash: `scrypt$${salt}$${hash}`,
    passcodeHint: clean.length <= 4
      ? `${clean.length} 位 / 已加密保存`
      : `${clean.length} 位 / 末尾 ${clean.slice(-2)} / 已加密保存`,
    passcodeUpdatedAt: new Date().toISOString(),
  };
}

function verifyPasscode(passcode, stored) {
  if (!stored || !stored.startsWith('scrypt$')) return false;
  const [, salt, expected] = stored.split('$');
  const actual = crypto.scryptSync(String(passcode || '').trim(), salt, 32);
  const expectedBytes = Buffer.from(expected, 'hex');
  return expectedBytes.length === actual.length && crypto.timingSafeEqual(actual, expectedBytes);
}

function isPasscodeExpired(share) {
  if (!share.passcodeExpiresAt) return false;
  return new Date(share.passcodeExpiresAt).getTime() <= Date.now();
}

function extendActiveTokensForShare(share) {
  const shareExpiry = share.passcodeExpiresAt ? new Date(share.passcodeExpiresAt).getTime() : Number.POSITIVE_INFINITY;
  const sessionExpiry = Math.min(Date.now() + 4 * 60 * 60 * 1000, shareExpiry);
  for (const record of activeTokens.values()) {
    if (record.shareId === share.id && record.expiresAt > Date.now()) {
      record.expiresAt = Math.max(record.expiresAt, sessionExpiry);
    }
  }
}

function extendShareExpiry(share, addMs) {
  const ms = Number(addMs);
  if (!Number.isFinite(ms) || ms <= 0) throw new Error('加时时长无效');
  if (!share.passcodeExpiresAt) return share;

  const now = Date.now();
  const currentExpiry = new Date(share.passcodeExpiresAt).getTime();
  const base = Number.isFinite(currentExpiry) && currentExpiry > now ? currentExpiry : now;
  share.passcodeExpiresAt = new Date(base + ms).toISOString();
  extendActiveTokensForShare(share);
  return share;
}

function normalizeAlias(input) {
  const alias = String(input || '').trim().replace(/[^a-zA-Z0-9_-]/g, '');
  if (!alias) throw new Error('共享别名不能为空，且只能包含英文、数字、下划线和短横线');
  return alias;
}

function normalizeAccessMode(input) {
  return input === 'multi' ? 'multi' : 'exclusive';
}

function normalizeIpWhitelist(input) {
  return String(input || '')
    .split(/[,，;；\n\r\t ]+/)
    .map(item => item.trim())
    .filter(Boolean)
    .join(', ');
}

function parseIpv4(value) {
  const parts = String(value || '').trim().split('.');
  if (parts.length !== 4) return null;
  const octets = parts.map(part => Number.parseInt(part, 10));
  if (octets.some(part => Number.isNaN(part) || part < 0 || part > 255)) return null;
  return octets;
}

function ipToNumber(value) {
  const octets = parseIpv4(value);
  if (!octets) return null;
  return (((octets[0] << 24) >>> 0) + (octets[1] << 16) + (octets[2] << 8) + octets[3]) >>> 0;
}

function ipInWhitelist(clientIp, whitelist) {
  if (!whitelist || !String(whitelist).trim()) return true;
  const cleanIp = String(clientIp || '').trim().replace(/^::ffff:/, '');
  const cleanIpNumber = ipToNumber(cleanIp);
  const rules = String(whitelist).split(',').map(rule => rule.trim()).filter(Boolean);
  if (rules.length === 0) return true;

  for (const rule of rules) {
    if (cleanIp === rule) return true;
    if (rule.includes('*')) {
      const regex = new RegExp(`^${rule.replace(/\./g, '\\.').replace(/\*/g, '[0-9]{1,3}')}$`);
      if (regex.test(cleanIp)) return true;
      continue;
    }
    if (rule.includes('/')) {
      const [subnet, maskText] = rule.split('/');
      const mask = Number.parseInt(maskText, 10);
      const subnetNumber = ipToNumber(subnet);
      if (cleanIpNumber !== null && subnetNumber !== null && mask >= 0 && mask <= 32) {
        const maskNumber = mask === 0 ? 0 : (0xffffffff << (32 - mask)) >>> 0;
        if ((subnetNumber & maskNumber) === (cleanIpNumber & maskNumber)) return true;
      }
    }
  }
  return false;
}

function clientIpFromRequest(req) {
  return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '')
    .split(',')[0]
    .trim()
    .replace(/^::ffff:/, '');
}

function isMobileUserAgent(req) {
  const ua = String(req.headers['user-agent'] || '');
  const uaMobile = String(req.headers['sec-ch-ua-mobile'] || '').trim();
  const uaPlatform = String(req.headers['sec-ch-ua-platform'] || '').replace(/"/g, '');
  return uaMobile === '?1'
    || /Android|iOS|iPhone|iPad|iPod/i.test(uaPlatform)
    || /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile|Tablet|Kindle|PlayBook|Silk/i.test(ua);
}

function proofLooksMobile(proof = {}) {
  const ua = String(proof.userAgent || '');
  const platform = String(proof.platform || '');
  const uaDataPlatform = String(proof.uaDataPlatform || '');
  const maxTouchPoints = Number(proof.maxTouchPoints) || 0;
  const pointerCoarse = proof.pointerCoarse === true;
  const screenWidth = Number(proof.screenWidth) || 0;
  const screenHeight = Number(proof.screenHeight) || 0;
  const largerScreenEdge = Math.max(screenWidth, screenHeight);

  if (proof.uaDataMobile === true) return true;
  if (/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile|Tablet|Kindle|PlayBook|Silk/i.test(ua)) return true;
  if (/Android|iOS|iPhone|iPad|iPod/i.test(`${platform} ${uaDataPlatform}`)) return true;
  if (/Macintosh/i.test(ua) && maxTouchPoints > 1) return true;
  if (maxTouchPoints > 1 && pointerCoarse && largerScreenEdge > 0 && largerScreenEdge <= 1600) return true;
  return false;
}

function proofMatchesRequest(req, proof = {}) {
  const headerUa = String(req.headers['user-agent'] || '');
  const proofUa = String(proof.userAgent || '');
  if (!headerUa || proofUa !== headerUa) return false;

  const headerMobile = String(req.headers['sec-ch-ua-mobile'] || '').trim();
  if (headerMobile === '?1' && proof.uaDataMobile !== true) return false;

  const headerPlatform = String(req.headers['sec-ch-ua-platform'] || '').replace(/"/g, '').trim();
  const proofPlatform = String(proof.uaDataPlatform || '').trim();
  if (headerPlatform && proofPlatform && headerPlatform.toLowerCase() !== proofPlatform.toLowerCase()) return false;

  return Number.isFinite(Number(proof.maxTouchPoints))
    && Number.isFinite(Number(proof.screenWidth))
    && Number.isFinite(Number(proof.screenHeight));
}

function parseCookies(cookieHeader = '') {
  const cookies = {};
  for (const part of String(cookieHeader).split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (key) cookies[key] = decodeURIComponent(value);
  }
  return cookies;
}

function hmac(value) {
  return crypto.createHmac('sha256', linkCipherKey()).update(value).digest('base64url');
}

function requestUserAgentHash(req) {
  return crypto.createHash('sha256').update(String(req.headers['user-agent'] || '')).digest('base64url');
}

function gateFingerprint(req) {
  return {
    ip: clientIpFromRequest(req),
    uaHash: requestUserAgentHash(req),
  };
}

function createDesktopGateToken(req) {
  const payload = {
    v: 1,
    ...gateFingerprint(req),
    exp: Date.now() + DESKTOP_GATE_MAX_AGE_MS,
  };
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${body}.${hmac(body)}`;
}

function verifyDesktopGate(req) {
  const token = parseCookies(req.headers.cookie)[DESKTOP_GATE_COOKIE];
  if (!token || !token.includes('.')) return false;
  const [body, signature] = token.split('.');
  const expectedSignature = hmac(body);
  const signatureBytes = Buffer.from(signature || '');
  const expectedBytes = Buffer.from(expectedSignature);
  if (signatureBytes.length !== expectedBytes.length || !crypto.timingSafeEqual(signatureBytes, expectedBytes)) return false;

  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    const fingerprint = gateFingerprint(req);
    return payload.v === 1
      && payload.exp > Date.now()
      && payload.ip === fingerprint.ip
      && payload.uaHash === fingerprint.uaHash;
  } catch {
    return false;
  }
}

function sendForbiddenDevice(res) {
  res.status(403)
    .setHeader('Cache-Control', 'no-store')
    .type('text/plain')
    .send('Forbidden');
}

function canServeMobileRequest(req) {
  const method = req.method.toUpperCase();
  if (req.path === '/blocked-mobile') return true;

  if (method === 'GET' || method === 'HEAD') {
    if (req.path === '/' || req.path === '/index.html' || req.path.startsWith('/assets/')) return true;
    return new Set(['/api/public-share', '/api/files', '/api/preview', '/api/hash', '/api/download', '/api/archive']).has(req.path);
  }

  if (method === 'POST') {
    return new Set(['/api/auth', '/api/heartbeat']).has(req.path);
  }

  return false;
}

function desktopGateHtml(targetUrl) {
  const target = JSON.stringify(targetUrl || '/').replace(/</g, '\\u003c');
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title></title><style>html,body{margin:0;background:#fff;color:#fff}</style></head><body><script>
(async function(){
  const target=${target};
  const navData=navigator.userAgentData || null;
  const proof={
    userAgent:navigator.userAgent || '',
    platform:navigator.platform || '',
    uaDataMobile:navData ? navData.mobile === true : false,
    uaDataPlatform:navData ? navData.platform || '' : '',
    maxTouchPoints:Number(navigator.maxTouchPoints || 0),
    pointerCoarse:window.matchMedia ? window.matchMedia('(pointer: coarse)').matches : false,
    screenWidth:window.screen ? Number(window.screen.width || 0) : 0,
    screenHeight:window.screen ? Number(window.screen.height || 0) : 0
  };
  const mobile=/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini|Mobile|Tablet|Kindle|PlayBook|Silk/i.test(proof.userAgent)
    || proof.uaDataMobile
    || /Android|iOS|iPhone|iPad|iPod/i.test(proof.platform + ' ' + proof.uaDataPlatform)
    || (/Macintosh/i.test(proof.userAgent) && proof.maxTouchPoints > 1)
    || (proof.maxTouchPoints > 1 && proof.pointerCoarse && Math.max(proof.screenWidth, proof.screenHeight) <= 1600);
  if (mobile) {
    location.replace('/blocked-mobile');
    return;
  }
  const response=await fetch('/api/desktop-proof',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify(proof)});
  if (!response.ok) {
    location.replace('/blocked-mobile');
    return;
  }
  location.replace(target);
})().catch(function(){ location.replace('/blocked-mobile'); });
</script></body></html>`;
}

function rateSubject(value) {
  return crypto.createHash('sha256').update(String(value || '')).digest('base64url').slice(0, 16);
}

function rateLimitKey(scope, req, subject = '') {
  return `${scope}:${clientIpFromRequest(req)}:${subject}`;
}

function checkRateLimit(key) {
  const record = rateLimits.get(key);
  if (!record) return null;
  if (record.lockUntil && record.lockUntil > Date.now()) return record;
  if (record.resetAt && record.resetAt <= Date.now()) {
    rateLimits.delete(key);
    return null;
  }
  return null;
}

function noteRateFailure(key, maxFailures = AUTH_MAX_FAILURES, lockMs = AUTH_LOCK_MS) {
  const now = Date.now();
  const record = rateLimits.get(key) || { count: 0, resetAt: now + lockMs, lockUntil: 0 };
  record.count += 1;
  record.resetAt = now + lockMs;
  if (record.count >= maxFailures) record.lockUntil = now + lockMs;
  rateLimits.set(key, record);
  return record;
}

function clearRateLimit(key) {
  rateLimits.delete(key);
}

function sendRateLimited(res, record) {
  const retrySeconds = Math.max(1, Math.ceil(((record?.lockUntil || Date.now()) - Date.now()) / 1000));
  res.setHeader('Retry-After', String(retrySeconds));
  return jsonError(res, 429, `尝试次数过多，请 ${retrySeconds} 秒后再试`);
}

function ensureLease(share, tokenRecord) {
  if ((share.accessMode || 'exclusive') === 'multi') return true;
  const existing = shareLeases.get(share.id);
  if (!existing || existing.expiresAt <= Date.now() || existing.token === tokenRecord.token) {
    shareLeases.set(share.id, {
      token: tokenRecord.token,
      clientIp: tokenRecord.clientIp,
      expiresAt: Date.now() + 45_000,
      updatedAt: Date.now(),
    });
    return true;
  }
  return false;
}

function pruneExpiredActivity(now = Date.now()) {
  for (const [token, record] of activeTokens.entries()) {
    if (!record || record.expiresAt <= now) activeTokens.delete(token);
  }
  for (const [shareId, lease] of shareLeases.entries()) {
    if (!lease || lease.expiresAt <= now) shareLeases.delete(shareId);
  }
}

function beginTransfer(type, auth, details = {}) {
  const id = nextTransferId++;
  const transfer = {
    id,
    type,
    shareId: auth.share.id,
    shareName: auth.share.name,
    clientIp: auth.record.clientIp,
    fileName: details.fileName || '',
    sizeBytes: Number(details.sizeBytes) || 0,
    startedAt: Date.now(),
  };
  activeTransfers.set(id, transfer);
  logEvent('transfer:start', transfer);
  return reason => {
    if (!activeTransfers.delete(id)) return;
    logEvent('transfer:end', { id, reason, shareId: transfer.shareId, clientIp: transfer.clientIp });
  };
}

function watchTransferResponse(res, endTransfer) {
  let done = false;
  const finish = reason => {
    if (done) return;
    done = true;
    endTransfer(reason);
  };
  res.on('finish', () => finish('finish'));
  res.on('close', () => finish('close'));
  res.on('error', error => finish(error instanceof Error ? `error:${error.message}` : 'error'));
  return finish;
}

function requireAuth(req, res) {
  pruneExpiredActivity();
  const auth = String(req.headers.authorization || '');
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : String(req.query.token || '');
  const record = activeTokens.get(token);
  if (!record || record.expiresAt <= Date.now()) {
    res.status(401).json({ error: '登录已过期，请重新验证口令' });
    return null;
  }
  const clientIp = clientIpFromRequest(req);
  if (record.clientIp !== clientIp || record.userAgentHash !== requestUserAgentHash(req)) {
    activeTokens.delete(token);
    res.status(401).json({ error: '会话已被设备指纹保护拒绝，请在原认证电脑上重新验证口令' });
    return null;
  }
  const share = findShareById(record.shareId);
  if (!share) {
    res.status(404).json({ error: '共享不存在或已被撤销' });
    return null;
  }
  if (isMobileUserAgent(req) && share.allowMobileAccess !== true) {
    res.status(403).json({ error: '移动/平板终端未被此共享开关允许访问' });
    return null;
  }
  if (!ipInWhitelist(clientIp, share.ipWhitelist)) {
    res.status(403).json({ error: '当前客户端 IP 不在白名单内' });
    return null;
  }
  if (!ensureLease(share, record)) {
    res.status(423).json({ error: '该共享正在被另一台客户端独占访问' });
    return null;
  }
  return { token, record, share };
}

function safeResolve(root, relativePath = '') {
  const rootFull = path.resolve(root);
  const rootStat = fs.statSync(rootFull);
  if (rootStat.isFile()) {
    const cleanFileRelative = String(relativePath || '').replace(/\\/g, path.sep);
    if (!cleanFileRelative || cleanFileRelative === '.' || cleanFileRelative === path.basename(rootFull)) return rootFull;
    throw new Error('非法路径：该共享仅包含一个指定文件');
  }
  const cleanRelative = String(relativePath || '').replace(/\\/g, path.sep);
  const full = path.resolve(rootFull, cleanRelative);
  if (full !== rootFull && !full.startsWith(rootFull + path.sep)) {
    throw new Error('非法路径：目标不在共享目录内');
  }
  return full;
}

function categoryForFile(name) {
  const ext = path.extname(name).toLowerCase();
  if (['.txt', '.md', '.pdf', '.doc', '.docx', '.rtf'].includes(ext)) return 'document';
  if (['.xls', '.xlsx', '.csv', '.tsv'].includes(ext)) return 'spreadsheet';
  if (['.js', '.ts', '.tsx', '.json', '.xml', '.html', '.css', '.ps1', '.sh', '.py', '.cs'].includes(ext)) return 'code';
  if (['.zip', '.7z', '.rar', '.tar', '.gz', '.msi', '.exe'].includes(ext)) return 'archive';
  if (['.png', '.jpg', '.jpeg', '.gif', '.webp', '.mp4', '.mov', '.mp3', '.wav'].includes(ext)) return 'media';
  return 'other';
}

function formatBytes(bytes) {
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function encodePathId(relativePath) {
  return Buffer.from(relativePath, 'utf8').toString('base64url');
}

async function listPhysicalFiles(root, options = {}) {
  const maxDepth = options.maxDepth ?? 6;
  const maxItems = options.maxItems ?? 5000;
  const rows = [];
  const rootFull = path.resolve(root);

  async function walk(dir, depth) {
    if (rows.length >= maxItems) return;
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    entries.sort((a, b) => Number(b.isDirectory()) - Number(a.isDirectory()) || a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (rows.length >= maxItems) break;
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(rootFull, fullPath).replace(/\\/g, '/');
      const stat = await fsp.stat(fullPath);
      const isDirectory = entry.isDirectory();
      rows.push({
        id: encodePathId(relativePath),
        name: entry.name,
        relativePath,
        type: isDirectory ? 'folder' : 'file',
        sizeBytes: isDirectory ? 0 : stat.size,
        size: isDirectory ? '目录' : formatBytes(stat.size),
        lastModified: stat.mtime.toISOString(),
        category: isDirectory ? 'other' : categoryForFile(entry.name),
      });
      if (isDirectory && depth < maxDepth) await walk(fullPath, depth + 1);
    }
  }

  const stat = await fsp.stat(rootFull);
  if (stat.isFile()) {
    const name = path.basename(rootFull);
    return [{
      id: encodePathId(name),
      name,
      relativePath: name,
      type: 'file',
      sizeBytes: stat.size,
      size: formatBytes(stat.size),
      lastModified: stat.mtime.toISOString(),
      category: categoryForFile(name),
    }];
  }
  if (!stat.isDirectory()) throw new Error('共享路径不是目录');
  await walk(rootFull, 0);
  return rows;
}

async function previewFile(root, relativePath) {
  const full = safeResolve(root, relativePath);
  const stat = await fsp.stat(full);
  if (stat.isDirectory()) {
    return { type: 'folder', content: '目录不支持文本预览，请进入打包下载或选择目录内文件。' };
  }
  const ext = path.extname(full).toLowerCase();
  const textLike = ['.txt', '.md', '.json', '.xml', '.html', '.css', '.js', '.ts', '.tsx', '.csv', '.log', '.ps1', '.sh', '.py'];
  if (!textLike.includes(ext)) {
    return { type: 'binary', content: `此文件类型 (${ext || '无扩展名'}) 不进行文本预览，可直接真实下载。` };
  }
  const handle = await fsp.open(full, 'r');
  try {
    const length = Math.min(stat.size, 64 * 1024);
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, 0);
    return {
      type: 'text',
      truncated: stat.size > length,
      content: buffer.toString('utf8'),
    };
  } finally {
    await handle.close();
  }
}

async function hashFile(filePath) {
  const sha256 = crypto.createHash('sha256');
  const md5 = crypto.createHash('md5');
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => {
      sha256.update(chunk);
      md5.update(chunk);
    });
    stream.on('end', resolve);
    stream.on('error', reject);
  });
  return { sha256: sha256.digest('hex'), md5: md5.digest('hex') };
}

function parseRangeHeader(range, size) {
  if (!range) return null;
  const match = String(range).match(/^bytes=(\d*)-(\d*)$/);
  if (!match) return null;
  const start = match[1] ? Number.parseInt(match[1], 10) : 0;
  const end = match[2] ? Number.parseInt(match[2], 10) : size - 1;
  if (Number.isNaN(start) || Number.isNaN(end) || start > end || start >= size) return null;
  return { start, end: Math.min(end, size - 1) };
}

const crcTable = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c >>> 0;
  }
  return table;
})();

async function crc32File(filePath) {
  let crc = 0xffffffff;
  await new Promise((resolve, reject) => {
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => {
      for (const byte of chunk) crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
    });
    stream.on('end', resolve);
    stream.on('error', reject);
  });
  return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(date) {
  const year = Math.max(1980, date.getFullYear());
  const dosTime = (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2);
  const dosDate = ((year - 1980) << 9) | ((date.getMonth() + 1) << 5) | date.getDate();
  return { dosDate, dosTime };
}

async function collectArchiveFiles(root, relativePaths) {
  const rootFull = path.resolve(root);
  const files = [];
  async function addPath(relativePath) {
    const full = safeResolve(rootFull, relativePath);
    const stat = await fsp.stat(full);
    if (stat.isDirectory()) {
      const entries = await listPhysicalFiles(full, { maxDepth: 20, maxItems: 20_000 });
      for (const item of entries) {
        if (item.type !== 'file') continue;
        const childRelative = path.relative(rootFull, path.join(full, item.relativePath)).replace(/\\/g, '/');
        files.push({ fullPath: safeResolve(rootFull, childRelative), zipName: childRelative, stat: await fsp.stat(safeResolve(rootFull, childRelative)) });
      }
    } else {
      files.push({
        fullPath: full,
        zipName: path.relative(rootFull, full).replace(/\\/g, '/'),
        stat,
      });
    }
  }
  for (const relativePath of relativePaths) await addPath(relativePath);
  return files;
}

async function writeBuffer(stream, buffer) {
  await new Promise((resolve, reject) => {
    stream.write(buffer, error => error ? reject(error) : resolve());
  });
}

async function buildZip(root, relativePaths, outputPath) {
  const files = await collectArchiveFiles(root, relativePaths);
  if (files.length === 0) throw new Error('没有可打包的真实文件');

  const centralRecords = [];
  let offset = 0;
  const output = fs.createWriteStream(outputPath);
  try {
    for (const file of files) {
      if (file.stat.size > 0xffffffff) throw new Error(`文件过大，当前 ZIP 实现不支持超过 4GB：${file.zipName}`);
      const crc = await crc32File(file.fullPath);
      const nameBytes = Buffer.from(file.zipName, 'utf8');
      const { dosDate, dosTime } = dosDateTime(file.stat.mtime);
      const local = Buffer.alloc(30);
      local.writeUInt32LE(0x04034b50, 0);
      local.writeUInt16LE(20, 4);
      local.writeUInt16LE(0x0800, 6);
      local.writeUInt16LE(0, 8);
      local.writeUInt16LE(dosTime, 10);
      local.writeUInt16LE(dosDate, 12);
      local.writeUInt32LE(crc, 14);
      local.writeUInt32LE(file.stat.size, 18);
      local.writeUInt32LE(file.stat.size, 22);
      local.writeUInt16LE(nameBytes.length, 26);
      local.writeUInt16LE(0, 28);
      await writeBuffer(output, Buffer.concat([local, nameBytes]));
      await new Promise((resolve, reject) => {
        fs.createReadStream(file.fullPath)
          .on('error', reject)
          .on('end', resolve)
          .pipe(output, { end: false });
      });
      centralRecords.push({ file, crc, nameBytes, dosDate, dosTime, offset });
      offset += local.length + nameBytes.length + file.stat.size;
    }

    const centralStart = offset;
    for (const record of centralRecords) {
      const central = Buffer.alloc(46);
      central.writeUInt32LE(0x02014b50, 0);
      central.writeUInt16LE(20, 4);
      central.writeUInt16LE(20, 6);
      central.writeUInt16LE(0x0800, 8);
      central.writeUInt16LE(0, 10);
      central.writeUInt16LE(record.dosTime, 12);
      central.writeUInt16LE(record.dosDate, 14);
      central.writeUInt32LE(record.crc, 16);
      central.writeUInt32LE(record.file.stat.size, 20);
      central.writeUInt32LE(record.file.stat.size, 24);
      central.writeUInt16LE(record.nameBytes.length, 28);
      central.writeUInt16LE(0, 30);
      central.writeUInt16LE(0, 32);
      central.writeUInt16LE(0, 34);
      central.writeUInt16LE(0, 36);
      central.writeUInt32LE(0, 38);
      central.writeUInt32LE(record.offset, 42);
      await writeBuffer(output, Buffer.concat([central, record.nameBytes]));
      offset += central.length + record.nameBytes.length;
    }

    const centralSize = offset - centralStart;
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0);
    end.writeUInt16LE(0, 4);
    end.writeUInt16LE(0, 6);
    end.writeUInt16LE(centralRecords.length, 8);
    end.writeUInt16LE(centralRecords.length, 10);
    end.writeUInt32LE(centralSize, 12);
    end.writeUInt32LE(centralStart, 16);
    end.writeUInt16LE(0, 20);
    await writeBuffer(output, end);
  } finally {
    await new Promise(resolve => output.end(resolve));
  }
}

function configureSecurityPolicies() {
  session.defaultSession.setPermissionRequestHandler((_webContents, permission, callback) => {
    callback(permission === 'screen-wake-lock');
  });

  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    if (!app.isPackaged) {
      callback({ responseHeaders: details.responseHeaders });
      return;
    }

    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          "default-src 'self' file: http://127.0.0.1:* http://localhost:*; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: file:; font-src 'self' data:; connect-src 'self' http://127.0.0.1:* http://localhost:* http://*:*; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        ]
      }
    });
  });
}

function jsonError(res, status, error) {
  res.status(status).json({ error: error instanceof Error ? error.message : String(error) });
}

async function startLanServer() {
  await stopLanServer();
  logEvent('lan-server:start', { bindAddress: serverState.bindAddress, port: serverState.port, hostIp: serverState.hostIp });
  const expressApp = express();
  expressApp.use(express.json({ limit: '256kb' }));
  expressApp.disable('x-powered-by');

  expressApp.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
    res.setHeader('Accept-CH', 'Sec-CH-UA-Mobile, Sec-CH-UA-Platform');
    res.setHeader('Vary', 'User-Agent, Sec-CH-UA-Mobile, Sec-CH-UA-Platform');
    next();
  });

  expressApp.use((req, res, next) => {
    const method = req.method.toUpperCase();
    const allowedPostPaths = new Set(['/api/desktop-proof', '/api/auth', '/api/heartbeat']);
    if (['PUT', 'PATCH', 'DELETE'].includes(method) || (method === 'POST' && !allowedPostPaths.has(req.path))) {
      return jsonError(res, 405, 'Read-only transfer service: upload, write, modify, and delete requests are blocked.');
    }
    next();
  });

  expressApp.get('/blocked-mobile', (_req, res) => sendForbiddenDevice(res));

  expressApp.post('/api/desktop-proof', (req, res) => {
    const key = rateLimitKey('desktop-proof', req, requestUserAgentHash(req).slice(0, 16));
    const limited = checkRateLimit(key);
    if (limited) return sendRateLimited(res, limited);
    if (isMobileUserAgent(req) || !proofMatchesRequest(req, req.body) || proofLooksMobile(req.body)) {
      noteRateFailure(key, 3, AUTH_LOCK_MS);
      return sendForbiddenDevice(res);
    }
    clearRateLimit(key);
    const token = createDesktopGateToken(req);
    res.setHeader(
      'Set-Cookie',
      `${DESKTOP_GATE_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${Math.floor(DESKTOP_GATE_MAX_AGE_MS / 1000)}; HttpOnly; SameSite=Strict`
    );
    res.setHeader('Cache-Control', 'no-store');
    res.json({ ok: true });
  });

  expressApp.use((req, res, next) => {
    if (isMobileUserAgent(req)) {
      if (canServeMobileRequest(req)) return next();
      return sendForbiddenDevice(res);
    }
    if (verifyDesktopGate(req)) return next();

    const acceptsHtml = req.method === 'GET' || req.method === 'HEAD'
      ? String(req.headers.accept || '').includes('text/html') || req.path === '/' || req.path.endsWith('.html')
      : false;

    if (acceptsHtml && !req.path.startsWith('/api/')) {
      res.setHeader('Cache-Control', 'no-store');
      return res.type('html').send(desktopGateHtml(req.originalUrl || '/'));
    }

    return sendForbiddenDevice(res);
  });

  expressApp.get('/api/server-state', (_req, res) => {
    res.json(getServerState());
  });

  expressApp.get('/api/public-share', async (req, res) => {
    const share = findShareFromAccess({ share: req.query.share, token: req.query.token });
    if (!share) return jsonError(res, 404, '共享不存在或已被撤销');
    const clientIp = clientIpFromRequest(req);
    res.json({
      share: publicShare(share),
      clientIp,
      ipAllowed: ipInWhitelist(clientIp, share.ipWhitelist),
      mobileBlocked: isMobileUserAgent(req) && share.allowMobileAccess !== true,
      passcodeExpired: isPasscodeExpired(share),
      occupied: (() => {
        if ((share.accessMode || 'exclusive') === 'multi') return false;
        const lease = shareLeases.get(share.id);
        return !!lease && lease.expiresAt > Date.now();
      })(),
    });
  });

  expressApp.post('/api/auth', async (req, res) => {
    try {
      const authRateKey = rateLimitKey('auth', req, rateSubject(req.body?.share || req.body?.token || 'unknown-share'));
      const limited = checkRateLimit(authRateKey);
      if (limited) return sendRateLimited(res, limited);

      const share = findShareFromAccess({ share: req.body.share, token: req.body.token });
      if (!share) {
        noteRateFailure(authRateKey);
        return jsonError(res, 404, '共享不存在或已被撤销');
      }
      const clientIp = clientIpFromRequest(req);
      if (isMobileUserAgent(req) && share.allowMobileAccess !== true) {
        noteRateFailure(authRateKey, 3, AUTH_LOCK_MS);
        return jsonError(res, 403, '移动/平板终端未被此共享开关允许访问');
      }
      if (!ipInWhitelist(clientIp, share.ipWhitelist)) return jsonError(res, 403, '当前客户端 IP 不在白名单内');
      if (isPasscodeExpired(share)) return jsonError(res, 403, '访问口令已过期');
      if (!verifyPasscode(req.body.passcode, share.passcodeHash)) {
        noteRateFailure(authRateKey);
        return jsonError(res, 401, '访问口令错误');
      }

      if ((share.accessMode || 'exclusive') !== 'multi') {
        const existing = shareLeases.get(share.id);
        if (existing && existing.expiresAt > Date.now()) {
          return jsonError(res, 423, '该共享正在被另一台客户端独占访问');
        }
      }

      const token = crypto.randomBytes(32).toString('base64url');
      const expiresAt = Math.min(
        Date.now() + 4 * 60 * 60 * 1000,
        share.passcodeExpiresAt ? new Date(share.passcodeExpiresAt).getTime() : Date.now() + 4 * 60 * 60 * 1000
      );
      const record = { token, shareId: share.id, clientIp, userAgentHash: requestUserAgentHash(req), expiresAt };
      activeTokens.set(token, record);
      clearRateLimit(authRateKey);
      ensureLease(share, record);
      res.json({ token, expiresAt, clientIp, share: publicShare(share), files: await listPhysicalFiles(share.localPath) });
    } catch (error) {
      jsonError(res, 500, error);
    }
  });

  expressApp.post('/api/heartbeat', (req, res) => {
    const auth = requireAuth(req, res);
    if (!auth) return;
    ensureLease(auth.share, auth.record);
    res.json({ ok: true, expiresAt: auth.record.expiresAt, share: publicShare(auth.share) });
  });

  expressApp.get('/api/files', async (req, res) => {
    try {
      const auth = requireAuth(req, res);
      if (!auth) return;
      res.json({ files: await listPhysicalFiles(auth.share.localPath) });
    } catch (error) {
      jsonError(res, 500, error);
    }
  });

  expressApp.get('/api/preview', async (req, res) => {
    try {
      const auth = requireAuth(req, res);
      if (!auth) return;
      res.json(await previewFile(auth.share.localPath, req.query.path));
    } catch (error) {
      jsonError(res, 500, error);
    }
  });

  expressApp.get('/api/hash', async (req, res) => {
    try {
      const auth = requireAuth(req, res);
      if (!auth) return;
      const full = safeResolve(auth.share.localPath, req.query.path);
      const stat = await fsp.stat(full);
      if (stat.isDirectory()) return jsonError(res, 400, '目录请使用 ZIP 打包下载');
      const hashes = await hashFile(full);
      res.json({ ...hashes, sizeBytes: stat.size, size: formatBytes(stat.size) });
    } catch (error) {
      jsonError(res, 500, error);
    }
  });

  expressApp.get('/api/download', async (req, res) => {
    let endTransfer = null;
    try {
      const auth = requireAuth(req, res);
      if (!auth) return;
      const full = safeResolve(auth.share.localPath, req.query.path);
      const stat = await fsp.stat(full);
      if (stat.isDirectory()) return jsonError(res, 400, '目录请使用 ZIP 打包下载');
      const fileName = path.basename(full);
      endTransfer = beginTransfer('download', auth, { fileName, sizeBytes: stat.size });
      const finishTransfer = watchTransferResponse(res, endTransfer);
      const hashes = await hashFile(full);
      const range = parseRangeHeader(req.headers.range, stat.size);
      res.setHeader('Accept-Ranges', 'bytes');
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`);
      res.setHeader('X-Content-SHA256', hashes.sha256);
      res.setHeader('X-Content-MD5', hashes.md5);

      if (range) {
        res.status(206);
        res.setHeader('Content-Range', `bytes ${range.start}-${range.end}/${stat.size}`);
        res.setHeader('Content-Length', range.end - range.start + 1);
        fs.createReadStream(full, { start: range.start, end: range.end })
          .on('error', error => {
            finishTransfer(`stream-error:${error.message}`);
            if (res.headersSent) res.destroy(error);
            else jsonError(res, 500, error);
          })
          .pipe(res);
      } else {
        res.setHeader('Content-Length', stat.size);
        fs.createReadStream(full)
          .on('error', error => {
            finishTransfer(`stream-error:${error.message}`);
            if (res.headersSent) res.destroy(error);
            else jsonError(res, 500, error);
          })
          .pipe(res);
      }
    } catch (error) {
      if (endTransfer) endTransfer(`setup-error:${error.message}`);
      if (res.headersSent) res.destroy(error);
      else jsonError(res, 500, error);
    }
  });

  expressApp.get('/api/archive', async (req, res) => {
    let tempPath = '';
    let endTransfer = null;
    try {
      const auth = requireAuth(req, res);
      if (!auth) return;
      const paths = Array.isArray(req.query.path) ? req.query.path : [req.query.path].filter(Boolean);
      if (paths.length === 0) return jsonError(res, 400, '未选择任何文件');
      endTransfer = beginTransfer('archive', auth, { fileName: `${auth.share.name}.zip` });
      tempPath = path.join(os.tmpdir(), `lan-transfer-${crypto.randomBytes(8).toString('hex')}.zip`);
      await buildZip(auth.share.localPath, paths, tempPath);
      const stat = await fsp.stat(tempPath);
      const hashes = await hashFile(tempPath);
      const fileName = `${auth.share.name}-${new Date().toISOString().slice(0, 10)}.zip`;
      const finishTransfer = watchTransferResponse(res, endTransfer);
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(fileName)}`);
      res.setHeader('Content-Length', stat.size);
      res.setHeader('X-Content-SHA256', hashes.sha256);
      res.setHeader('X-Content-MD5', hashes.md5);
      fs.createReadStream(tempPath)
        .on('error', error => {
          finishTransfer(`stream-error:${error.message}`);
          if (res.headersSent) res.destroy(error);
          else jsonError(res, 500, error);
        })
        .on('close', () => fsp.rm(tempPath, { force: true }).catch(() => {}))
        .pipe(res);
    } catch (error) {
      if (endTransfer) endTransfer(`setup-error:${error.message}`);
      if (tempPath) fsp.rm(tempPath, { force: true }).catch(() => {});
      if (res.headersSent) res.destroy(error);
      else jsonError(res, 500, error);
    }
  });

  const distDir = getDistDir();
  if (fs.existsSync(path.join(distDir, 'index.html'))) {
    expressApp.use(express.static(distDir));
    expressApp.get('*', (_req, res) => res.sendFile(path.join(distDir, 'index.html')));
  } else {
    expressApp.get('*', (_req, res) => res.type('html').send('<h2>内网闪传服务已启动，但前端 dist 尚未构建。</h2>'));
  }

  await new Promise((resolve, reject) => {
    lanServer = http.createServer(expressApp);
    lanServer.once('error', error => {
      logEvent('lan-server:error', { error: error.message });
      reject(error);
    });
    lanServer.listen(serverState.port, serverState.bindAddress, resolve);
  });
  serverState.running = true;
  serverState.error = '';
  logEvent('lan-server:ready', getServerState());
}

async function stopLanServer() {
  if (!lanServer) {
    serverState.running = false;
    return;
  }
  await new Promise(resolve => lanServer.close(resolve));
  lanServer = null;
  serverState.running = false;
}

function getServerState() {
  pruneExpiredActivity();
  const hostIp = normalizeHostIp(serverState.hostIp || firstUsableIp());
  serverState.hostIp = hostIp;
  const port = Number(serverState.port) || 8787;
  return {
    ...serverState,
    hostIp,
    port,
    urlBase: `http://${hostIp}:${port}`,
    accessUrls: accessUrlsForPort(port, hostIp),
    runtimeIdleGuard: getRuntimeIdleGuardState(),
    activeLeases: Array.from(shareLeases.entries())
      .filter(([, lease]) => lease.expiresAt > Date.now())
      .map(([shareId, lease]) => ({ shareId, clientIp: lease.clientIp, expiresAt: lease.expiresAt })),
    activeTransfers: Array.from(activeTransfers.values()).map(transfer => ({
      id: transfer.id,
      type: transfer.type,
      shareId: transfer.shareId,
      shareName: transfer.shareName,
      clientIp: transfer.clientIp,
      fileName: transfer.fileName,
      sizeBytes: transfer.sizeBytes,
      startedAt: new Date(transfer.startedAt).toISOString(),
    })),
  };
}

function getActiveShutdownRisk() {
  const state = getServerState();
  return {
    leases: state.activeLeases,
    transfers: state.activeTransfers,
  };
}

function showQuitDialog(parentWindow, options) {
  if (parentWindow && !parentWindow.isDestroyed()) return dialog.showMessageBoxSync(parentWindow, options);
  return dialog.showMessageBoxSync(options);
}

function confirmQuitWithActiveVisitors(parentWindow) {
  const risk = getActiveShutdownRisk();
  if (risk.leases.length === 0 && risk.transfers.length === 0) return true;

  const activeClients = new Set([
    ...risk.leases.map(item => item.clientIp),
    ...risk.transfers.map(item => item.clientIp),
  ]);
  const transferLines = risk.transfers
    .slice(0, 5)
    .map(item => `${item.clientIp} 正在传输 ${item.fileName || item.type}`)
    .join('\n');
  const detail = [
    `当前有 ${risk.leases.length} 个访客独占会话、${risk.transfers.length} 个正在传输的任务。`,
    `涉及访客：${Array.from(activeClients).join(', ') || '未知'}`,
    transferLines ? `\n正在传输：\n${transferLines}` : '',
    '\n退出会立即关闭本机 HTTP 服务，访客下载会中断；重新打开程序后，访客需要重新进入加密链接并继续/重下任务。',
  ].join('\n');

  const first = showQuitDialog(parentWindow, {
    type: 'warning',
    buttons: ['继续运行', '我知道，准备退出'],
    defaultId: 0,
    cancelId: 0,
    noLink: true,
    title: '仍有访客正在使用共享',
    message: '关闭程序会中断访客下载',
    detail,
  });
  if (first !== 1) return false;

  const second = showQuitDialog(parentWindow, {
    type: 'error',
    buttons: ['取消退出', '确认退出并中断传输'],
    defaultId: 0,
    cancelId: 0,
    noLink: true,
    title: '二次确认退出',
    message: '再次确认后会立即停止共享服务',
    detail: '请只在已经通知访客、或确认可以中断当前下载时继续退出。',
  });

  if (second !== 1) return false;
  quitConfirmed = true;
  logEvent('app:quit-confirmed-with-active-visitors', {
    activeLeaseCount: risk.leases.length,
    activeTransferCount: risk.transfers.length,
  });
  return true;
}

function registerIpcHandlers() {
  ipcMain.handle('lan:getNetworkInterfaces', () => getNetworkInterfaces());
  ipcMain.handle('lan:getServerState', () => getServerState());

  ipcMain.handle('lan:setServerConfig', async (_event, config) => {
    const port = Number(config?.port);
    if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('端口必须在 1024-65535 之间');
    const hostIp = normalizeHostIp(config?.hostIp || firstUsableIp());
    serverState.hostIp = hostIp;
    serverState.port = port;
    appState.server = { hostIp, port };
    await saveAppState();
    try {
      await startLanServer();
    } catch (error) {
      serverState.running = false;
      serverState.error = error.message;
      throw error;
    }
    return getServerState();
  });

  ipcMain.handle('lan:chooseDirectory', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: '选择要真实共享的本机目录',
      properties: ['openDirectory'],
    });
    if (result.canceled || result.filePaths.length === 0) return null;
    return result.filePaths[0];
  });

  ipcMain.handle('lan:chooseFile', async () => {
    const result = await dialog.showOpenDialog(mainWindow, {
      title: '选择要真实共享的本机文件',
      properties: ['openFile'],
    });
    if (result.canceled || result.filePaths.length === 0) return null;
    return result.filePaths[0];
  });

  ipcMain.handle('lan:listShares', () => appState.shares.map(adminShare));

  ipcMain.handle('lan:createShare', async (_event, payload) => {
    const alias = normalizeAlias(payload?.name || path.basename(payload?.localPath || ''));
    if (findShareByName(alias)) throw new Error('共享别名已存在');
    const localPath = path.resolve(String(payload?.localPath || ''));
    const stat = await fsp.stat(localPath);
    if (stat.isFile()) stat.isDirectory = () => true;
    if (!stat.isDirectory()) throw new Error('只能共享真实存在的本机目录');
    const pass = makePasscodeRecord(payload?.passcode);
    const share = {
      id: crypto.randomUUID(),
      name: alias,
      localPath,
      description: String(payload?.description || ''),
      accessMode: normalizeAccessMode(payload?.accessMode),
      allowMobileAccess: payload?.allowMobileAccess === true,
      createdAt: new Date().toISOString(),
      ...pass,
      passcodeExpiresAt: payload?.passcodeExpiresAt || undefined,
      passcodeDuration: payload?.passcodeDuration || '4h',
      ipWhitelist: normalizeIpWhitelist(payload?.ipWhitelist),
    };
    appState.shares.push(share);
    await saveAppState();
    return adminShare(share);
  });

  ipcMain.handle('lan:updateShare', async (_event, id, patch) => {
    const share = findShareById(id);
    if (!share) throw new Error('共享不存在');
    if (patch.name && normalizeAlias(patch.name) !== share.name) {
      const alias = normalizeAlias(patch.name);
      if (findShareByName(alias)) throw new Error('共享别名已存在');
      share.name = alias;
    }
    if (typeof patch.description === 'string') share.description = patch.description;
    if (typeof patch.ipWhitelist === 'string') share.ipWhitelist = normalizeIpWhitelist(patch.ipWhitelist);
    if (typeof patch.accessMode === 'string') share.accessMode = normalizeAccessMode(patch.accessMode);
    if (typeof patch.allowMobileAccess === 'boolean') share.allowMobileAccess = patch.allowMobileAccess === true;
    if ('passcodeExpiresAt' in patch) share.passcodeExpiresAt = patch.passcodeExpiresAt || undefined;
    if (patch.passcodeDuration) share.passcodeDuration = patch.passcodeDuration;
    if (patch.passcode) Object.assign(share, makePasscodeRecord(patch.passcode));
    extendActiveTokensForShare(share);
    await saveAppState();
    return adminShare(share);
  });

  ipcMain.handle('lan:extendShareExpiry', async (_event, id, addMs) => {
    const share = findShareById(id);
    if (!share) throw new Error('共享不存在');
    extendShareExpiry(share, addMs);
    await saveAppState();
    return adminShare(share);
  });

  ipcMain.handle('lan:deleteShare', async (_event, id) => {
    appState.shares = appState.shares.filter(share => share.id !== id);
    shareLeases.delete(id);
    for (const [token, record] of activeTokens.entries()) {
      if (record.shareId === id) activeTokens.delete(token);
    }
    await saveAppState();
    return true;
  });

  ipcMain.handle('lan:listFiles', async (_event, shareId) => {
    const share = findShareById(shareId);
    if (!share) throw new Error('共享不存在');
    return listPhysicalFiles(share.localPath);
  });

  ipcMain.handle('lan:previewFile', async (_event, shareId, relativePath) => {
    const share = findShareById(shareId);
    if (!share) throw new Error('共享不存在');
    return previewFile(share.localPath, relativePath);
  });

  ipcMain.handle('lan:forceRelease', (_event, shareId) => {
    const share = findShareById(shareId);
    if ((share?.accessMode || 'exclusive') === 'multi') return getServerState();
    shareLeases.delete(shareId);
    for (const [token, record] of activeTokens.entries()) {
      if (record.shareId === shareId) activeTokens.delete(token);
    }
    return getServerState();
  });
}

function createWindow() {
  const isDev = process.env.ELECTRON_DEV === 'true' || !app.isPackaged;
  const preloadPath = getPreloadPath();
  const iconPath = fs.existsSync(assetPath('icon.ico'))
    ? assetPath('icon.ico')
    : fs.existsSync(assetPath('icon.png'))
      ? assetPath('icon.png')
      : undefined;

  logEvent('window:create', {
    isPackaged: app.isPackaged,
    appPath: app.getAppPath(),
    resourcesPath: process.resourcesPath,
    preloadPath,
    preloadExists: fs.existsSync(preloadPath),
  });

  mainWindow = new BrowserWindow({
    width: 1320,
    height: 880,
    minWidth: 1060,
    minHeight: 680,
    title: '内网闪传 - 真实文件传输控制器',
    autoHideMenuBar: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      devTools: isDev,
      preload: preloadPath,
    },
    icon: iconPath,
  });

  mainWindow.webContents.on('preload-error', (_event, failedPreloadPath, error) => {
    logEvent('window:preload-error', {
      preloadPath: failedPreloadPath,
      error: error.message,
      stack: error.stack,
    });
  });

  mainWindow.webContents.on('did-finish-load', async () => {
    try {
      const bridgeState = await mainWindow.webContents.executeJavaScript(
        '({ hasLanTransfer: !!window.lanTransfer, hasDesktopEnvironment: !!window.desktopEnvironment, href: location.href })'
      );
      logEvent('window:bridge-state', bridgeState);
    } catch (error) {
      logEvent('window:bridge-state-error', { error: error.message });
    }
  });

  if (isDev) {
    mainWindow.loadURL('http://localhost:3000');
    mainWindow.webContents.openDevTools();
  } else {
    const distPath = path.join(getDistDir(), 'index.html');
    if (fs.existsSync(distPath)) mainWindow.loadFile(distPath);
    else mainWindow.loadURL(loadFailureHtml());
  }

  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', event => {
    const targetUrl = event.url || '';
    if (isDev && targetUrl.startsWith('http://localhost:3000')) return;
    if (targetUrl.startsWith('file://')) return;
    event.preventDefault();
  });

  mainWindow.on('close', event => {
    if (quitConfirmed) return;
    if (confirmQuitWithActiveVisitors(mainWindow)) return;
    event.preventDefault();
  });

  mainWindow.on('query-session-end', event => {
    if (quitConfirmed) return;
    if (confirmQuitWithActiveVisitors(mainWindow)) return;
    event.preventDefault();
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });

  Menu.setApplicationMenu(null);
}

app.setAppUserModelId('com.codex.intranetflashtransfer');
const mainInstanceLock = app.requestSingleInstanceLock();
if (!mainInstanceLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
  });

  app.whenReady().then(async () => {
    configureSecurityPolicies();
    registerIpcHandlers();
    await loadAppState();
    startRuntimeIdleGuard();
    try {
      await startLanServer();
    } catch (error) {
      serverState.running = false;
      serverState.error = error.message;
      logEvent('lan-server:boot-failed', { error: error.message });
    }
    createWindow();

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
  });
}

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', event => {
  if (!quitConfirmed && !confirmQuitWithActiveVisitors(mainWindow)) {
    event.preventDefault();
    return;
  }
  stopRuntimeIdleGuard();
  if (lanServer) lanServer.close();
});

app.on('web-contents-created', (_event, contents) => {
  contents.on('will-attach-webview', event => event.preventDefault());
});
