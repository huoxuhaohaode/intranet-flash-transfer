/* 内网闪传 Service Worker：仅缓存应用外壳，绝不缓存 /api/* 数据接口 */
const CACHE_NAME = 'lan-transfer-shell-v1';
const SHELL = ['./', './manifest.webmanifest', './icons/icon-192.png', './icons/icon-512.png'];

self.addEventListener('install', event => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then(cache => cache.addAll(SHELL))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches
      .keys()
      .then(keys => Promise.all(keys.filter(key => key !== CACHE_NAME).map(key => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (event.request.method !== 'GET' || url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;
  // 带令牌/参数的页面请求始终走网络，避免把加密链接写入缓存键
  if (url.search) return;
  event.respondWith(fetch(event.request).catch(() => caches.match(event.request).then(match => match || caches.match('./'))));
});
