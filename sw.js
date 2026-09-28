const CACHE = 'study-log-v14';
const LOCAL_ASSETS = [
  './', './index.html', './manifest.json', './icon-192.png', './icon-512.png', './icon-512-maskable.png', './sound-start.mp3',
  './badge-6h.jpg', './badge-7h.jpg', './badge-8h.jpg', './badge-9h.jpg', './badge-10h.jpg', './badge-12h.jpg',
  './popup-6h.jpg', './popup-7h.jpg', './popup-8h.jpg', './popup-9h.jpg', './popup-10h.jpg', './popup-12h.jpg'
];
// Third-party files the app needs to work offline (Chart.js is versioned, so safe to keep)
const REMOTE_ASSETS = ['https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js'];

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    // Add one by one so a single missing/failed file never blocks the whole update
    await Promise.all(LOCAL_ASSETS.map((u) => c.add(u).catch(() => {})));
    await Promise.all(REMOTE_ASSETS.map((u) => c.add(new Request(u, { mode: 'cors' })).catch(() => {})));
  })());
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter((n) => n !== CACHE).map((n) => caches.delete(n)));
    await self.clients.claim();
  })());
});

async function rangeResponse(req, cached) {
  const buf = await cached.arrayBuffer();
  const m = /bytes=(\d*)-(\d*)/.exec(req.headers.get('range') || '');
  const start = m && m[1] ? parseInt(m[1], 10) : 0;
  const end = m && m[2] ? Math.min(parseInt(m[2], 10), buf.byteLength - 1) : buf.byteLength - 1;
  return new Response(buf.slice(start, end + 1), {
    status: 206,
    statusText: 'Partial Content',
    headers: {
      'Content-Type': cached.headers.get('Content-Type') || 'application/octet-stream',
      'Content-Range': 'bytes ' + start + '-' + end + '/' + buf.byteLength,
      'Content-Length': String(end - start + 1)
    }
  });
}

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return;

  e.respondWith((async () => {
    const cache = await caches.open(CACHE);

    // Audio/video range requests: answer from cache (needed for offline + Safari)
    if (req.headers.has('range')) {
      const hit = await cache.match(url.href, { ignoreSearch: true });
      if (hit) { try { return await rangeResponse(req, hit); } catch (err) {} }
      return fetch(req);
    }

    try {
      const res = await fetch(req);
      // Only store complete, successful responses (never 206 partials or errors)
      if (res && res.status === 200 && (res.type === 'basic' || res.type === 'cors')) {
        cache.put(req, res.clone()).catch(() => {});
      }
      return res;
    } catch (err) {
      const hit = await cache.match(req, { ignoreSearch: true });
      if (hit) return hit;
      if (req.mode === 'navigate') {
        const shell = await cache.match('./index.html');
        if (shell) return shell;
      }
      return new Response('Offline', { status: 503, statusText: 'Offline' });
    }
  })());
});
