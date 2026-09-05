const CACHE = 'study-log-v6';
const ASSETS = [
  './', './index.html', './manifest.json', './icon-192.png', './icon-512.png', './sound-start.mp3',
  './badge-6h.jpg', './badge-7h.jpg', './badge-8h.jpg', './badge-9h.jpg', './badge-10h.jpg', './badge-12h.jpg',
  './popup-6h.jpg', './popup-7h.jpg', './popup-8h.jpg', './popup-9h.jpg', './popup-10h.jpg', './popup-12h.jpg'
];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((names) => Promise.all(
      names.filter((n) => n !== CACHE).map((n) => caches.delete(n))
    ))
  );
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  e.respondWith(
    fetch(e.request).then((res) => {
      const copy = res.clone();
      caches.open(CACHE).then((c) => c.put(e.request, copy));
      return res;
    }).catch(() => caches.match(e.request))
  );
});
