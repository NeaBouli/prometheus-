const CACHE = 'prometheus-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/faq.html',
  '/roadmap.html',
  '/whitepaper.html',
  '/logo/Prometheus.png',
  '/sitemap.xml',
  '/llms.txt'
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(ASSETS))
  );
});

self.addEventListener('fetch', e => {
  e.respondWith(
    caches.match(e.request).then(cached => {
      return cached || fetch(e.request).then(response => {
        return caches.open(CACHE).then(c => {
          c.put(e.request, response.clone());
          return response;
        });
      });
    })
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    )
  );
});
