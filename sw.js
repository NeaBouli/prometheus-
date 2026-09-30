// Retired service worker (GH-275 / PRM-29).
// The previous worker precached root-absolute paths that do not exist under
// /prometheus-/, so it never installed, and its cache-first design would have
// pinned clients to stale pages. Pages no longer register a worker. This file
// stays only so that any browser that ever installed a worker from this scope
// fetches this update, clears every cache it owns, and unregisters itself.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.map(key => caches.delete(key))))
      .then(() => self.registration.unregister())
  );
});
