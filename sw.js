// Retired service worker (GH-275 / PRM-29).
// The previous worker precached root-absolute paths that do not exist under
// /prometheus-/, so it never installed, and its cache-first design would have
// pinned clients to stale pages. Pages no longer register a worker. This file
// stays only so that any browser that ever installed a worker from this scope
// fetches this update, clears the caches it owned, and unregisters itself.
// CacheStorage is shared by the whole GitHub Pages origin, so only the exact
// cache names the historical worker created (20e8531) are deleted; caches of
// other projects on the same origin are left untouched.
const OWNED_CACHES = ['prometheus-v1'];
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(key => OWNED_CACHES.includes(key)).map(key => caches.delete(key))
      ))
      .then(() => self.registration.unregister())
  );
});
