// Real-browser regression for the retired service worker (sw.js).
// Seeds the historical Prometheus cache plus unrelated caches on the same
// origin, activates the retired worker, and asserts that only the owned cache
// is deleted and the registration is gone. Requires Playwright + Chromium:
//   PLAYWRIGHT_MODULE=/path/to/node_modules/playwright/index.js \
//     node scripts/browser_retired_service_worker_regression.mjs
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const BASE = '/prometheus-/';
const OWNED = ['prometheus-v1'];
const UNRELATED = ['other-project-v1', 'prometheus-v2', 'workbox-precache-v2'];

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname === BASE) {
    res.writeHead(200, { 'content-type': 'text/html' });
    return res.end('<!doctype html><title>sw regression</title>');
  }
  if (url.pathname === `${BASE}sw.js`) {
    res.writeHead(200, { 'content-type': 'text/javascript' });
    return res.end(await readFile(path.join(root, 'sw.js')));
  }
  res.writeHead(404);
  res.end();
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const origin = `http://localhost:${server.address().port}`;

const browser = await chromium.launch();
let failed = false;
try {
  const page = await browser.newPage();
  const errors = [];
  page.on('pageerror', err => errors.push(String(err)));
  await page.goto(`${origin}${BASE}`);
  await page.evaluate(async names => {
    for (const name of names) {
      const cache = await caches.open(name);
      await cache.put(`/seed/${name}`, new Response(name));
    }
  }, [...OWNED, ...UNRELATED]);
  const before = await page.evaluate(() => caches.keys());
  await page.evaluate(async base => {
    await navigator.serviceWorker.register(`${base}sw.js`, { scope: base });
  }, BASE);
  const result = await page.evaluate(async () => {
    const deadline = Date.now() + 10000;
    while (Date.now() < deadline) {
      const regs = await navigator.serviceWorker.getRegistrations();
      if (regs.length === 0) break;
      await new Promise(r => setTimeout(r, 100));
    }
    return {
      registrations: (await navigator.serviceWorker.getRegistrations()).length,
      caches: (await caches.keys()).sort(),
    };
  });
  console.log(JSON.stringify({ before: before.sort(), after: result, errors }));
  const check = (ok, msg) => { if (!ok) { failed = true; console.error(`FAIL: ${msg}`); } };
  check(before.length === OWNED.length + UNRELATED.length, 'caches were not seeded');
  check(result.registrations === 0, 'retired worker registration still present');
  for (const name of OWNED) check(!result.caches.includes(name), `owned cache ${name} not deleted`);
  for (const name of UNRELATED) check(result.caches.includes(name), `unrelated cache ${name} deleted`);
  check(errors.length === 0, `page errors: ${errors.join('; ')}`);
} finally {
  await browser.close();
  server.close();
}
if (failed) process.exit(1);
console.log('OK: retired service worker removes only owned caches and unregisters');
