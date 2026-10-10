// GH275: isolated real-Chrome lifecycle fixtures, never historical live proof.
// PLAYWRIGHT_MODULE=/installed/playwright/index.js CHROME=/installed/chrome \
// EXPECTED_SOURCE_REVISION=<canonical40hex> EVIDENCE_DIR=/private/evidence \
// node scripts/browser_retired_service_worker_regression.mjs
// No installation, repository helper execution, or persistent browser profile.
import { createServer } from 'node:http';
import { readFile, writeFile, mkdir, copyFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = process.env.PROJECT_ROOT || path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const expectedRevision = process.env.EXPECTED_SOURCE_REVISION;
if (!expectedRevision) throw new Error('EXPECTED_SOURCE_REVISION is required');
if (!/^[0-9a-f]{40}$/.test(expectedRevision)) {
  throw new Error('EXPECTED_SOURCE_REVISION must be canonical lowercase 40hex');
}
const git = (...args) => execFileSync('git', args, { cwd: root });
const baseline = git('rev-parse', 'HEAD').toString().trim();
if (baseline !== expectedRevision) throw new Error('HEAD does not equal EXPECTED_SOURCE_REVISION');
const pages = ['index.html', 'faq.html', 'roadmap.html', 'whitepaper.html',
  'guardian-economics.html', 'googleaa2902079481c7a8.html'];
const files = [...pages, 'sw.js', 'assets/site.css', 'manifest.json',
  'logo/Prometheus-96.png', 'logo/Prometheus-880.png', 'logo/kas_coin-128.png', 'logo/prom_coin-128.png'];
const localProducts = new Map();
for (const file of files) {
  const bytes = await readFile(path.join(root, file));
  if (!bytes.equals(git('show', `${expectedRevision}:${file}`))) {
    throw new Error(`Local product file differs from EXPECTED_SOURCE_REVISION: ${file}`);
  }
  localProducts.set(file, bytes);
}
if (!process.env.PLAYWRIGHT_MODULE || !process.env.CHROME || !process.env.EVIDENCE_DIR) {
  throw new Error('Supply PLAYWRIGHT_MODULE, CHROME and private EVIDENCE_DIR explicitly');
}
const out = path.resolve(process.env.EVIDENCE_DIR);
await mkdir(out, { recursive: true, mode: 0o700 });
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
try {
  const previous = JSON.parse(await readFile(path.join(out, 'observations.json'), 'utf8'));
  const allowedScreenshots = new Set(['homepage-1440x1000.png', 'homepage-1180x820.png',
    'homepage-820x1180.png', 'homepage-390x844.png']);
  if (!Array.isArray(previous.screenshots) ||
      previous.screenshots.some(s => !s || !allowedScreenshots.has(s.filename))) {
    throw new Error('Prior screenshot filename is not an allowed emitted basename');
  }
  const archive = path.join(out, `prior-${sha(JSON.stringify(previous)).slice(0, 12)}`);
  await mkdir(archive, { recursive: true });
  for (const file of ['observations.json', 'repro.mjs', ...previous.screenshots.map(s => s.filename)]) {
    await copyFile(path.join(out, file), path.join(archive, file));
  }
} catch (error) { if (error.code !== 'ENOENT') throw error; }
const { chromium } = createRequire(import.meta.url)(process.env.PLAYWRIGHT_MODULE);
const legacy = git('show', '20e8531de5d39969a8c1fe32340d5411f7ab7af0:sw.js');
const retired = localProducts.get('sw.js');
const BASE = '/prometheus-/';
const PUBLIC = 'https://neabouli.github.io';
const roots = ['/', '/index.html', '/faq.html', '/roadmap.html', '/whitepaper.html',
  '/logo/Prometheus.png', '/sitemap.xml', '/llms.txt'];
const foreign = ['other-project-v1', 'prometheus-v2', 'prometheus-v1-extra',
  'prometheus-v10', 'x-prometheus-v1', 'workbox-precache-v2'];
const evidence = {
  schema: 1, status: 'partial', baseline, tested_source_revision: expectedRevision, browser: null,
  classification: 'loopback lifecycle fixtures plus exact public HTTP response replay',
  historical_live_install: 'not inferred; counterfactual success is not deployed history',
  sources: { historical_commit: '20e8531de5d39969a8c1fe32340d5411f7ab7af0',
    historical_sw_sha256: sha(legacy), retirement_sw_sha256: sha(retired) },
  public_resources: [], cases: [], screenshots: [],
  risks: ['Core full-suite/security/CI/acceptance and post-publication checks pending',
    'Independent archival-history fallback outside this block'],
};
const check = (result, name, ok, observed) => {
  result.assertions.push({ name, pass: Boolean(ok), observed });
};
const mime = file => ({ '.html': 'text/html', '.js': 'text/javascript',
  '.css': 'text/css', '.png': 'image/png', '.json': 'application/json' }[path.extname(file)] || 'text/plain');
// Only these exact public GETs and font URLs discovered in the existing CSS are fetched.
function get(url) {
  const parsed = new URL(url);
  if (!(parsed.origin === PUBLIC || parsed.origin === 'https://fonts.googleapis.com' ||
        parsed.origin === 'https://fonts.gstatic.com')) throw new Error('Non-allowlisted GET');
  const bytes = execFileSync('curl', ['-q', '--silent', '--show-error', '--max-time', '25',
    '--proto', '=https', '--request', 'GET', '--write-out', '\n%{http_code}', url],
  { maxBuffer: 8 * 1024 * 1024 });
  const split = bytes.lastIndexOf(10);
  return { status: Number(bytes.subarray(split + 1).toString()), body: bytes.subarray(0, split) };
}
const resources = new Map();
let server, browser;
async function snapshot(page) {
  return page.evaluate(async () => ({
    registrations: (await navigator.serviceWorker.getRegistrations()).length,
    controller: navigator.serviceWorker.controller?.state || null,
    caches: (await caches.keys()).sort(),
  }));
}
async function seed(page, names) {
  return page.evaluate(async names => {
    for (const name of names) {
      const cache = await caches.open(name);
      await cache.put(`/fixture/${name}`, new Response(`fixture:${name}`));
    }
  }, names);
}
async function contents(page) {
  return page.evaluate(async () => {
    const result = {};
    for (const name of await caches.keys()) {
      const cache = await caches.open(name);
      const response = await cache.match(`/fixture/${name}`);
      if (response) result[name] = await response.text();
    }
    return result;
  });
}
async function register(page, expected) {
  return page.evaluate(async ({ base, expected }) => {
    const registration = await navigator.serviceWorker.register(`${base}sw.js`,
      { scope: base, updateViaCache: 'none' });
    const worker = registration.installing || registration.waiting || registration.active;
    const transitions = [worker?.state];
    if (worker && worker.state !== expected && worker.state !== 'redundant') {
      await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Worker state deadline')), 15000);
        worker.addEventListener('statechange', () => {
          transitions.push(worker.state);
          if (worker.state === expected || worker.state === 'redundant') {
            clearTimeout(timeout); resolve();
          }
        });
      });
    }
    return { transitions, final: worker?.state };
  }, { base: BASE, expected });
}
async function unregistered(page) {
  const registrations = await page.evaluate(async () => (await navigator.serviceWorker.getRegistrations()).length);
  if (registrations !== 0) throw new Error('Registration remains after terminal worker state');
}
async function run(name, fn) {
  const result = { name, assertions: [] };
  evidence.cases.push(result);
  try { await fn(result); }
  catch (error) {
    // Error classes, not raw browser logs/URLs/profile paths, enter public evidence.
    result.failure = { type: error.name, classification: 'harness or browser operation failed' };
    await writeFile(path.join(out, `${name}-failure.txt`), String(error.stack));
  }
  result.pass = !result.failure && result.assertions.every(a => a.pass);
}
try {
  for (const file of files) {
    const fetched = get(`${PUBLIC}${BASE}${file}${file === 'assets/site.css' ? '?v=20260930' : ''}`);
    const local = localProducts.get(file);
    const equal = fetched.status === 200 && sha(fetched.body) === sha(local);
    evidence.public_resources.push({ resource: file, status: fetched.status,
      sha256: sha(fetched.body), equals_baseline: equal, equals_exact_git_blob: true,
      local_git_blob_sha256: sha(local) });
    resources.set(`${BASE}${file}`, { ...fetched, type: mime(file) });
  }
  resources.set(BASE, resources.get(`${BASE}index.html`));
  const rootResponses = new Map();
  for (const resource of roots) {
    const response = get(`${PUBLIC}${resource}`);
    rootResponses.set(resource, response);
    evidence.public_resources.push({ resource: `historical-root:${resource}`,
      status: response.status, sha256: sha(response.body) });
  }
  const fontCSSURL = 'https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500&family=Space+Mono:wght@400;700&display=swap';
  const fontCSS = get(fontCSSURL);
  const fontResources = new Map([[fontCSSURL, { ...fontCSS, type: 'text/css' }]]);
  for (const url of new Set([...fontCSS.body.toString().matchAll(/https:\/\/fonts\.gstatic\.com\/[^)\s]+/g)].map(m => m[0]))) {
    fontResources.set(url, { ...get(url), type: url.endsWith('.woff2') ? 'font/woff2' : 'font/ttf' });
  }
  evidence.sources.fonts = [...fontResources.values()].map(r => ({ status: r.status, sha256: sha(r.body) }));
  let mode = 'current';
  const requests = [];
  const fixtureHTML = Buffer.from('<!doctype html><title>GH275 isolated lifecycle fixture</title>');
  server = createServer((req, res) => {
    const pathname = new URL(req.url, 'http://fixture.invalid').pathname;
    let response;
    if (pathname === `${BASE}sw.js`) {
      response = { status: 200, body: mode === 'current' ? retired : legacy, type: 'text/javascript' };
    } else if (pathname === `${BASE}harness.html`) {
      response = { status: 200, body: fixtureHTML, type: 'text/html' };
    } else if (roots.includes(pathname) && mode === 'legacy-success') {
      // Counterfactual root availability only. Historical JS is unchanged.
      response = { status: 200, body: Buffer.from('counterfactual root resource'), type: 'text/plain' };
    } else if (roots.includes(pathname) && mode === 'legacy-missing') {
      response = { ...rootResponses.get(pathname), type: mime(pathname) };
    } else response = resources.get(pathname);
    response ||= { status: 404, body: Buffer.from('fixture not found'), type: 'text/plain' };
    requests.push({ resource: pathname, status: response.status, sha256: sha(response.body), mode });
    res.writeHead(response.status, { 'content-type': response.type, 'cache-control': 'no-store' });
    res.end(response.body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  browser = await chromium.launch({ executablePath: process.env.CHROME, chromiumSandbox: true });
  evidence.browser = browser.version();
  async function context(viewport = { width: 1440, height: 1000 }) {
    const ctx = await browser.newContext({ viewport, serviceWorkers: 'allow' });
    // Browser has no external egress: exact GET response replay for existing fonts only.
    await ctx.route('**/*', async route => {
      const url = route.request().url();
      if (url.startsWith(`${origin}/`)) return route.continue();
      const resource = fontResources.get(url);
      if (resource && route.request().method() === 'GET') return route.fulfill({
        status: resource.status, body: resource.body, contentType: resource.type });
      return route.abort('blockedbyclient');
    });
    return ctx;
  }
  await run('source-contract', async result => {
    check(result, 'exact unchanged historical and retirement script pins',
      sha(legacy) === '7e45aadd9d4c1e36df9a74e035b92193bf840d8e78819cadf1bf22da1edc7399' &&
      sha(retired) === 'e2821c24c190a8df9c8aff9582654554d0a6d68d8ecd35c9d5b79cb6a00f45a0', evidence.sources);
    check(result, 'current live files equal exact baseline',
      evidence.public_resources.filter(r => r.equals_baseline !== undefined).every(r => r.equals_baseline),
      evidence.public_resources.filter(r => r.equals_baseline === false).map(r => r.resource));
    for (const file of pages) {
      const html = resources.get(`${BASE}${file}`).body.toString();
      check(result, `${file}: no registration`, !/serviceWorker\s*\.\s*register/.test(html), null);
    }
    const html = resources.get(`${BASE}index.html`).body.toString();
    check(result, 'homepage development and no-production status',
      /development-stage/i.test(html) && /no production protocol network/i.test(html), null);
    check(result, 'actual missing-root status includes 404',
      [...rootResponses.values()].some(r => r.status === 404), [...rootResponses.values()].map(r => r.status));
  });
  await run('fresh-current-pages', async result => {
    mode = 'current';
    const ctx = await context();
    try {
      const page = await ctx.newPage();
      for (const file of pages) {
        const response = await page.goto(`${origin}${BASE}${file}`);
        const state = await snapshot(page);
        check(result, `${file}: current bytes and no worker`, response.status() === 200 &&
          sha(await response.body()) === sha(resources.get(`${BASE}${file}`).body) &&
          state.registrations === 0 && state.controller === null && state.caches.length === 0, state);
      }
    } finally { await ctx.close(); }
  });
  for (const update of [false, true]) {
    await run(update ? 'legacy-update-counterfactual' : 'fresh-retirement', async result => {
      mode = update ? 'legacy-success' : 'current';
      const ctx = await context();
      try {
        const page = await ctx.newPage();
        await page.goto(`${origin}${BASE}harness.html`);
        if (update) {
          result.install = await register(page, 'activated');
          check(result, 'historical worker genuinely activated', result.install.final === 'activated', result.install);
          result.after_install = await snapshot(page);
          check(result, 'historical precache present before foreign seeding',
            result.after_install.caches.includes('prometheus-v1'), result.after_install);
          await page.reload();
          check(result, 'historical worker controls reload', (await snapshot(page)).controller === 'activated', await snapshot(page));
        }
        await seed(page, ['prometheus-v1', ...foreign]);
        result.seeded = await snapshot(page);
        const before = await contents(page);
        if (update) {
          await page.evaluate(async base => {
            const cache = await caches.open('prometheus-v1');
            await cache.put(`${base}index.html`, new Response('<!doctype html><title>GH275 stale fixture</title><p>STALE_GH275</p>',
              { headers: { 'content-type': 'text/html' } }));
          }, BASE);
          await ctx.setOffline(true);
          await page.goto(`${origin}${BASE}index.html`);
          check(result, 'legacy offline cache-first negative control',
            (await page.content()).includes('STALE_GH275'), await snapshot(page));
          await ctx.setOffline(false);
          mode = 'current';
          result.update = await page.evaluate(async () => {
            const registration = await navigator.serviceWorker.getRegistration();
            let resolveUpdate;
            const found = new Promise(resolve => { resolveUpdate = resolve; });
            registration.addEventListener('updatefound', () => resolveUpdate(registration.installing), { once: true });
            const timeout = new Promise((_, reject) => setTimeout(() => reject(new Error('Update deadline')), 15000));
            await registration.update();
            const worker = await Promise.race([found, timeout]);
            const transitions = [worker.state];
            if (!['activated', 'redundant'].includes(worker.state)) {
              await Promise.race([new Promise(resolve => worker.addEventListener('statechange', () => {
                transitions.push(worker.state);
                if (['activated', 'redundant'].includes(worker.state)) resolve();
              })), timeout]);
            }
            return { transitions, final: worker.state };
          });
        } else result.install = await register(page, 'activated');
        await unregistered(page);
        result.after_retirement = await snapshot(page);
        const after = await contents(page);
        check(result, 'only exact historical cache removed',
          !result.after_retirement.caches.includes('prometheus-v1') &&
          JSON.stringify(result.after_retirement.caches) === JSON.stringify([...foreign].sort()), result.after_retirement);
        check(result, 'foreign and near-match cache bytes preserved',
          foreign.every(name => before[name] === after[name]), after);
        if (!update) await page.goto(`${origin}${BASE}index.html?recovery=1`);
        const response = await page.reload();
        result.after_reload = await snapshot(page);
        check(result, 'actual reload releases controller and registration',
          result.after_reload.controller === null && result.after_reload.registrations === 0, result.after_reload);
        check(result, 'current online bytes, not stale own cache',
          sha(await response.body()) === sha(resources.get(`${BASE}index.html`).body) &&
          !(await page.content()).includes('STALE_GH275'), null);
        await ctx.setOffline(true);
        let offlineFailure = false;
        try { await page.goto(`${origin}${BASE}index.html?offline=unique`, { timeout: 8000 }); }
        catch (error) { offlineFailure = /ERR_INTERNET_DISCONNECTED/.test(error.message); }
        check(result, 'offline current navigation unsupported, no stale response', offlineFailure, { offlineFailure });
        await ctx.setOffline(false);
        const recovery = await page.goto(`${origin}${BASE}index.html?online=recovery`);
        result.recovered = await snapshot(page);
        check(result, 'online recovery exact current bytes with no own cache or worker',
          sha(await recovery.body()) === sha(resources.get(`${BASE}index.html`).body) &&
          result.recovered.controller === null && result.recovered.registrations === 0 &&
          !result.recovered.caches.includes('prometheus-v1'), result.recovered);
      } finally { await ctx.close(); }
    });
  }
  await run('legacy-realistic-missing-root', async result => {
    mode = 'legacy-missing';
    const start = requests.length;
    const ctx = await context();
    try {
      const page = await ctx.newPage();
      await page.goto(`${origin}${BASE}harness.html`);
      result.install = await register(page, 'activated');
      await unregistered(page);
      result.state = await snapshot(page);
      result.requests = requests.slice(start);
      check(result, 'unmodified historical install becomes redundant', result.install.final === 'redundant', result.install);
      check(result, 'missing root fetched with actual public 404', result.requests.some(r => roots.includes(r.resource) && r.status === 404), result.requests);
      check(result, 'no active registration or controller after failed installation',
        result.state.registrations === 0 && result.state.controller === null, result.state);
      const cacheEntries = await page.evaluate(async () => {
        const cache = await caches.open('prometheus-v1');
        return (await cache.keys()).length;
      });
      check(result, 'failed addAll retained no precache responses', cacheEntries === 0, cacheEntries);
    } finally { await ctx.close(); }
  });
  mode = 'current';
  for (const [width, height] of [[1440, 1000], [1180, 820], [820, 1180], [390, 844]]) {
    await run(`homepage-${width}x${height}`, async result => {
      const ctx = await context({ width, height });
      try {
        const page = await ctx.newPage();
        const pageErrors = [];
        page.on('pageerror', error => pageErrors.push(error.name));
        await page.goto(`${origin}${BASE}index.html`, { waitUntil: 'networkidle' });
        await page.evaluate(() => document.fonts.ready);
        await page.waitForFunction(() => [...document.querySelectorAll('.hero h1, h1')].some(el =>
          Number(getComputedStyle(el).opacity) === 1));
        const metrics = await page.evaluate(() => {
          const h1 = document.querySelector('h1');
          const box = h1.getBoundingClientRect();
          const sub = document.querySelector('.hero-sub').getBoundingClientRect();
          const actions = document.querySelector('.hero-actions').getBoundingClientRect();
          return { viewport: [innerWidth, innerHeight], overflow: document.documentElement.scrollWidth - innerWidth,
            h1: { left: box.left, right: box.right, top: box.top, bottom: box.bottom,
              clipped: h1.scrollWidth > h1.clientWidth + 1 },
            verticalGaps: { headingToCopy: sub.top - box.bottom, copyToActions: actions.top - sub.bottom },
            fonts: [...document.fonts].map(f => ({ family: f.family, status: f.status })),
            images: [...document.images].map(i => ({ resource: i.getAttribute('src'), loaded: i.complete && i.naturalWidth > 0 })),
            heading: h1.innerText, bodyStatus: /no production protocol network/i.test(document.body.innerText) };
        });
        check(result, 'no horizontal overflow or clipped homepage heading', metrics.overflow === 0 &&
          !metrics.h1.clipped && metrics.h1.left >= 0 && metrics.h1.right <= width + 1, metrics);
        check(result, 'actual existing font families loaded', ['Space Grotesk', 'Space Mono'].every(family =>
          metrics.fonts.some(f => f.family.replaceAll('"', '') === family && f.status === 'loaded')), metrics.fonts);
        check(result, 'homepage heading, copy and actions do not overlap',
          metrics.verticalGaps.headingToCopy >= 0 && metrics.verticalGaps.copyToActions >= 0, metrics.verticalGaps);
        check(result, 'existing images render', metrics.images.every(i => i.loaded), metrics.images);
        check(result, 'visible current no-production status', metrics.bodyStatus, null);
        check(result, 'no page exceptions', pageErrors.length === 0, pageErrors);
        check(result, 'no registration/controller', (await snapshot(page)).registrations === 0 &&
          (await snapshot(page)).controller === null, await snapshot(page));
        const filename = `homepage-${width}x${height}.png`;
        await page.screenshot({ path: path.join(out, filename), fullPage: false, animations: 'disabled' });
        evidence.screenshots.push({ filename, sha256: sha(await readFile(path.join(out, filename))),
          viewport: [width, height], classification: 'current public HTTP replay, fresh isolated Chrome',
          inspected: false });
        if (width === 390) {
          await page.locator('#burger').click();
          check(result, 'mobile navigation opens', await page.locator('#mobile-menu').evaluate(el => el.classList.contains('open')), null);
          await page.locator('#burger').click();
          check(result, 'mobile navigation closes', await page.locator('#mobile-menu').evaluate(el => !el.classList.contains('open')), null);
        }
      } finally { await ctx.close(); }
    });
  }
  evidence.lifecycle_requests = requests.filter(r => r.resource.endsWith('/sw.js'));
} catch (error) {
  evidence.setup_failure = { type: error.name, classification: 'setup or public GET failed' };
  await writeFile(path.join(out, 'setup-failure.txt'), String(error.stack));
} finally {
  if (browser) await browser.close();
  if (server) await new Promise(resolve => server.close(resolve));
  evidence.browser_assertions_pass = !evidence.setup_failure && evidence.cases.every(c => c.pass);
  await writeFile(path.join(out, 'observations.json'), `${JSON.stringify(evidence, null, 2)}\n`);
  await copyFile(fileURLToPath(import.meta.url), path.join(out, 'repro.mjs'));
}
console.log(JSON.stringify({ status: evidence.status, pass: evidence.browser_assertions_pass,
  cases: evidence.cases.map(c => ({ name: c.name, pass: c.pass })), setup_failure: evidence.setup_failure || null }));
if (!evidence.browser_assertions_pass) process.exitCode = 1;
