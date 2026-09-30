import { chromium } from 'playwright';
const out = process.argv[2];
const VP = [[1440,1000],[1180,820],[820,1180],[390,844]];
const targets = [
  {page:'index.html', sel:'.metrics-grid', name:'metrics'},
  {page:'index.html', sel:'.layers-grid', name:'layers'},
  {page:'guardian-economics.html', sel:'.solutions-grid', name:'solutions'},
];
const vers = {before:'http://127.0.0.1:8761/', after:'http://127.0.0.1:8762/'};
const browser = await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'});
const results = [];
for (const [w,h] of VP) for (const [ver,base] of Object.entries(vers)) {
  const ctx = await browser.newContext({viewport:{width:w,height:h}, reducedMotion:'reduce'});
  for (const pg of ['index.html','guardian-economics.html']) {
    const page = await ctx.newPage(); const errs=[];
    page.on('pageerror', e=>errs.push(String(e)));
    await page.goto(base+pg, {waitUntil:'load', timeout:30000});
    // force reveal animations
    await page.addStyleTag({content:'.r{opacity:1!important;transform:none!important;transition:none!important}'});
    const m = await page.evaluate(() => {
      const se = document.scrollingElement;
      const ids = [...document.querySelectorAll('[id]')].map(e=>e.id);
      const dup = ids.filter((v,i)=>ids.indexOf(v)!==i);
      const broken = [...document.querySelectorAll('a[href^="#"]')].map(a=>a.getAttribute('href').slice(1)).filter(id=>id && !document.getElementById(id));
      const clipped = [...document.querySelectorAll('.metric-k,.metric-v,.sol-impact,.layer-items li')].filter(e=>e.scrollWidth>e.clientWidth+1).length;
      const outOfParent = [...document.querySelectorAll('.metric,.sol-card,.layer')].filter(e=>{const p=e.parentElement.getBoundingClientRect(), r=e.getBoundingClientRect(); return r.left<p.left-1||r.right>p.right+1;}).length;
      return {hOverflow: se.scrollWidth - window.innerWidth, dupIds:[...new Set(dup)], brokenAnchors:[...new Set(broken)], clipped, outOfParent};
    });
    results.push({vp:`${w}x${h}`, ver, pg, ...m, errors:errs.length});
    for (const t of targets.filter(t=>t.page===pg)) {
      const el = page.locator(t.sel).first();
      await el.scrollIntoViewIfNeeded();
      await el.screenshot({path:`${out}/${ver}-${t.name}-${w}x${h}.png`});
    }
    await page.close();
  }
  await ctx.close();
}
await browser.close();
console.log(JSON.stringify(results,null,0).replace(/},{/g,'},\n{'));
