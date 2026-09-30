import { chromium } from 'playwright';
const base = process.argv[2] || 'http://127.0.0.1:8762/';
const pages = ['index.html','roadmap.html','faq.html','whitepaper.html','guardian-economics.html'];
const browser = await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'});
const ctx = await browser.newContext({viewport:{width:1440,height:1000}, reducedMotion:'reduce'});
const summary = {};
for (const pg of pages) {
  const page = await ctx.newPage();
  await page.goto(base+pg, {waitUntil:'load', timeout:30000});
  await page.addStyleTag({content:'.r,*{opacity:1!important;animation:none!important;transition:none!important}'});
  const fails = await page.evaluate(() => {
    const parse = c => { const m = c.match(/rgba?\(([^)]+)\)/); if(!m) return null; const p=m[1].split(/[, /]+/).filter(Boolean).map(Number); return {r:p[0],g:p[1],b:p[2],a:p.length>3?p[3]:1}; };
    const lum = ({r,g,b}) => { const f=v=>{v/=255;return v<=0.03928?v/12.92:((v+0.055)/1.055)**2.4}; return 0.2126*f(r)+0.7152*f(g)+0.0722*f(b); };
    const blend=(fg,bg)=>({r:fg.r*fg.a+bg.r*(1-fg.a),g:fg.g*fg.a+bg.g*(1-fg.a),b:fg.b*fg.a+bg.b*(1-fg.a),a:1});
    const bgOf = el => { let layers=[]; for(let e=el;e;e=e.parentElement){const c=parse(getComputedStyle(e).backgroundColor); if(c&&c.a>0){layers.push(c); if(c.a>=1)break;}} let bg={r:5,g:5,b:5,a:1}; for(const l of layers.reverse()) bg=blend(l,bg); return bg; };
    const out = {};
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const t = walker.currentNode; if (!t.textContent.trim()) continue;
      const el = t.parentElement; const cs = getComputedStyle(el);
      if (cs.visibility==='hidden'||cs.display==='none') continue; if (el.closest('[aria-hidden="true"]')) continue; if ((cs.webkitBackgroundClip||cs.backgroundClip)==='text') continue;
      const r = el.getBoundingClientRect(); if (r.width===0||r.height===0) continue;
      let fg = parse(cs.color); if(!fg) continue; const bg=bgOf(el); fg=blend({...fg,a:fg.a*parseFloat(cs.opacity||1)},bg);
      const L1=lum(fg), L2=lum(bg); const ratio=(Math.max(L1,L2)+0.05)/(Math.min(L1,L2)+0.05);
      const size=parseFloat(cs.fontSize), bold=parseInt(cs.fontWeight)>=700; const large=size>=24||(bold&&size>=18.66);
      const need = large?3:4.5;
      if (ratio < need) { const key = el.tagName.toLowerCase()+(el.className&&typeof el.className==='string'?'.'+el.className.trim().split(/\s+/).join('.'):'')+` ${cs.color} ${ratio.toFixed(2)}`; out[key]=(out[key]||0)+1; }
    }
    return out;
  });
  summary[pg]=fails; await page.close();
}
await browser.close();
for (const [pg,f] of Object.entries(summary)) { const n=Object.values(f).reduce((a,b)=>a+b,0); console.log(`== ${pg}: ${n} failing text nodes, ${Object.keys(f).length} classes`); for (const [k,v] of Object.entries(f).sort((a,b)=>b[1]-a[1]).slice(0,40)) console.log(`  ${v}x ${k}`); }
