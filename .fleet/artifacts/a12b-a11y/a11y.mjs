import { chromium } from 'playwright';
const out=process.argv[2]; const base='http://127.0.0.1:8762/';
const b=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'});
const pages=['index.html','roadmap.html','faq.html','whitepaper.html','guardian-economics.html'];
for (const [w,h] of [[1440,1000],[390,844]]) {
 const ctx=await b.newContext({viewport:{width:w,height:h}});
 for (const pg of pages){ const p=await ctx.newPage(); await p.goto(base+pg,{waitUntil:'load'});
  await p.keyboard.press('Tab');
  const f=await p.evaluate(()=>{const a=document.activeElement; const r=a.getBoundingClientRect(); return {cls:a.className,text:a.textContent.trim(),inView:r.left>=0&&r.top>=0&&r.right<=innerWidth,w:Math.round(r.width),h:Math.round(r.height)}});
  if (w===390&&pg==='index.html') await p.screenshot({path:`${out}/skip-focus-${pg.replace('.html','')}-${w}.png`, clip:{x:0,y:0,width:w,height:120}});
  await p.keyboard.press('Enter'); await p.waitForTimeout(100);
  const tgt=await p.evaluate(()=>location.hash+' focus='+(document.activeElement.id||document.activeElement.tagName));
  console.log(`${w} ${pg} firstTab=${f.cls}:${f.text} visible=${f.inView} size=${f.w}x${f.h} after=${tgt}`); await p.close(); }
 await ctx.close(); }
// reduced motion: hero visible immediately
{ const ctx=await b.newContext({viewport:{width:1440,height:1000},reducedMotion:'reduce'}); const p=await ctx.newPage();
  await p.goto(base+'index.html',{waitUntil:'domcontentloaded'}); await p.waitForTimeout(150);
  const o=await p.evaluate(()=>['.hero-h1','.hero-sub','.hero-actions'].map(s=>getComputedStyle(document.querySelector(s)).opacity));
  console.log('reduced-motion hero opacity at 150ms', o.join(',')); await p.screenshot({path:`${out}/reduced-motion-index-1440.png`}); await ctx.close(); }
// no JS: reveal content visible
{ const ctx=await b.newContext({viewport:{width:1440,height:1000},javaScriptEnabled:false}); const p=await ctx.newPage();
  for (const pg of pages){ await p.goto(base+pg,{waitUntil:'load'}); const hidden=await p.evaluate(()=>[...document.querySelectorAll('.r')].filter(e=>getComputedStyle(e).opacity==='0').length); console.log('noJS',pg,'hidden .r =',hidden); }
  await ctx.close(); }
await b.close();
