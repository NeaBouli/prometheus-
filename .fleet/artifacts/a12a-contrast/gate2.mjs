import { chromium } from 'playwright';
const [,, base, out] = process.argv;
const VP=[[1440,1000],[1180,820],[820,1180],[390,844]];
const pages=['index.html','roadmap.html','faq.html','whitepaper.html','guardian-economics.html'];
const shots={'index.html':['.hero','.metrics-grid','.tok-row','.cta-wrap','footer'],'roadmap.html':['.sprint','footer'],'faq.html':['.faq-item','footer'],'whitepaper.html':['table','footer'],'guardian-economics.html':['table','footer']};
const b=await chromium.launch({executablePath:'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'});
const res=[];
for (const [w,h] of VP){ const ctx=await b.newContext({viewport:{width:w,height:h},reducedMotion:'reduce'});
 for (const pg of pages){ const p=await ctx.newPage(); const errs=[]; p.on('pageerror',e=>errs.push(String(e)));
  await p.goto(base+pg,{waitUntil:'load',timeout:30000});
  await p.addStyleTag({content:'*,.r{animation:none!important;transition:none!important} .r{opacity:1!important;transform:none!important} nav{position:static!important}'});
  const m=await p.evaluate(()=>{const se=document.scrollingElement;const ids=[...document.querySelectorAll('[id]')].map(e=>e.id);
   const clipped=[...document.querySelectorAll('p,li,a,span,div,td,th,h1,h2,h3')].filter(e=>{const cs=getComputedStyle(e);return e.children.length===0&&e.textContent.trim()&&cs.overflow!=='visible'&&e.scrollWidth>e.clientWidth+1}).length;
   return {hOverflow:se.scrollWidth-innerWidth,dupIds:[...new Set(ids.filter((v,i)=>ids.indexOf(v)!==i))].length,clipped}});
  res.push(`${w}x${h} ${pg} hOverflow=${m.hOverflow} dupIds=${m.dupIds} clipped=${m.clipped} errors=${errs.length}`);
  if (w===1440||w===390) for (const sel of shots[pg]){ const el=p.locator(sel).first(); if(!(await el.count())) continue; const fn=out+'/'+pg.replace('.html','')+'-'+sel.replace(/[^a-z]/g,'')+'-'+w+'.png'; await el.screenshot({path:fn}).catch(e=>console.log('shotfail',pg,sel,String(e).slice(0,80))); }
  await p.close(); }
 await ctx.close(); }
await b.close(); console.log(res.join('\n'));
