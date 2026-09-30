"""Remove CSS declarations that a later top-level rule with the identical selector overrides.

Only top-level style rules are considered; every @-block (media, keyframes, supports,
font-face) is kept verbatim. Cascade is preserved: a declaration is dropped only when the
same property is declared again later for the same selector at top level.
"""
import re, sys
from pathlib import Path
def dedupe(css):
    items=[]; i=0; at=re.compile(r"\s*@[a-zA-Z-]+[^{;]*\{")
    while i<len(css):
        mm=at.match(css,i)
        if mm:
            depth=0; j=css.index("{",mm.start())
            while True:
                if css[j]=="{": depth+=1
                elif css[j]=="}":
                    depth-=1
                    if depth==0: break
                j+=1
            items.append(["raw",css[i:j+1]]); i=j+1; continue
        k=css.find("{",i)
        if k<0: items.append(["raw",css[i:]]); break
        pre=css[i:k]; lead=re.match(r"(\s*(?:/\*.*?\*/\s*)*)",pre,re.S).group(1)
        if lead: items.append(["raw",lead])
        e=css.find("}",k); items.append(["rule",pre[len(lead):],css[k+1:e]]); i=e+1
    norm=lambda x:" ".join(x.split())
    decls=lambda b:[(d.split(":",1)[0].strip(),d.split(":",1)[1].strip()) for d in b.split(";") if ":" in d and d.strip()]
    groups={}
    for idx,it in enumerate(items):
        if it[0]=="rule": groups.setdefault(norm(it[1]),[]).append(idx)
    stats=[0,0,0]
    for idxs in groups.values():
        if len(idxs)<2: continue
        stats[0]+=1; later=set()
        for ix in reversed(idxs):
            ds=decls(items[ix][2]); keep=[(n,v) for n,v in ds if n not in later or "!important" in v]
            stats[1]+=len(ds)-len(keep); later|={n for n,_ in ds}
            if keep: items[ix][2]=";".join(f"{n}:{v}" for n,v in keep)
            else: items[ix]=["raw",""]; stats[2]+=1
    return "".join(it[1] if it[0]=="raw" else it[1]+"{"+it[2]+"}" for it in items), stats
for f in sys.argv[1:]:
    p=Path(f); s=p.read_text(); m=re.search(r"<style>(.*?)</style>",s,re.S)
    new,st=dedupe(m.group(1)); p.write_text(s[:m.start(1)]+new+s[m.end(1):])
    print(f,"dup selectors",st[0],"dead declarations",st[1],"emptied rules",st[2])
