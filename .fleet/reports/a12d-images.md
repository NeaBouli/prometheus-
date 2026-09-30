id: a12d-images (GH-278, PRM-47 performance)
status: ok
worker: claude (Codex stand-in, solo)
summary: sips-resized variants logo/Prometheus-96.png (4.9 KB, nav 26px @2x+), Prometheus-880.png (179 KB, hero ambient up to 440px @2x), kas_coin-128.png (8 KB), prom_coin-128.png (16 KB); <img> tags on five pages switched, with width/height; the absolute /prometheus-/ coin paths became relative (work on Pages and locally). Index image transfer ≈3.1 MB → ≈208 KB. Originals untouched (og:image, manifest, README, sw.js list).
tests: all four images load and display at 1440 and 390 (DPR 2); layout gate 5 pages × 4 viewports clean; claim consistency; verify_site_css; screenshots inspected (nav, hero, token cards).
finding (not changed, owner scope): index.html token card "Tested cooldown: 7 days on exit" repeats the PRM-35 discrepancy (COOLDOWN_BLOCKS = 100,800 ≈ 2.8 h at 10 BPS); resolution belongs to MS-B/#276.
remaining in GH-278: A12c shared stylesheet (PRM-44).
