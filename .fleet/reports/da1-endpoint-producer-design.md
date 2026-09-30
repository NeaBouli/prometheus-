id: da1-endpoint-producer-design (GH-258/GH-261 next observe-only slice)
status: ok (design only)
worker: claude (Codex stand-in, solo; PLAN assigned Kimi — Kimi token_limited)
summary: docs/endpoint-producer-design-v1.md — first producer candidate limited to resource_utilization (sustained_compute_saturation, accelerator_utilization_spike), Linux, host-wide aggregates only (/proc/stat first line, NVML device utilization; no per-process data). Derivation rules within GH-264 windows; every GH-267 future_requirement mapped to a control (opt-in file, local revocation/erasure, 7-day/1000-statement retention, no egress, no reuse for identity/reputation/rewards/action); residual risks (linkability, local adversary, evasion, false positives); non-goals; 5 review/promotion gates before code.
why this domain: directly serves GH-261 compute conscription and is the least privacy-invasive; other domains need separate designs.
tests: public documentation hygiene OK; public-claim consistency PASS (13 surfaces); GH-267 privacy gate OK. No code, no status change.
owner/codex items: independent privacy review + owner approval of retention/thresholds/opt-in text required before any implementation brief.
