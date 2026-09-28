# A4H1 retry — README-only factual check

Read `.fleet/tasks/a4h-readme-honesty.md` and the cited evidence, then inspect
only `README.md` plus cited implementation lines. Correct only confirmed README
misstatements; do not touch any other file except the required Fleet report.

Check AI/models, scanner/YARA, validator command, PROM emission, KAS stake,
lifecycle wiring, sprint labels, version/test/completion wording. Do not copy
stale counts. Issues #282/#283 and all runtime/CI changes remain excluded.

Always write `.fleet/reports/a4h1-readme-only.md`, even when README is already
accurate; in that case use `status: ok`, `files: none`, and explain why no diff
is needed. Work only on `agent/<worker>/a4h1-readme-only`; no subagent or
external action.
