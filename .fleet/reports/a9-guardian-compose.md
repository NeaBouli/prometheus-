id: a9-guardian-compose (R7, GH-280, PRM-10)
status: ok
worker: claude (Codex stand-in, solo); decisions delegated by Gio
decisions: (1) UID:GID 2000:2000 — root group removed; ./models must be readable by UID/GID 2000 (documented). (2) Explicit CPU caps: 8B cpus "16", 70B cpus "64" (generous, bounded; pids/mem/shm unchanged). (3) /tmp NOT noexec: vLLM/Triton/torch load JIT-compiled kernels from the HOME=/tmp cache; noexec would break inference; nosuid,nodev,size unchanged and drift now tested. (4) Unauthenticated loopback vLLM kept and documented as single-operator-host trust boundary (every local process/user can prompt it); no API key because the Compose file must require no secret.
files: modules/guardian-node/docker-compose.yml, scripts/verify_guardian_vllm_compose.py, modules/guardian-node/tests/test_guardian_vllm_compose.py (+root-group, cpus, tmpfs-drift tests), modules/guardian-node/README.md
tests: verify_guardian_vllm_compose OK; compose tests 35 passed; full Guardian suite 1428 passed / 4 skipped; Black; Pylint 10.00; doc hygiene; claims.
risks: `docker compose config` rendering (cpus as string) is only proven by hosted CI (no local docker compose); real GPU inference with UID/GID 2000:2000 is unverified (no GPU host) — if an image path needs group 0, the failure is visible at start, not silent.
review owed to Codex: yes (container security surface).
