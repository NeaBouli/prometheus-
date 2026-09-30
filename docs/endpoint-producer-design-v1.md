# Endpoint Producer Design v1 (design candidate, not implemented)

Status: design-only review package for the next GH-258/GH-261 observe-only
slice (fleet block DA1). Nothing in this document is implemented, enabled, or
authorized. It adds no sensor, collection, retention, transport, warning,
response, or production behavior, and it does not change any public status
capability. The canonical output boundary remains the GH-264
[Endpoint Observation Statement v1](endpoint-observation-v1.md); every
requirement below comes from the GH-267 pre-producer privacy/threat model
(`docs/evidence/endpoint-producer-privacy-threat-model-v1.json`).

## 1. Why this producer first

The first producer candidate covers only the `resource_utilization` domain and
its two signals, `sustained_compute_saturation` and
`accelerator_utilization_spike`.

- It addresses the GH-261 scenario of unauthorized compute conscription
  (endpoints, accelerators or servers commandeered into a compute mesh).
- It is the least privacy-invasive domain: it can be derived from host-wide
  aggregate counters without reading any process, file, network, credential,
  prompt, or user data.
- Process, file, network, persistence, credential-access, and model/tool
  producers require materially more sensitive access. They are out of scope
  for v1 and each needs its own design and review.

## 2. Inputs (read-only, aggregate only)

Linux only for v1:

| Signal | Input | Access |
|---|---|---|
| `sustained_compute_saturation` | Host-wide CPU busy ratio from two readings of the first line of `/proc/stat` | Unprivileged read; no per-process or per-cgroup data |
| `accelerator_utilization_spike` | Device-wide GPU utilization percentage from the NVIDIA Management Library (NVML), aggregate per device | Unprivileged NVML query; no process list call |

Explicitly not read: `/proc/<pid>/*`, process names or command lines, cgroup
membership, per-process GPU accounting, file paths, sockets, addresses,
hostnames, user names, environment variables, model inputs or outputs.

## 3. Derivation

- The producer samples at a fixed 10-second period and evaluates one window of
  60, 300, 900 or 3600 seconds (the only windows GH-264 accepts); the window is
  fixed in the owner configuration.
- `sustained_compute_saturation`: emitted when the host-wide CPU busy ratio is
  at least 90 % for every sample in the window. `event_count` = number of
  consecutive saturated windows, capped at 255.
- `accelerator_utilization_spike`: emitted when any device reports at least
  90 % utilization for at least half of the samples in a window during which
  the owner has declared no expected accelerator workload.
  `event_count` = number of such windows, capped at 255.
- Thresholds are owner configuration with the values above as upper-bounded
  defaults; they carry no claim of accuracy, maliciousness, or attribution.
- `observed_at` is truncated to the minute; `report_nonce` is 32 fresh random
  bytes per statement; `network_id` is the separately trusted local network.
  No other field exists.

A saturated CPU or busy GPU is common and usually benign (builds, training,
games, mining the owner runs). The statement records a bounded category, never
a verdict.

## 4. Privacy controls (mapping to GH-267 requirements)

| GH-267 requirement | Design element |
|---|---|
| default-off, explicit informed per-host opt-in | No producer runs unless the owner creates an owner-only configuration file that names the domain and acknowledges this document; absent or unreadable file means off |
| local revocation without remote dependency | Deleting the configuration file (or one CLI flag) stops sampling at the next period and triggers local erasure |
| least-privilege OS access scoped to declared domains | Only the two inputs in section 2; runs as the unprivileged owner; no capabilities; OS sandbox profile limited to `/proc/stat` and the NVML device |
| bounded aggregate counts only | Only the counters above; no raw samples leave process memory |
| local-only aggregation and redaction | Derivation happens in-process; only canonical GH-264 statements are written |
| data minimization to the eight fields | Output is exactly the GH-264 wire; the shared Rust/Python parser is the gate |
| linkability review (count, time, nonce, network) | Minute truncation, fresh nonce, capped counts; section 5 records residual linkability |
| explicit bounded retention and local erasure | Owner-only local file, at most 7 days or 1,000 statements, whichever is smaller; oldest first deletion; full erasure on revocation |
| independent privacy review before implementation | Implementation starts only after the review in section 7 |
| separate transport and recipient authorization | v1 has no network egress at all; any transport is a later, separately reviewed slice |
| no reuse for identity, reputation, rewards, or automatic action | Statements are not an input to membership, Guardian reputation, PROM rewards, or any response path |

## 5. Residual risks and threat model

- **Linkability:** a sequence of minute timestamps and counts can reveal usage
  patterns of one host (for example working hours or gaming sessions). The
  data stays local in v1; any future transport must add a linkability review
  (batching, coarsening or aggregation across hosts).
- **Local adversary:** malware with the owner's privileges can suppress,
  forge, or delete statements. The producer therefore offers no integrity
  guarantee and no proof of absence; statements are unauthenticated local
  observations.
- **Evasion:** conscription throttled below the thresholds is not detected.
  The producer claims no detection rate.
- **False positives:** legitimate heavy workloads trigger the signals. Because
  there is no warning or response in v1, a false positive has no effect beyond
  a local file entry.
- **Resource cost:** one `/proc/stat` read and one NVML query every 10 seconds;
  bounded memory for one window.

## 6. Non-goals (stay disabled and unauthorized)

Process termination, quarantine, firewall changes, credential rotation, remote
commands, deletion, host isolation, correlation across devices, AI/AGI/actor
or intent attribution, warnings, network transport, and any production claim.

## 7. Review and promotion gates before any code

1. Independent privacy review of this design against the GH-267 model,
   recorded as a dated update of the privacy/threat-model artifact.
2. Owner approval of the retention bound, thresholds, and opt-in text.
3. Implementation brief naming the architecture node
   (`modules/threat-hint` producer module plus a client CLI opt-in) with the
   shared GH-264 corpus as the output gate and new negative tests for every
   prohibited input class.
4. Security review of the sandbox profile and file permissions.
5. Public status capabilities stay false until a dated promotion record.
