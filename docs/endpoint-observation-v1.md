# Endpoint Observation Statement v1

GH-264 defines one canonical, local-only statement for bounded endpoint
behavior categories. It is the first implemented observe-only data contract
under the GH-258/GH-261 roadmap. It is not an endpoint sensor, detector,
classifier, correlation service, warning system, transport, or response engine.
It adds no production behavior or authority.

## Canonical Wire

The compact JSON field order is fixed:

~~~text
schema_version, domain, signal, event_count, window_seconds,
report_nonce, observed_at, network_id
~~~

The parser accepts at most 512 bytes. Schema version is 1; event_count is
1..=255; window_seconds is one of 60, 300, 900, or 3600; report_nonce is 32
opaque bytes encoded as 64 lowercase hexadecimal characters; observed_at is a
positive minute-aligned u64; and network_id must equal a separately trusted
local network.

The closed domains are process, file, network, persistence, credential access,
model/tool, and resource utilization. Their 15 signals are likewise closed and
must match the declared domain. The schema has no path, process name, command
line, address, host/device identifier, prompt, credential, file content,
arbitrary label, or free-text field.

Rust and Python parse the same exact-byte corpus. The corpus contains 20 valid
cases, including every signal and every mutable digest field, plus 42 invalid
canonicalization, scalar, domain/signal, trust-context, and forbidden-field
cases. One redacted error covers all rejection paths.

## Digest

~~~text
SHA256(
  "prometheus-endpoint-observation-v1\\0" ||
  u32be(canonical_length) ||
  canonical_statement
)
~~~

This digest binds the canonical statement bytes. It does not prove that an
event occurred, that it is malicious, that its source or count is accurate,
that privacy is safe, or that disclosure or action is authorized.

## Safety Boundary

GH-264 accepts caller-supplied bytes only. It performs no process, file,
network, credential, model, accelerator, or OS access and collects no
telemetry. It provides no correlation, AI/AGI/actor/intent attribution,
warning, transport, proof, analysis, containment, automation, wallet, chain,
contract, Guardian, or production authority.

The next endpoint slice must separately design opt-in least-privileged
producers and complete privacy/threat-model review before any real host data is
read. Automatic process termination, quarantine, firewall mutation, credential
rotation, remote commands, deletion, and host isolation remain disabled and
unauthorized.
