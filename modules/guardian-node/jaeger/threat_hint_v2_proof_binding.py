"""Local-only data-only ThreatHint-v2 envelope/manifest compatibility binding.

The binding reparses both canonical objects against one separately trusted
network, pins the raw manifest bytes to a separately trusted SHA-256 anchor
before manifest parsing, cross-checks the exact protocol, relation, and
network identities, recomputes the statement digest from the
manifest-declared domain bytes, and derives the two claimed 16-byte
big-endian public-input halves of the ``sha256_split_u128_bn254_v2``
encoding.

Structural compatibility and the derived claimed public inputs are not
Groth16 proof acceptance and not rollout readiness: this module performs no
proof verification, key or source loading, circuit or key approval, ceremony
validation, file or network I/O, or any other operational action. The proof
bytes remain opaque.

The fail-closed order is fixed: trusted network and trusted manifest anchor
validation, raw manifest byte-anchor comparison, manifest parsing, envelope
parsing (which reparses the embedded canonical statement), identity
cross-checks, manifest-domain statement-digest recomputation, and
public-input encoding/count assertion with half derivation. Steps five
through seven are defense-in-depth drift closures: while both public parsers
pin the same closed constants those mismatch branches are unreachable, and
they are documented here rather than weakening either parser.
"""

# Exact built-in types are protocol requirements.
# pylint: disable=unidiomatic-typecheck

from __future__ import annotations

import hashlib
import re
import weakref
from dataclasses import dataclass
from typing import Any, Tuple

from jaeger.relation_manifest_v2 import RelationManifestV2, RelationManifestV2Error
from jaeger.threat_hint_v2_proof_envelope import (
    ThreatHintV2ProofEnvelope,
    ThreatHintV2ProofEnvelopeError,
)

PUBLIC_INPUT_ENCODING = "sha256_split_u128_bn254_v2"
PUBLIC_INPUT_COUNT = 2
_BindingSnapshot = Tuple[bytes, bytes, str, str, str, bytes, bytes]


class ThreatHintV2ProofBindingError(ValueError):
    """Redacted local binding failure."""

    def __init__(self) -> None:
        super().__init__("invalid threat-hint v2 proof binding")


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ThreatHintV2ProofBinding:
    """Immutable binding result with no proof or operational authority.

    Direct construction is disabled; ``bind_canonical`` is the only
    supported construction path. The weakref identity snapshot binds the
    derived anchors and claimed halves to this exact instance so that
    mutation or a forged same-shape instance fails closed on every derived
    read. This is object-integrity hardening, not authority against
    arbitrary code in the same interpreter.
    """

    envelope: ThreatHintV2ProofEnvelope
    manifest: RelationManifestV2

    def __init__(self) -> None:
        """Reject direct construction outside canonical binding."""
        raise TypeError("direct threat-hint v2 proof binding construction is disabled")

    @classmethod
    def bind_canonical(
        cls,
        envelope_wire: bytes,
        manifest_wire: bytes,
        trusted_network_id: str,
        trusted_manifest_sha256_hex: str,
    ) -> "ThreatHintV2ProofBinding":
        """Bind raw wires against trusted anchors in one fail-closed pass."""
        if cls is not ThreatHintV2ProofBinding:
            raise ThreatHintV2ProofBindingError()
        if type(envelope_wire) is not bytes or type(manifest_wire) is not bytes:
            raise ThreatHintV2ProofBindingError()

        # Step 1: validate the separately trusted network and manifest
        # anchor before any hashing or parsing.
        _validate_network_id(trusted_network_id)
        _validate_anchor(trusted_manifest_sha256_hex)

        # Step 2: compare the exact raw manifest bytes against the trusted
        # anchor before the manifest is parsed.
        raw_manifest_sha256_hex = hashlib.sha256(manifest_wire).hexdigest()
        if raw_manifest_sha256_hex != trusted_manifest_sha256_hex:
            raise ThreatHintV2ProofBindingError()

        # Step 3: parse the canonical manifest against the trusted network.
        try:
            manifest = RelationManifestV2.parse_canonical(
                manifest_wire, trusted_network_id
            )
        except RelationManifestV2Error:
            raise ThreatHintV2ProofBindingError() from None

        # Step 4: parse the canonical envelope against the same trusted
        # network; the envelope parser reparses the embedded statement.
        try:
            envelope = ThreatHintV2ProofEnvelope.parse_canonical(
                envelope_wire, trusted_network_id
            )
        except ThreatHintV2ProofEnvelopeError:
            raise ThreatHintV2ProofBindingError() from None

        # Step 5: cross-check the exact protocol, relation, and trusted
        # network identities. Defense-in-depth: both parsers already pin
        # these exact values.
        if (
            envelope.protocol_id != manifest.protocol_id
            or envelope.relation_id != manifest.relation_id
            or manifest.network_id != trusted_network_id
            or envelope.parsed_statement.network_id != trusted_network_id
        ):
            raise ThreatHintV2ProofBindingError()

        # Step 6: recompute the statement digest from the manifest-declared
        # domain bytes over the parsed canonical statement wire.
        statement_digest_hex = _statement_digest_hex(manifest, envelope)
        if statement_digest_hex != envelope.statement_digest:
            raise ThreatHintV2ProofBindingError()

        # Step 7: assert the exact public-input encoding and count, then
        # derive the two claimed 16-byte big-endian unsigned halves.
        if (
            manifest.public_input_encoding != PUBLIC_INPUT_ENCODING
            or manifest.public_input_count != PUBLIC_INPUT_COUNT
        ):
            raise ThreatHintV2ProofBindingError()
        digest = bytes.fromhex(statement_digest_hex)
        first_half = digest[:16]
        second_half = digest[16:]

        binding = object.__new__(cls)
        object.__setattr__(binding, "envelope", envelope)
        object.__setattr__(binding, "manifest", manifest)
        _BINDING_SNAPSHOT[binding] = (
            envelope_wire,
            manifest_wire,
            trusted_network_id,
            raw_manifest_sha256_hex,
            statement_digest_hex,
            first_half,
            second_half,
        )
        binding._validate_state()
        return binding

    @property
    def raw_manifest_sha256_hex(self) -> str:
        """Return the snapshotted raw manifest byte SHA-256 anchor."""
        return self._snapshot()[3]

    @property
    def statement_digest_hex(self) -> str:
        """Return the snapshotted recomputed statement digest."""
        return self._snapshot()[4]

    @property
    def public_input_first_half(self) -> bytes:
        """Return the claimed first 16-byte big-endian public-input half."""
        return self._snapshot()[5]

    @property
    def public_input_second_half(self) -> bytes:
        """Return the claimed second 16-byte big-endian public-input half."""
        return self._snapshot()[6]

    def _snapshot(self) -> _BindingSnapshot:
        self._validate_state()
        snapshot = _BINDING_SNAPSHOT.get(self)
        if snapshot is None:
            raise ThreatHintV2ProofBindingError()
        return snapshot

    def _validate_state(self) -> None:
        """Revalidate identity, nested objects, and every derived value."""
        if type(self) is not ThreatHintV2ProofBinding:
            raise ThreatHintV2ProofBindingError()
        snapshot = _BINDING_SNAPSHOT.get(self)
        if snapshot is None:
            raise ThreatHintV2ProofBindingError()
        if type(self.envelope) is not ThreatHintV2ProofEnvelope:
            raise ThreatHintV2ProofBindingError()
        if type(self.manifest) is not RelationManifestV2:
            raise ThreatHintV2ProofBindingError()
        (
            envelope_wire_at_bind,
            manifest_wire_at_bind,
            trusted_network_id,
            raw_hex,
            digest_hex,
            first_half,
            second_half,
        ) = snapshot
        try:
            # The nested identity snapshots revalidate themselves on these reads.
            manifest_wire = self.manifest.canonical_bytes
            envelope_wire = self.envelope.canonical_bytes
            recomputed = _statement_digest_hex(self.manifest, self.envelope)
        except (
            RelationManifestV2Error,
            ThreatHintV2ProofEnvelopeError,
            TypeError,
            ValueError,
            OverflowError,
        ):
            raise ThreatHintV2ProofBindingError() from None
        if (
            manifest_wire != manifest_wire_at_bind
            or envelope_wire != envelope_wire_at_bind
        ):
            raise ThreatHintV2ProofBindingError()
        if hashlib.sha256(manifest_wire).hexdigest() != raw_hex:
            raise ThreatHintV2ProofBindingError()
        if (
            self.envelope.protocol_id != self.manifest.protocol_id
            or self.envelope.relation_id != self.manifest.relation_id
            or self.manifest.network_id != trusted_network_id
            or self.envelope.parsed_statement.network_id != trusted_network_id
        ):
            raise ThreatHintV2ProofBindingError()
        if recomputed != digest_hex or recomputed != self.envelope.statement_digest:
            raise ThreatHintV2ProofBindingError()
        digest = bytes.fromhex(recomputed)
        if digest[:16] != first_half or digest[16:] != second_half:
            raise ThreatHintV2ProofBindingError()
        if (
            self.manifest.public_input_encoding != PUBLIC_INPUT_ENCODING
            or self.manifest.public_input_count != PUBLIC_INPUT_COUNT
        ):
            raise ThreatHintV2ProofBindingError()


def _statement_digest_hex(
    manifest: RelationManifestV2, envelope: ThreatHintV2ProofEnvelope
) -> str:
    """Recompute SHA256(domain || u32be(len) || canonical statement wire)."""
    domain = bytes.fromhex(manifest.statement_digest_domain_hex)
    canonical_statement = envelope.parsed_statement.canonical_bytes
    hasher = hashlib.sha256()
    hasher.update(domain)
    hasher.update(len(canonical_statement).to_bytes(4, byteorder="big", signed=False))
    hasher.update(canonical_statement)
    return hasher.hexdigest()


def _validate_network_id(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) < 2
        or len(value) > 64
        or _NETWORK_RE.fullmatch(value) is None
    ):
        raise ThreatHintV2ProofBindingError()
    return value


def _validate_anchor(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or _LOWER_HEX_RE.fullmatch(value) is None
        or not any(character != "0" for character in value)
    ):
        raise ThreatHintV2ProofBindingError()
    return value


_LOWER_HEX_RE = re.compile(r"[0-9a-f]{64}")
_NETWORK_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}[a-z0-9]")
_BINDING_SNAPSHOT: weakref.WeakKeyDictionary[Any, _BindingSnapshot] = (
    weakref.WeakKeyDictionary()
)
