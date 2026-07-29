"""Local-only canonical RelationManifest-v2 parsing and byte-anchor binding.

The manifest binds only closed protocol/relation/proof-system identities,
relation-source and key artifact hashes/sizes, public-input encoding/count,
the network, and the pinned KIP-16/Kaspa/Arkworks versions. Source and key
hashes are byte anchors only: this parser performs no file I/O, key loading,
pairing proof, ceremony validation, proof generation or verification,
approval, or any other operational action. Proving-key metadata is mandatory
but inert. The raw SHA-256 of the canonical manifest bytes is the external
trust anchor.

``public_input_encoding`` is ``sha256_split_u128_bn254_v2``: the 32-byte
statement digest is split into two 16-byte halves, each interpreted as a
big-endian unsigned 128-bit integer. Every such integer is below the BN254
scalar-field modulus (which is greater than 2^128), so each half embeds into
a BN254 Fr element without reduction and the encoding is injective over the
two halves.
"""

# Exact built-in types and a fixed nineteen-field wire are protocol requirements.
# pylint: disable=too-many-instance-attributes,too-many-locals,unidiomatic-typecheck

from __future__ import annotations

import json
import re
import weakref
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Mapping

MAX_CANONICAL_V2_MANIFEST_BYTES = 4096
SCHEMA_VERSION = 2
PROTOCOL_ID = "/prometheus/threat-hint/2.0.0"
RELATION_ID = "prometheus-threat-hint-v2"
STATEMENT_DIGEST_DOMAIN_HEX = (
    "70726f6d6574686575732d7468726561742d68696e742d73746174656d656e742d763200"
)
PROOF_SYSTEM = "groth16_bn254_kip16"
KIP16_TAG = 32
PUBLIC_INPUT_ENCODING = "sha256_split_u128_bn254_v2"
PUBLIC_INPUT_COUNT = 2
MAX_RELATION_SOURCE_BYTES = 1_048_576
MAX_PROVING_KEY_BYTES = 1_073_741_824
MAX_VERIFYING_KEY_BYTES = 65_536
KIP16_STATUS_COMMIT = "e4ae2332117b5cb68bd6188e065ef885b6d17939"
RUSTY_KASPA_TAG = "v2.0.1"
RUSTY_KASPA_COMMIT = "cfafeb4c093fa37a303f1b9f19c58f986b870ce3"
ARKWORKS_VERSION = "0.6.0"
U64_MAX = (1 << 64) - 1


class RelationManifestV2Error(ValueError):
    """Redacted local parser/validator failure."""

    def __init__(self) -> None:
        super().__init__("invalid relation manifest v2")


@dataclass(frozen=True, init=False, repr=False, eq=False)
class RelationManifestV2:
    """Canonical local RelationManifest-v2 with no operational authority."""

    schema_version: int
    protocol_id: str
    relation_id: str
    statement_digest_domain_hex: str
    proof_system: str
    kip16_tag: int
    public_input_encoding: str
    public_input_count: int
    network_id: str
    relation_source_bytes: int
    relation_source_sha256: str
    proving_key_bytes: int
    proving_key_sha256: str
    verifying_key_bytes: int
    verifying_key_sha256: str
    kip16_status_commit: str
    rusty_kaspa_tag: str
    rusty_kaspa_commit: str
    arkworks_version: str

    def __init__(self) -> None:
        """Reject direct construction outside canonical parsing."""
        raise TypeError("direct relation manifest v2 construction is disabled")

    @classmethod
    def parse_canonical(
        cls, wire_bytes: bytes, trusted_network_id: str
    ) -> "RelationManifestV2":
        """Parse exact bytes against a separately trusted local network."""
        if cls is not RelationManifestV2 or type(wire_bytes) is not bytes:
            raise RelationManifestV2Error()
        if len(wire_bytes) == 0 or len(wire_bytes) > MAX_CANONICAL_V2_MANIFEST_BYTES:
            raise RelationManifestV2Error()
        _validate_network_id(trusted_network_id)

        try:
            decoded = json.loads(
                wire_bytes.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
            )
        except (UnicodeDecodeError, ValueError):
            raise RelationManifestV2Error() from None

        manifest = cls._parse_object(decoded)
        if manifest.network_id != trusted_network_id:
            raise RelationManifestV2Error()
        _PARSED_CANONICAL[manifest] = wire_bytes
        if manifest.canonical_bytes != wire_bytes:
            raise RelationManifestV2Error()
        return manifest

    @classmethod
    def _parse_object(cls, value: Mapping[str, Any]) -> "RelationManifestV2":
        """Validate one decoded exact-shape manifest object."""
        if type(value) is not dict or list(value.keys()) != [
            "schema_version",
            "protocol_id",
            "relation_id",
            "statement_digest_domain_hex",
            "proof_system",
            "kip16_tag",
            "public_input_encoding",
            "public_input_count",
            "network_id",
            "relation_source_bytes",
            "relation_source_sha256",
            "proving_key_bytes",
            "proving_key_sha256",
            "verifying_key_bytes",
            "verifying_key_sha256",
            "kip16_status_commit",
            "rusty_kaspa_tag",
            "rusty_kaspa_commit",
            "arkworks_version",
        ]:
            raise RelationManifestV2Error()

        schema_version = _exact_int(value["schema_version"])
        kip16_tag = _exact_int(value["kip16_tag"])
        public_input_count = _exact_int(value["public_input_count"])
        relation_source_bytes = _bounded_int(value["relation_source_bytes"], 1)
        proving_key_bytes = _bounded_int(value["proving_key_bytes"], 1)
        verifying_key_bytes = _bounded_int(value["verifying_key_bytes"], 1)
        if (
            schema_version != SCHEMA_VERSION
            or kip16_tag != KIP16_TAG
            or public_input_count != PUBLIC_INPUT_COUNT
        ):
            raise RelationManifestV2Error()
        if (
            relation_source_bytes > MAX_RELATION_SOURCE_BYTES
            or proving_key_bytes > MAX_PROVING_KEY_BYTES
            or verifying_key_bytes > MAX_VERIFYING_KEY_BYTES
        ):
            raise RelationManifestV2Error()

        protocol_id = _exact_string(value["protocol_id"], PROTOCOL_ID)
        relation_id = _exact_string(value["relation_id"], RELATION_ID)
        statement_digest_domain_hex = _exact_string(
            value["statement_digest_domain_hex"], STATEMENT_DIGEST_DOMAIN_HEX
        )
        proof_system = _exact_string(value["proof_system"], PROOF_SYSTEM)
        public_input_encoding = _exact_string(
            value["public_input_encoding"], PUBLIC_INPUT_ENCODING
        )
        relation_source_sha256 = _lower_hex_anchor(value["relation_source_sha256"])
        proving_key_sha256 = _lower_hex_anchor(value["proving_key_sha256"])
        verifying_key_sha256 = _lower_hex_anchor(value["verifying_key_sha256"])
        kip16_status_commit = _exact_string(
            value["kip16_status_commit"], KIP16_STATUS_COMMIT
        )
        rusty_kaspa_tag = _exact_string(value["rusty_kaspa_tag"], RUSTY_KASPA_TAG)
        rusty_kaspa_commit = _exact_string(
            value["rusty_kaspa_commit"], RUSTY_KASPA_COMMIT
        )
        arkworks_version = _exact_string(value["arkworks_version"], ARKWORKS_VERSION)
        network_id = _validate_network_id(value["network_id"])

        manifest = object.__new__(cls)
        object.__setattr__(manifest, "schema_version", schema_version)
        object.__setattr__(manifest, "protocol_id", protocol_id)
        object.__setattr__(manifest, "relation_id", relation_id)
        object.__setattr__(
            manifest, "statement_digest_domain_hex", statement_digest_domain_hex
        )
        object.__setattr__(manifest, "proof_system", proof_system)
        object.__setattr__(manifest, "kip16_tag", kip16_tag)
        object.__setattr__(manifest, "public_input_encoding", public_input_encoding)
        object.__setattr__(manifest, "public_input_count", public_input_count)
        object.__setattr__(manifest, "network_id", network_id)
        object.__setattr__(manifest, "relation_source_bytes", relation_source_bytes)
        object.__setattr__(manifest, "relation_source_sha256", relation_source_sha256)
        object.__setattr__(manifest, "proving_key_bytes", proving_key_bytes)
        object.__setattr__(manifest, "proving_key_sha256", proving_key_sha256)
        object.__setattr__(manifest, "verifying_key_bytes", verifying_key_bytes)
        object.__setattr__(manifest, "verifying_key_sha256", verifying_key_sha256)
        object.__setattr__(manifest, "kip16_status_commit", kip16_status_commit)
        object.__setattr__(manifest, "rusty_kaspa_tag", rusty_kaspa_tag)
        object.__setattr__(manifest, "rusty_kaspa_commit", rusty_kaspa_commit)
        object.__setattr__(manifest, "arkworks_version", arkworks_version)
        return manifest

    @property
    def canonical_bytes(self) -> bytes:
        """Return the revalidated exact canonical JSON bytes."""
        canonical_at_parse = _PARSED_CANONICAL.get(self)
        if canonical_at_parse is None:
            raise RelationManifestV2Error()
        self._validate_state()
        payload = {
            "schema_version": self.schema_version,
            "protocol_id": self.protocol_id,
            "relation_id": self.relation_id,
            "statement_digest_domain_hex": self.statement_digest_domain_hex,
            "proof_system": self.proof_system,
            "kip16_tag": self.kip16_tag,
            "public_input_encoding": self.public_input_encoding,
            "public_input_count": self.public_input_count,
            "network_id": self.network_id,
            "relation_source_bytes": self.relation_source_bytes,
            "relation_source_sha256": self.relation_source_sha256,
            "proving_key_bytes": self.proving_key_bytes,
            "proving_key_sha256": self.proving_key_sha256,
            "verifying_key_bytes": self.verifying_key_bytes,
            "verifying_key_sha256": self.verifying_key_sha256,
            "kip16_status_commit": self.kip16_status_commit,
            "rusty_kaspa_tag": self.rusty_kaspa_tag,
            "rusty_kaspa_commit": self.rusty_kaspa_commit,
            "arkworks_version": self.arkworks_version,
        }
        canonical = json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if len(canonical) == 0 or len(canonical) > MAX_CANONICAL_V2_MANIFEST_BYTES:
            raise RelationManifestV2Error()
        if canonical != canonical_at_parse:
            raise RelationManifestV2Error()
        return canonical

    def _validate_state(self) -> None:
        """Revalidate private state before serialization."""
        if type(self) is not RelationManifestV2:
            raise RelationManifestV2Error()
        if (
            type(self.schema_version) is not int
            or self.schema_version != SCHEMA_VERSION
        ):
            raise RelationManifestV2Error()
        if type(self.kip16_tag) is not int or self.kip16_tag != KIP16_TAG:
            raise RelationManifestV2Error()
        if (
            type(self.public_input_count) is not int
            or self.public_input_count != PUBLIC_INPUT_COUNT
        ):
            raise RelationManifestV2Error()
        _bounded_int(self.relation_source_bytes, 1)
        _bounded_int(self.proving_key_bytes, 1)
        _bounded_int(self.verifying_key_bytes, 1)
        if (
            self.relation_source_bytes > MAX_RELATION_SOURCE_BYTES
            or self.proving_key_bytes > MAX_PROVING_KEY_BYTES
            or self.verifying_key_bytes > MAX_VERIFYING_KEY_BYTES
        ):
            raise RelationManifestV2Error()
        _exact_string(self.protocol_id, PROTOCOL_ID)
        _exact_string(self.relation_id, RELATION_ID)
        _exact_string(self.statement_digest_domain_hex, STATEMENT_DIGEST_DOMAIN_HEX)
        _exact_string(self.proof_system, PROOF_SYSTEM)
        _exact_string(self.public_input_encoding, PUBLIC_INPUT_ENCODING)
        _lower_hex_anchor(self.relation_source_sha256)
        _lower_hex_anchor(self.proving_key_sha256)
        _lower_hex_anchor(self.verifying_key_sha256)
        _exact_string(self.kip16_status_commit, KIP16_STATUS_COMMIT)
        _exact_string(self.rusty_kaspa_tag, RUSTY_KASPA_TAG)
        _exact_string(self.rusty_kaspa_commit, RUSTY_KASPA_COMMIT)
        _exact_string(self.arkworks_version, ARKWORKS_VERSION)
        _validate_network_id(self.network_id)


def _reject_duplicate_keys(items: Iterable[tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise RelationManifestV2Error()
        result[key] = value
    return result


def _exact_int(value: Any) -> int:
    if type(value) is not int or value < 0 or value > U64_MAX:
        raise RelationManifestV2Error()
    return value


def _bounded_int(value: Any, minimum: int) -> int:
    result = _exact_int(value)
    if result < minimum:
        raise RelationManifestV2Error()
    return result


def _exact_string(value: Any, expected: str) -> str:
    if type(value) is not str or value != expected:
        raise RelationManifestV2Error()
    return value


def _lower_hex_anchor(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or _LOWER_HEX_RE.fullmatch(value) is None
        or not any(character != "0" for character in value)
    ):
        raise RelationManifestV2Error()
    return value


def _validate_network_id(value: Any) -> str:
    if (
        type(value) is not str
        or len(value) < 2
        or len(value) > 64
        or _NETWORK_RE.fullmatch(value) is None
    ):
        raise RelationManifestV2Error()
    return value


_LOWER_HEX_RE = re.compile(r"[0-9a-f]{64}")
_NETWORK_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}[a-z0-9]")
_PARSED_CANONICAL: weakref.WeakKeyDictionary[Any, bytes] = weakref.WeakKeyDictionary()
