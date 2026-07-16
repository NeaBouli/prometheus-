"""Authenticated Guardian ballot envelopes and persistent replay protection.

The transport session binds an externally supplied committee to public BIP340
keys. This module verifies public signatures only. It does not hold signing
keys, discover peers, trust the membership source, or submit rules.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from collections.abc import Sequence
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Final

from coincurve import PublicKeyXOnly

from .ensemble import (
    EnsembleCandidate,
    EnsembleDecision,
    EnsembleVoter,
    GuardianVote,
    MembershipSnapshot,
    is_valid_candidate,
    is_valid_guardian_vote,
    is_valid_membership_snapshot,
)

SIGNED_BALLOT_PROTOCOL_VERSION: Final[int] = 1
MAX_BALLOT_WIRE_BYTES: Final[int] = 8_192
MAX_BALLOT_LIFETIME_MS: Final[int] = 120_000
MAX_SESSION_LIFETIME_MS: Final[int] = 900_000
MAX_CLOCK_SKEW_MS: Final[int] = 30_000

_SESSION_DOMAIN = b"PROMETHEUS_GUARDIAN_BALLOT_SESSION_V1"
_BALLOT_DOMAIN = b"PROMETHEUS_GUARDIAN_SIGNED_BALLOT_V1"
_LOWER_HEX_32 = re.compile(r"[0-9a-f]{64}")
_LOWER_HEX_64 = re.compile(r"[0-9a-f]{128}")
_NETWORK_ID = re.compile(r"(?:mainnet|testnet-[0-9]{1,3})")
_SQLITE_SCHEMA_VERSION = 1
_MAX_SQLITE_INT = (1 << 63) - 1


class BallotTransportError(ValueError):
    """Base exception for a rejected authenticated ballot."""


class BallotFormatError(BallotTransportError):
    """The wire envelope or configured session is not canonical."""


class BallotVerificationError(BallotTransportError):
    """The envelope is not valid for the configured ballot context."""


class BallotReplayError(BallotTransportError):
    """The session already consumed this Guardian or nonce."""


@dataclass(frozen=True)
class BallotSigner:
    """One Guardian-to-BIP340-key binding supplied by membership config."""

    guardian_id: str
    xonly_public_key: str


@dataclass(frozen=True)
class BallotSession:  # pylint: disable=too-many-instance-attributes
    """Committed per-candidate signing session for a complete committee."""

    protocol_version: int
    network_id: str
    membership_snapshot_id: str
    candidate_digest: str
    session_nonce: str
    valid_from_ms: int
    valid_until_ms: int
    signers: tuple[BallotSigner, ...]
    session_id: str

    @classmethod
    # Explicit inputs keep every session commitment visible to callers.
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def create(
        cls,
        candidate: EnsembleCandidate,
        snapshot: MembershipSnapshot,
        signers: Sequence[BallotSigner],
        network_id: str,
        session_nonce: str,
        valid_from_ms: int,
        valid_until_ms: int,
    ) -> "BallotSession":
        """Validate and commit a key-bound ballot session."""
        if not is_valid_candidate(candidate):
            raise BallotFormatError("candidate commitment is invalid")
        if not is_valid_membership_snapshot(snapshot):
            raise BallotFormatError("membership snapshot is invalid")
        canonical_signers = _validated_signers(signers, snapshot)
        _validate_session_window(valid_from_ms, valid_until_ms)
        if not _is_network_id(network_id):
            raise BallotFormatError("network id is not canonical")
        if not _is_hex_32(session_nonce):
            raise BallotFormatError("session nonce must be canonical 32-byte hex")

        payload = _session_payload(
            SIGNED_BALLOT_PROTOCOL_VERSION,
            network_id,
            snapshot.snapshot_id,
            candidate.candidate_digest,
            session_nonce,
            valid_from_ms,
            valid_until_ms,
            canonical_signers,
        )
        return cls(
            protocol_version=SIGNED_BALLOT_PROTOCOL_VERSION,
            network_id=network_id,
            membership_snapshot_id=snapshot.snapshot_id,
            candidate_digest=candidate.candidate_digest,
            session_nonce=session_nonce,
            valid_from_ms=valid_from_ms,
            valid_until_ms=valid_until_ms,
            signers=canonical_signers,
            session_id=_canonical_digest(_SESSION_DOMAIN, payload),
        )


@dataclass(frozen=True)
class BallotSigningRequest:  # pylint: disable=too-many-instance-attributes
    """Canonical public digest request for an external Guardian signer."""

    protocol_version: int
    vote_protocol_version: int
    session_id: str
    network_id: str
    guardian_id: str
    membership_snapshot_id: str
    candidate_digest: str
    decision: str
    confidence_bps: int
    model_tier: str
    model_artifact_sha256: str
    nonce: str
    issued_at_ms: int
    expires_at_ms: int
    payload_digest: str

    @classmethod
    # Explicit inputs keep every external-signing boundary visible to callers.
    # pylint: disable-next=too-many-arguments,too-many-positional-arguments
    def create(
        cls,
        vote: GuardianVote,
        candidate: EnsembleCandidate,
        snapshot: MembershipSnapshot,
        session: BallotSession,
        nonce: str,
        issued_at_ms: int,
        expires_at_ms: int,
    ) -> "BallotSigningRequest":
        """Create a digest-only request without accepting private material."""
        if not _is_valid_session(session, candidate, snapshot):
            raise BallotFormatError("ballot session is invalid")
        if not is_valid_guardian_vote(vote, candidate, snapshot):
            raise BallotFormatError("vote binding is invalid")
        if not _is_hex_32(nonce):
            raise BallotFormatError("ballot nonce must be canonical 32-byte hex")
        _validate_ballot_window(session, issued_at_ms, expires_at_ms)

        payload = _ballot_payload(
            SIGNED_BALLOT_PROTOCOL_VERSION,
            vote.protocol_version,
            session.session_id,
            session.network_id,
            vote.guardian_id,
            vote.membership_snapshot_id,
            vote.candidate_digest,
            vote.decision,
            vote.confidence_bps,
            vote.model_tier,
            vote.model_artifact_sha256,
            nonce,
            issued_at_ms,
            expires_at_ms,
        )
        return cls(
            protocol_version=SIGNED_BALLOT_PROTOCOL_VERSION,
            vote_protocol_version=vote.protocol_version,
            session_id=session.session_id,
            network_id=session.network_id,
            guardian_id=vote.guardian_id,
            membership_snapshot_id=vote.membership_snapshot_id,
            candidate_digest=vote.candidate_digest,
            decision=vote.decision,
            confidence_bps=vote.confidence_bps,
            model_tier=vote.model_tier,
            model_artifact_sha256=vote.model_artifact_sha256,
            nonce=nonce,
            issued_at_ms=issued_at_ms,
            expires_at_ms=expires_at_ms,
            payload_digest=_canonical_digest(_BALLOT_DOMAIN, payload),
        )

    def attach_signature(self, signature: str) -> "SignedGuardianBallot":
        """Attach one external public signature without signing locally."""
        if not _is_hex_64(signature):
            raise BallotFormatError("signature must be canonical 64-byte hex")
        return SignedGuardianBallot(**asdict(self), signature=signature)


@dataclass(frozen=True)
class SignedGuardianBallot:  # pylint: disable=too-many-instance-attributes
    """Strict canonical Guardian ballot wire envelope."""

    protocol_version: int
    vote_protocol_version: int
    session_id: str
    network_id: str
    guardian_id: str
    membership_snapshot_id: str
    candidate_digest: str
    decision: str
    confidence_bps: int
    model_tier: str
    model_artifact_sha256: str
    nonce: str
    issued_at_ms: int
    expires_at_ms: int
    payload_digest: str
    signature: str

    def to_wire(self) -> bytes:
        """Serialize the envelope as canonical JSON bytes."""
        return _canonical_json(asdict(self))

    @classmethod
    def from_wire(cls, wire: bytes) -> "SignedGuardianBallot":
        """Parse exact-schema canonical JSON under a hard size limit."""
        if not isinstance(wire, bytes) or not wire or len(wire) > MAX_BALLOT_WIRE_BYTES:
            raise BallotFormatError("ballot wire size is invalid")
        try:
            decoded = json.loads(wire.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, BallotFormatError) as exc:
            raise BallotFormatError("ballot wire is not strict JSON") from exc
        expected_fields = {field.name for field in fields(cls)}
        if not isinstance(decoded, dict) or set(decoded) != expected_fields:
            raise BallotFormatError("ballot wire schema is invalid")
        try:
            envelope = cls(**decoded)
        except TypeError as exc:
            raise BallotFormatError("ballot wire fields are invalid") from exc
        if envelope.to_wire() != wire:
            raise BallotFormatError("ballot wire must use canonical JSON encoding")
        return envelope

    def to_vote(self) -> GuardianVote:
        """Return the unsigned domain vote after envelope verification."""
        return GuardianVote(
            guardian_id=self.guardian_id,
            membership_snapshot_id=self.membership_snapshot_id,
            candidate_digest=self.candidate_digest,
            decision=self.decision,  # type: ignore[arg-type]
            confidence_bps=self.confidence_bps,
            model_tier=self.model_tier,  # type: ignore[arg-type]
            model_artifact_sha256=self.model_artifact_sha256,
            protocol_version=self.vote_protocol_version,
        )


class BallotVerifier:  # pylint: disable=too-few-public-methods
    """Verify one signed envelope against all cheap and cryptographic gates."""

    def verify(
        self,
        envelope: SignedGuardianBallot,
        candidate: EnsembleCandidate,
        snapshot: MembershipSnapshot,
        session: BallotSession,
        now_ms: int,
    ) -> GuardianVote:
        """Return a domain vote only after complete public verification."""
        if not _is_timestamp(now_ms):
            raise BallotVerificationError("verification time is invalid")
        if not _is_valid_session(session, candidate, snapshot):
            raise BallotVerificationError("ballot session is invalid")
        if not _is_valid_envelope_shape(envelope):
            raise BallotVerificationError("ballot envelope is invalid")
        if (
            envelope.session_id != session.session_id
            or envelope.network_id != session.network_id
            or envelope.membership_snapshot_id != snapshot.snapshot_id
            or envelope.candidate_digest != candidate.candidate_digest
        ):
            raise BallotVerificationError("ballot context binding mismatch")
        if not _is_fresh_envelope(envelope, session, now_ms):
            raise BallotVerificationError("ballot freshness policy failed")

        vote = envelope.to_vote()
        if not is_valid_guardian_vote(vote, candidate, snapshot):
            raise BallotVerificationError("ballot vote binding is invalid")
        signer = {item.guardian_id: item for item in session.signers}.get(
            envelope.guardian_id
        )
        if signer is None or not _verify_signature(signer, envelope):
            raise BallotVerificationError("ballot signature verification failed")
        return vote


class ReplayLedger:
    """Owner-only SQLite ledger with atomic replay and equivocation constraints."""

    def __init__(self, path: Path) -> None:
        self.path = _prepare_ledger_path(path)
        with self._connect() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, _SQLITE_SCHEMA_VERSION):
                raise BallotFormatError("unsupported replay ledger schema")
            connection.execute("""
                CREATE TABLE IF NOT EXISTS accepted_ballots (
                    session_id TEXT NOT NULL,
                    guardian_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    expires_at_ms INTEGER NOT NULL,
                    session_valid_until_ms INTEGER NOT NULL,
                    accepted_at_ms INTEGER NOT NULL,
                    wire BLOB NOT NULL,
                    PRIMARY KEY (session_id, guardian_id),
                    UNIQUE (session_id, nonce)
                ) STRICT
                """)
            connection.execute("""
                CREATE TABLE IF NOT EXISTS ledger_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    high_water_ms INTEGER NOT NULL
                ) STRICT
                """)
            connection.execute(
                "INSERT OR IGNORE INTO ledger_state (singleton, high_water_ms) "
                "VALUES (1, 0)"
            )
            connection.execute(f"PRAGMA user_version = {_SQLITE_SCHEMA_VERSION}")

    def consume(
        self,
        envelope: SignedGuardianBallot,
        session: BallotSession,
        wire: bytes,
        accepted_at_ms: int,
    ) -> None:
        """Atomically persist one verified Guardian ballot for a session."""
        if (
            not _is_timestamp(accepted_at_ms)
            or not _is_valid_session_shape(session)
            or envelope.session_id != session.session_id
            or envelope.to_wire() != wire
        ):
            raise BallotFormatError("replay ledger input is invalid")
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                self._advance_time(connection, accepted_at_ms)
                connection.execute(
                    """
                    INSERT INTO accepted_ballots (
                        session_id, guardian_id, nonce, expires_at_ms,
                        session_valid_until_ms, accepted_at_ms, wire
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        envelope.session_id,
                        envelope.guardian_id,
                        envelope.nonce,
                        envelope.expires_at_ms,
                        session.valid_until_ms,
                        accepted_at_ms,
                        wire,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise BallotReplayError("ballot already consumed for this session") from exc

    def session_wires(self, session_id: str) -> tuple[bytes, ...]:
        """Load persisted canonical envelopes in deterministic Guardian order."""
        if not _is_hex_32(session_id):
            raise BallotFormatError("session id is invalid")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT wire FROM accepted_ballots
                WHERE session_id = ? ORDER BY guardian_id
                """,
                (session_id,),
            ).fetchall()
        return tuple(bytes(row[0]) for row in rows)

    def prune_expired(self, now_ms: int) -> int:
        """Delete replay markers only after their complete session expires."""
        if not _is_timestamp(now_ms):
            raise BallotFormatError("prune time is invalid")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._advance_time(connection, now_ms)
            cursor = connection.execute(
                "DELETE FROM accepted_ballots WHERE session_valid_until_ms <= ?",
                (now_ms,),
            )
        return cursor.rowcount

    @staticmethod
    def _advance_time(connection: sqlite3.Connection, now_ms: int) -> None:
        """Persist monotonic ledger time so clock rollback cannot reopen a session."""
        row = connection.execute(
            "SELECT high_water_ms FROM ledger_state WHERE singleton = 1"
        ).fetchone()
        if row is None or not isinstance(row[0], int):
            raise BallotFormatError("replay ledger state is invalid")
        if now_ms < row[0]:
            raise BallotReplayError("replay ledger clock rollback detected")
        connection.execute(
            "UPDATE ledger_state SET high_water_ms = ? WHERE singleton = 1",
            (now_ms,),
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA trusted_schema = OFF")
        return connection


class AuthenticatedBallotCollector:
    """Persist verified ballots and feed only re-verified votes to the ensemble."""

    def __init__(self, ledger: ReplayLedger) -> None:
        self._ledger = ledger
        self._verifier = BallotVerifier()

    def accept_wire(
        self,
        wire: bytes,
        candidate: EnsembleCandidate,
        snapshot: MembershipSnapshot,
        session: BallotSession,
        now_ms: int,
    ) -> GuardianVote:
        """Verify before atomically consuming one wire envelope."""
        envelope = SignedGuardianBallot.from_wire(wire)
        vote = self._verifier.verify(envelope, candidate, snapshot, session, now_ms)
        self._ledger.consume(envelope, session, wire, now_ms)
        return vote

    def evaluate(
        self,
        candidate: EnsembleCandidate,
        snapshot: MembershipSnapshot,
        session: BallotSession,
        now_ms: int,
    ) -> EnsembleDecision:
        """Re-verify stored envelopes and run the existing complete-ballot gate."""
        votes: list[GuardianVote] = []
        if not _is_valid_session(session, candidate, snapshot):
            return EnsembleVoter().evaluate(candidate, snapshot, votes)
        try:
            for wire in self._ledger.session_wires(session.session_id):
                envelope = SignedGuardianBallot.from_wire(wire)
                votes.append(
                    self._verifier.verify(
                        envelope, candidate, snapshot, session, now_ms
                    )
                )
        except BallotTransportError:
            votes = []
        return EnsembleVoter().evaluate(candidate, snapshot, votes)


def _validated_signers(
    signers: Sequence[BallotSigner], snapshot: MembershipSnapshot
) -> tuple[BallotSigner, ...]:
    try:
        canonical = tuple(sorted(signers, key=lambda item: item.guardian_id))
    except (AttributeError, TypeError, ValueError) as exc:
        raise BallotFormatError("signers must be a finite sequence") from exc
    if not canonical or not all(_is_valid_signer(item) for item in canonical):
        raise BallotFormatError("ballot signer fields are invalid")
    guardian_ids = [item.guardian_id for item in canonical]
    public_keys = [item.xonly_public_key for item in canonical]
    if len(set(guardian_ids)) != len(guardian_ids) or len(set(public_keys)) != len(
        public_keys
    ):
        raise BallotFormatError("ballot signer identities and keys must be unique")
    if set(guardian_ids) != {member.guardian_id for member in snapshot.members}:
        raise BallotFormatError("ballot signer set must equal the committee")
    return canonical


def _is_valid_signer(signer: object) -> bool:
    if not (
        isinstance(signer, BallotSigner)
        and _is_hex_32(signer.guardian_id)
        and _is_hex_32(signer.xonly_public_key)
    ):
        return False
    try:
        PublicKeyXOnly(bytes.fromhex(signer.xonly_public_key))
    except ValueError:
        return False
    return True


def _is_valid_session(
    session: BallotSession,
    candidate: EnsembleCandidate,
    snapshot: MembershipSnapshot,
) -> bool:
    if not _is_valid_session_shape(session):
        return False
    if (
        session.membership_snapshot_id != snapshot.snapshot_id
        or session.candidate_digest != candidate.candidate_digest
        or not is_valid_candidate(candidate)
        or not is_valid_membership_snapshot(snapshot)
    ):
        return False
    try:
        return session.signers == _validated_signers(session.signers, snapshot)
    except BallotTransportError:
        return False


def _is_valid_session_shape(session: object) -> bool:
    if not isinstance(session, BallotSession):
        return False
    valid_fields = (
        _is_int(session.protocol_version)
        and session.protocol_version == SIGNED_BALLOT_PROTOCOL_VERSION
        and _is_network_id(session.network_id)
        and _is_hex_32(session.membership_snapshot_id)
        and _is_hex_32(session.candidate_digest)
        and _is_hex_32(session.session_nonce)
        and _is_timestamp(session.valid_from_ms)
        and _is_timestamp(session.valid_until_ms)
        and isinstance(session.signers, tuple)
        and bool(session.signers)
        and all(_is_valid_signer(signer) for signer in session.signers)
        and _is_hex_32(session.session_id)
    )
    if not valid_fields:
        return False
    try:
        _validate_session_window(session.valid_from_ms, session.valid_until_ms)
    except BallotTransportError:
        return False
    payload = _session_payload(
        session.protocol_version,
        session.network_id,
        session.membership_snapshot_id,
        session.candidate_digest,
        session.session_nonce,
        session.valid_from_ms,
        session.valid_until_ms,
        session.signers,
    )
    return session.session_id == _canonical_digest(_SESSION_DOMAIN, payload)


def _is_valid_envelope_shape(envelope: object) -> bool:
    if not isinstance(envelope, SignedGuardianBallot):
        return False
    valid_fields = (
        _is_int(envelope.protocol_version)
        and envelope.protocol_version == SIGNED_BALLOT_PROTOCOL_VERSION
        and _is_int(envelope.vote_protocol_version)
        and _is_hex_32(envelope.session_id)
        and _is_network_id(envelope.network_id)
        and _is_hex_32(envelope.guardian_id)
        and _is_hex_32(envelope.membership_snapshot_id)
        and _is_hex_32(envelope.candidate_digest)
        and isinstance(envelope.decision, str)
        and envelope.decision in ("approve", "reject")
        and _is_int(envelope.confidence_bps)
        and 0 <= envelope.confidence_bps <= 10_000
        and isinstance(envelope.model_tier, str)
        and envelope.model_tier == "8b"
        and _is_hex_32(envelope.model_artifact_sha256)
        and _is_hex_32(envelope.nonce)
        and _is_timestamp(envelope.issued_at_ms)
        and _is_timestamp(envelope.expires_at_ms)
        and _is_hex_32(envelope.payload_digest)
        and _is_hex_64(envelope.signature)
    )
    if not valid_fields:
        return False
    payload = _ballot_payload(
        envelope.protocol_version,
        envelope.vote_protocol_version,
        envelope.session_id,
        envelope.network_id,
        envelope.guardian_id,
        envelope.membership_snapshot_id,
        envelope.candidate_digest,
        envelope.decision,
        envelope.confidence_bps,
        envelope.model_tier,
        envelope.model_artifact_sha256,
        envelope.nonce,
        envelope.issued_at_ms,
        envelope.expires_at_ms,
    )
    return envelope.payload_digest == _canonical_digest(_BALLOT_DOMAIN, payload)


def _is_fresh_envelope(
    envelope: SignedGuardianBallot, session: BallotSession, now_ms: int
) -> bool:
    return (
        session.valid_from_ms <= envelope.issued_at_ms
        and envelope.expires_at_ms <= session.valid_until_ms
        and envelope.issued_at_ms <= now_ms + MAX_CLOCK_SKEW_MS
        and now_ms < envelope.expires_at_ms
        and 0 < envelope.expires_at_ms - envelope.issued_at_ms <= MAX_BALLOT_LIFETIME_MS
    )


def _verify_signature(signer: BallotSigner, envelope: SignedGuardianBallot) -> bool:
    try:
        return PublicKeyXOnly(bytes.fromhex(signer.xonly_public_key)).verify(
            bytes.fromhex(envelope.signature),
            bytes.fromhex(envelope.payload_digest),
        )
    except ValueError:
        return False


def _validate_session_window(valid_from_ms: int, valid_until_ms: int) -> None:
    if not _is_timestamp(valid_from_ms) or not _is_timestamp(valid_until_ms):
        raise BallotFormatError("session timestamps are invalid")
    if not 0 < valid_until_ms - valid_from_ms <= MAX_SESSION_LIFETIME_MS:
        raise BallotFormatError("session lifetime is invalid")


def _validate_ballot_window(
    session: BallotSession, issued_at_ms: int, expires_at_ms: int
) -> None:
    if not _is_timestamp(issued_at_ms) or not _is_timestamp(expires_at_ms):
        raise BallotFormatError("ballot timestamps are invalid")
    if (
        issued_at_ms < session.valid_from_ms
        or expires_at_ms > session.valid_until_ms
        or not 0 < expires_at_ms - issued_at_ms <= MAX_BALLOT_LIFETIME_MS
    ):
        raise BallotFormatError("ballot lifetime is invalid")


def _prepare_ledger_path(path: Path) -> Path:
    if not isinstance(path, Path) or not path.name:
        raise BallotFormatError("replay ledger path is invalid")
    try:
        parent = path.parent.resolve(strict=True)
        parent_stat = parent.stat()
    except (FileNotFoundError, OSError) as exc:
        raise BallotFormatError("replay ledger parent is unavailable") from exc
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or parent_stat.st_uid != os.getuid()
        or parent_stat.st_mode & 0o022
    ):
        raise BallotFormatError("replay ledger parent must be owner-controlled")
    canonical = parent / path.name
    try:
        file_stat = canonical.lstat()
    except FileNotFoundError:
        flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(canonical, flags, 0o600)
        except OSError as exc:
            raise BallotFormatError("failed to create replay ledger") from exc
        os.close(descriptor)
        file_stat = canonical.lstat()
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_uid != os.getuid()
        or stat.S_IMODE(file_stat.st_mode) != 0o600
    ):
        raise BallotFormatError("replay ledger must be an owner-only regular file")
    return canonical


# Explicit arguments keep every session field visible at the hash boundary.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def _session_payload(
    protocol_version: int,
    network_id: str,
    membership_snapshot_id: str,
    candidate_digest: str,
    session_nonce: str,
    valid_from_ms: int,
    valid_until_ms: int,
    signers: tuple[BallotSigner, ...],
) -> dict[str, object]:
    return {
        "candidate_digest": candidate_digest,
        "membership_snapshot_id": membership_snapshot_id,
        "network_id": network_id,
        "protocol_version": protocol_version,
        "session_nonce": session_nonce,
        "signers": [asdict(signer) for signer in signers],
        "valid_from_ms": valid_from_ms,
        "valid_until_ms": valid_until_ms,
    }


# Explicit arguments keep every signed field visible at the hash boundary.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def _ballot_payload(
    protocol_version: int,
    vote_protocol_version: int,
    session_id: str,
    network_id: str,
    guardian_id: str,
    membership_snapshot_id: str,
    candidate_digest: str,
    decision: str,
    confidence_bps: int,
    model_tier: str,
    model_artifact_sha256: str,
    nonce: str,
    issued_at_ms: int,
    expires_at_ms: int,
) -> dict[str, object]:
    return {
        "candidate_digest": candidate_digest,
        "confidence_bps": confidence_bps,
        "decision": decision,
        "expires_at_ms": expires_at_ms,
        "guardian_id": guardian_id,
        "issued_at_ms": issued_at_ms,
        "membership_snapshot_id": membership_snapshot_id,
        "model_artifact_sha256": model_artifact_sha256,
        "model_tier": model_tier,
        "network_id": network_id,
        "nonce": nonce,
        "protocol_version": protocol_version,
        "session_id": session_id,
        "vote_protocol_version": vote_protocol_version,
    }


def _canonical_digest(domain: bytes, payload: dict[str, object]) -> str:
    return hashlib.sha256(domain + b"\x00" + _canonical_json(payload)).hexdigest()


def _canonical_json(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise BallotFormatError("duplicate JSON field")
        result[key] = value
    return result


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_timestamp(value: object) -> bool:
    return _is_int(value) and 0 <= value <= _MAX_SQLITE_INT


def _is_network_id(value: object) -> bool:
    return isinstance(value, str) and _NETWORK_ID.fullmatch(value) is not None


def _is_hex_32(value: object) -> bool:
    return isinstance(value, str) and _LOWER_HEX_32.fullmatch(value) is not None


def _is_hex_64(value: object) -> bool:
    return isinstance(value, str) and _LOWER_HEX_64.fullmatch(value) is not None
