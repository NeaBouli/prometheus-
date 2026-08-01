"""Security tests for authenticated Guardian ballot intake."""

from __future__ import annotations

import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from coincurve import PrivateKey, PublicKeyXOnly

from jaeger.ensemble import (
    EnsembleCandidate,
    GuardianMember,
    GuardianVote,
    MembershipSnapshot,
)
from jaeger.signed_ballots import (
    MAX_BALLOT_LIFETIME_MS,
    MAX_BALLOT_WIRE_BYTES,
    MAX_CLOCK_SKEW_MS,
    AuthenticatedBallotCollector,
    BallotFormatError,
    BallotReplayError,
    BallotSession,
    BallotSigner,
    BallotSigningRequest,
    BallotVerificationError,
    ReplayLedger,
    SignedGuardianBallot,
)
from jaeger.yara_generator import YaraRule

MODEL_HASH = "1" * 64
POLICY_HASH = "2" * 64
MEMBERSHIP_SOURCE_HASH = "3" * 64
THREAT_HASH = "a" * 64
NOW_MS = 1_700_000_000_000


@dataclass(frozen=True)
class BallotContext:
    """Complete deterministic public context with ephemeral test signers."""

    candidate: EnsembleCandidate
    snapshot: MembershipSnapshot
    session: BallotSession
    private_keys: tuple[PrivateKey, ...]


def guardian_id(index: int) -> str:
    """Return one canonical public test identity."""
    return f"{index:064x}"


def make_rule() -> YaraRule:
    """Build one deterministic candidate rule."""
    return YaraRule(
        name="PROM_SIGNED_BALLOT",
        rule_content=(
            'rule PROM_SIGNED_BALLOT { strings: $a = "signed" condition: $a }'
        ),
        confidence_bps=9_500,
        threat_hash=THREAT_HASH,
        generated_at=1_700_000_000,
    )


def make_context(count: int = 5) -> BallotContext:
    """Build a valid committee and one key-bound candidate session."""
    private_keys = tuple(PrivateKey() for _ in range(count))
    members = [
        GuardianMember(
            guardian_id=guardian_id(index),
            model_tier="8b",
            model_artifact_sha256=MODEL_HASH,
        )
        for index in range(1, count + 1)
    ]
    candidate = EnsembleCandidate.create(make_rule(), POLICY_HASH, MODEL_HASH)
    snapshot = MembershipSnapshot.create(members, MEMBERSHIP_SOURCE_HASH)
    signers = [
        BallotSigner(
            guardian_id=member.guardian_id,
            xonly_public_key=PublicKeyXOnly.from_secret(private.secret).format().hex(),
        )
        for member, private in zip(snapshot.members, private_keys, strict=True)
    ]
    session = BallotSession.create(
        candidate,
        snapshot,
        signers,
        network_id="testnet-10",
        session_nonce="4" * 64,
        valid_from_ms=NOW_MS - 1_000,
        valid_until_ms=NOW_MS + 600_000,
    )
    return BallotContext(candidate, snapshot, session, private_keys)


def make_vote(
    context: BallotContext,
    index: int,
    decision: str = "approve",
    confidence_bps: int = 9_000,
) -> GuardianVote:
    """Build one domain vote bound to the selected committee member."""
    member = context.snapshot.members[index]
    return GuardianVote(
        guardian_id=member.guardian_id,
        membership_snapshot_id=context.snapshot.snapshot_id,
        candidate_digest=context.candidate.candidate_digest,
        decision=decision,  # type: ignore[arg-type]
        confidence_bps=confidence_bps,
        model_tier="8b",
        model_artifact_sha256=MODEL_HASH,
    )


def sign_vote(
    context: BallotContext,
    index: int,
    *,
    decision: str = "approve",
    confidence_bps: int = 9_000,
    nonce: str | None = None,
    issued_at_ms: int = NOW_MS,
    expires_at_ms: int = NOW_MS + 60_000,
    signing_key: PrivateKey | None = None,
) -> SignedGuardianBallot:
    """Sign one request with an ephemeral test-only key."""
    vote = make_vote(context, index, decision, confidence_bps)
    request = BallotSigningRequest.create(
        vote,
        context.candidate,
        context.snapshot,
        context.session,
        nonce or f"{index + 10:064x}",
        issued_at_ms,
        expires_at_ms,
    )
    private = signing_key or context.private_keys[index]
    signature = private.sign_schnorr(bytes.fromhex(request.payload_digest)).hex()
    return request.attach_signature(signature)


def make_collector(tmp_path: Path) -> tuple[AuthenticatedBallotCollector, Path]:
    """Create an owner-controlled persistent replay ledger."""
    state_dir = tmp_path / "state"
    state_dir.mkdir(mode=0o700)
    ledger_path = state_dir / "ballots.sqlite3"
    return AuthenticatedBallotCollector(ReplayLedger(ledger_path)), ledger_path


def accept(
    collector: AuthenticatedBallotCollector,
    context: BallotContext,
    envelope: SignedGuardianBallot,
    now_ms: int = NOW_MS,
) -> GuardianVote:
    """Submit one envelope through every verification and replay gate."""
    return collector.accept_wire(
        envelope.to_wire(),
        context.candidate,
        context.snapshot,
        context.session,
        now_ms,
    )


def test_complete_authenticated_ballot_reaches_existing_ensemble_gate(
    tmp_path: Path,
) -> None:
    """Five persisted signatures produce the same strict 3:2 decision."""
    context = make_context()
    collector, _ = make_collector(tmp_path)
    decisions = ["approve", "reject", "approve", "reject", "approve"]
    confidences = [9_500, 8_000, 8_500, 7_000, 9_000]

    for index, (decision, confidence) in enumerate(
        zip(decisions, confidences, strict=True)
    ):
        accepted = accept(
            collector,
            context,
            sign_vote(
                context,
                index,
                decision=decision,
                confidence_bps=confidence,
            ),
        )
        assert accepted.guardian_id == context.snapshot.members[index].guardian_id

    result = collector.evaluate(
        context.candidate, context.snapshot, context.session, NOW_MS
    )
    assert result.approved is True
    assert result.approvals == 3
    assert result.rejections == 2
    assert result.aggregate_confidence_bps == 8_500


def test_partial_authenticated_ballot_fails_closed(tmp_path: Path) -> None:
    """Authenticated transport does not weaken complete-ballot policy."""
    context = make_context()
    collector, _ = make_collector(tmp_path)
    accept(collector, context, sign_vote(context, 0))

    result = collector.evaluate(
        context.candidate, context.snapshot, context.session, NOW_MS
    )
    assert result.approved is False
    assert result.analysis.should_submit is False
    assert result.analysis.yara_rule is None


def test_wrong_key_and_tampered_payload_fail_before_persistence(
    tmp_path: Path,
) -> None:
    """A foreign signer or any signed-field mutation is rejected."""
    context = make_context()
    collector, ledger_path = make_collector(tmp_path)
    wrong_key = sign_vote(context, 0, signing_key=PrivateKey())
    tampered = replace(sign_vote(context, 1), confidence_bps=9_001)

    with pytest.raises(BallotVerificationError, match="signature"):
        accept(collector, context, wrong_key)
    with pytest.raises(BallotVerificationError, match="envelope"):
        accept(collector, context, tampered)

    assert ReplayLedger(ledger_path).session_wires(context.session.session_id) == ()


@pytest.mark.parametrize(
    "field,value",
    [
        ("network_id", "mainnet"),
        ("session_id", "f" * 64),
        ("membership_snapshot_id", "e" * 64),
        ("candidate_digest", "d" * 64),
        ("model_artifact_sha256", "c" * 64),
    ],
)
def test_cross_context_bindings_fail_closed(
    tmp_path: Path, field: str, value: str
) -> None:
    """Signed ballots cannot cross a network, session, candidate, or model."""
    context = make_context()
    collector, _ = make_collector(tmp_path)
    envelope = replace(sign_vote(context, 0), **{field: value})

    with pytest.raises(BallotVerificationError):
        accept(collector, context, envelope)


def test_exact_wire_schema_rejects_unknown_duplicate_and_noncanonical_json() -> None:
    """The parser rejects alternate encodings before signature work."""
    context = make_context()
    wire = sign_vote(context, 0).to_wire()
    decoded = json.loads(wire)
    decoded["unknown"] = "field"
    unknown = json.dumps(decoded, sort_keys=True, separators=(",", ":")).encode()
    duplicate = wire.replace(
        b'"candidate_digest":',
        b'"candidate_digest":"0","candidate_digest":',
        1,
    )

    with pytest.raises(BallotFormatError, match="schema"):
        SignedGuardianBallot.from_wire(unknown)
    with pytest.raises(BallotFormatError, match="strict JSON"):
        SignedGuardianBallot.from_wire(duplicate)
    with pytest.raises(BallotFormatError, match="canonical"):
        SignedGuardianBallot.from_wire(b" " + wire)
    with pytest.raises(BallotFormatError, match="size"):
        SignedGuardianBallot.from_wire(b"x" * (MAX_BALLOT_WIRE_BYTES + 1))


def test_bool_integer_fields_are_rejected(tmp_path: Path) -> None:
    """Python bool values cannot pass integer protocol fields."""
    context = make_context()
    collector, _ = make_collector(tmp_path)
    envelope = replace(sign_vote(context, 0), confidence_bps=True)

    with pytest.raises(BallotVerificationError, match="envelope"):
        accept(collector, context, envelope)


def test_replay_is_rejected_after_process_restart(tmp_path: Path) -> None:
    """The same envelope remains consumed in a newly opened collector."""
    context = make_context()
    collector, ledger_path = make_collector(tmp_path)
    envelope = sign_vote(context, 0)
    accept(collector, context, envelope)

    restarted = AuthenticatedBallotCollector(ReplayLedger(ledger_path))
    with pytest.raises(BallotReplayError, match="already consumed"):
        accept(restarted, context, envelope)


def test_equivocation_and_cross_guardian_nonce_reuse_are_rejected(
    tmp_path: Path,
) -> None:
    """One Guardian vote and one nonce are accepted at most once per session."""
    context = make_context()
    collector, _ = make_collector(tmp_path)
    accept(collector, context, sign_vote(context, 0, nonce="a" * 64))

    with pytest.raises(BallotReplayError):
        accept(collector, context, sign_vote(context, 0, nonce="b" * 64))
    with pytest.raises(BallotReplayError):
        accept(collector, context, sign_vote(context, 1, nonce="a" * 64))


def test_concurrent_duplicate_has_exactly_one_winner(tmp_path: Path) -> None:
    """SQLite uniqueness remains atomic across separate collectors."""
    context = make_context()
    _, ledger_path = make_collector(tmp_path)
    envelope = sign_vote(context, 0)
    collectors = [
        AuthenticatedBallotCollector(ReplayLedger(ledger_path)) for _ in range(2)
    ]

    def submit(collector: AuthenticatedBallotCollector) -> bool:
        try:
            accept(collector, context, envelope)
            return True
        except BallotReplayError:
            return False

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(submit, collectors))
    assert sorted(results) == [False, True]


def test_expired_future_and_overlong_ballots_fail_closed(tmp_path: Path) -> None:
    """Freshness policy rejects stale, future, and excessive lifetimes."""
    context = make_context()
    collector, _ = make_collector(tmp_path)
    expired = sign_vote(
        context,
        0,
        issued_at_ms=NOW_MS - 500,
        expires_at_ms=NOW_MS,
    )
    future = sign_vote(
        context,
        1,
        issued_at_ms=NOW_MS + MAX_CLOCK_SKEW_MS + 1,
        expires_at_ms=NOW_MS + MAX_CLOCK_SKEW_MS + 60_000,
    )

    with pytest.raises(BallotVerificationError, match="freshness"):
        accept(collector, context, expired)
    with pytest.raises(BallotVerificationError, match="freshness"):
        accept(collector, context, future)
    with pytest.raises(BallotFormatError, match="lifetime"):
        BallotSigningRequest.create(
            make_vote(context, 2),
            context.candidate,
            context.snapshot,
            context.session,
            "f" * 64,
            NOW_MS,
            NOW_MS + MAX_BALLOT_LIFETIME_MS + 1,
        )


def test_session_requires_exact_unique_guardian_key_set() -> None:
    """Missing identities, duplicate keys, and invalid curve points fail."""
    context = make_context()
    signers = list(context.session.signers)

    with pytest.raises(BallotFormatError, match="equal the committee"):
        BallotSession.create(
            context.candidate,
            context.snapshot,
            signers[:-1],
            "testnet-10",
            "5" * 64,
            NOW_MS,
            NOW_MS + 60_000,
        )
    with pytest.raises(BallotFormatError, match="unique"):
        BallotSession.create(
            context.candidate,
            context.snapshot,
            [replace(signers[0], guardian_id=item.guardian_id) for item in signers],
            "testnet-10",
            "5" * 64,
            NOW_MS,
            NOW_MS + 60_000,
        )
    invalid = [replace(signers[0], xonly_public_key="0" * 64), *signers[1:]]
    with pytest.raises(BallotFormatError, match="fields"):
        BallotSession.create(
            context.candidate,
            context.snapshot,
            invalid,
            "testnet-10",
            "5" * 64,
            NOW_MS,
            NOW_MS + 60_000,
        )


def test_signing_request_rejects_invalid_domain_vote() -> None:
    """External signers are never asked to sign a malformed domain vote."""
    context = make_context()
    invalid_vote = replace(make_vote(context, 0), candidate_digest="f" * 64)

    with pytest.raises(BallotFormatError, match="vote binding"):
        BallotSigningRequest.create(
            invalid_vote,
            context.candidate,
            context.snapshot,
            context.session,
            "9" * 64,
            NOW_MS,
            NOW_MS + 60_000,
        )


def test_ledger_requires_owner_only_regular_file_and_parent(tmp_path: Path) -> None:
    """Unsafe state paths are rejected before SQLite opens them."""
    unsafe_parent = tmp_path / "unsafe"
    unsafe_parent.mkdir(mode=0o777)
    os.chmod(unsafe_parent, 0o777)
    with pytest.raises(BallotFormatError, match="owner-controlled"):
        ReplayLedger(unsafe_parent / "ledger.sqlite3")

    safe_parent = tmp_path / "safe"
    safe_parent.mkdir(mode=0o700)
    unsafe_file = safe_parent / "unsafe.sqlite3"
    unsafe_file.touch(mode=0o644)
    os.chmod(unsafe_file, 0o644)
    with pytest.raises(BallotFormatError, match="owner-only"):
        ReplayLedger(unsafe_file)

    target = safe_parent / "target.sqlite3"
    target.touch(mode=0o600)
    symlink = safe_parent / "link.sqlite3"
    symlink.symlink_to(target)
    with pytest.raises(BallotFormatError, match="owner-only"):
        ReplayLedger(symlink)


def test_persisted_wire_is_reverified_and_tamper_fails_closed(
    tmp_path: Path,
) -> None:
    """Local ledger mutation cannot create a submittable ensemble result."""
    context = make_context()
    collector, ledger_path = make_collector(tmp_path)
    accept(collector, context, sign_vote(context, 0))
    with sqlite3.connect(ledger_path) as connection:
        connection.execute(
            "UPDATE accepted_ballots SET wire = ?", (b'{"tampered":true}',)
        )

    result = collector.evaluate(
        context.candidate, context.snapshot, context.session, NOW_MS
    )
    assert result.approved is False
    assert result.analysis.should_submit is False
    assert result.analysis.yara_rule is None


def test_replay_marker_is_retained_until_the_complete_session_expires(
    tmp_path: Path,
) -> None:
    """Ballot expiry cannot reopen equivocation during the same session."""
    context = make_context()
    collector, ledger_path = make_collector(tmp_path)
    envelope = sign_vote(context, 0, expires_at_ms=NOW_MS + 1)
    accept(collector, context, envelope)
    ledger = ReplayLedger(ledger_path)

    assert ledger.prune_expired(NOW_MS) == 0
    assert ledger.prune_expired(NOW_MS + 1) == 0
    assert len(ledger.session_wires(context.session.session_id)) == 1
    assert ledger.prune_expired(context.session.valid_until_ms) == 1
    assert ledger.session_wires(context.session.session_id) == ()


def test_persistent_clock_high_water_rejects_rollback_after_pruning(
    tmp_path: Path,
) -> None:
    """A forward clock jump followed by rollback cannot reopen a session."""
    context = make_context()
    collector, ledger_path = make_collector(tmp_path)
    envelope = sign_vote(context, 0)
    accept(collector, context, envelope)

    assert ReplayLedger(ledger_path).prune_expired(context.session.valid_until_ms) == 1
    restarted = AuthenticatedBallotCollector(ReplayLedger(ledger_path))
    with pytest.raises(BallotReplayError, match="clock rollback"):
        accept(restarted, context, envelope, NOW_MS)
    assert ReplayLedger(ledger_path).session_wires(context.session.session_id) == ()


def test_malformed_session_fails_closed_without_raising_internal_errors(
    tmp_path: Path,
) -> None:
    """Ad-hoc malformed signer objects cannot crash ensemble evaluation."""
    context = make_context()
    collector, _ = make_collector(tmp_path)
    malformed = replace(context.session, signers=(object(),))

    result = collector.evaluate(
        context.candidate, context.snapshot, malformed, NOW_MS  # type: ignore[arg-type]
    )
    assert result.approved is False
    assert result.analysis.should_submit is False
    assert result.analysis.yara_rule is None
