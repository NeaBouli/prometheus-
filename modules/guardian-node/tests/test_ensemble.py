"""Tests for fail-closed local Guardian ensemble voting."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace

import pytest

from jaeger.ensemble import (
    ENSEMBLE_PROTOCOL_VERSION,
    MIN_CONFIDENCE_BPS,
    EnsembleCandidate,
    EnsembleVoter,
    GuardianMember,
    GuardianVote,
    MembershipSnapshot,
)
from jaeger.yara_generator import YaraRule

MODEL_HASH = "1" * 64
POLICY_HASH = "2" * 64
MEMBERSHIP_SOURCE_HASH = "3" * 64
THREAT_HASH = "a" * 64
EXPECTED_CANDIDATE_DIGEST = (
    "b6c045b9e5a25b0fb24822a11d7d55535ed64116360cd9f5e7df9d57fb2e311e"
)
EXPECTED_RULE_SHA256 = (
    "3e875a80d81a14c8a90e9a026b99404c9dd819406538b0fd3b43393a3206860b"
)
EXPECTED_SNAPSHOT_ID = (
    "d49d115eeed0c2292cd449fa6828295d4bdeb3248308808f95c40c22283c6699"
)


def make_rule(confidence_bps: object = 9_500) -> YaraRule:
    """Build one deterministic candidate rule."""
    return YaraRule(
        name="PROM_TEST_RULE",
        rule_content=(
            'rule PROM_TEST_RULE { strings: $a = "suspicious" condition: $a }'
        ),
        confidence_bps=confidence_bps,  # type: ignore[arg-type]
        threat_hash=THREAT_HASH,
        generated_at=1_700_000_000,
    )


def guardian_id(index: int) -> str:
    """Return a canonical deterministic public Guardian identifier."""
    return f"{index:064x}"


def make_members(count: int = 5) -> list[GuardianMember]:
    """Build a deterministic 8B committee."""
    return [
        GuardianMember(
            guardian_id=guardian_id(index),
            model_tier="8b",
            model_artifact_sha256=MODEL_HASH,
        )
        for index in range(1, count + 1)
    ]


def make_context(
    count: int = 5,
) -> tuple[EnsembleCandidate, MembershipSnapshot]:
    """Build a valid candidate and membership snapshot."""
    candidate = EnsembleCandidate.create(make_rule(), POLICY_HASH, MODEL_HASH)
    snapshot = MembershipSnapshot.create(make_members(count), MEMBERSHIP_SOURCE_HASH)
    return candidate, snapshot


def make_votes(
    candidate: EnsembleCandidate,
    snapshot: MembershipSnapshot,
    decisions: list[str],
    confidences: list[int] | None = None,
) -> list[GuardianVote]:
    """Build one bound vote for every listed committee decision."""
    vote_confidences = confidences or [9_000] * len(decisions)
    return [
        GuardianVote(
            guardian_id=member.guardian_id,
            membership_snapshot_id=snapshot.snapshot_id,
            candidate_digest=candidate.candidate_digest,
            decision=decision,  # type: ignore[arg-type]
            confidence_bps=confidence,
            model_tier="8b",
            model_artifact_sha256=MODEL_HASH,
        )
        for member, decision, confidence in zip(
            snapshot.members, decisions, vote_confidences, strict=True
        )
    ]


def test_three_of_five_complete_votes_approve_with_minimum_confidence() -> None:
    """A complete 3:2 ballot returns the candidate at conservative confidence."""
    candidate, snapshot = make_context()
    votes = make_votes(
        candidate,
        snapshot,
        ["approve", "reject", "approve", "reject", "approve"],
        [9_500, 9_900, 8_500, 8_000, 9_000],
    )

    decision = EnsembleVoter().evaluate(candidate, snapshot, votes)

    assert decision.approved is True
    assert decision.analysis.should_submit is True
    assert decision.approvals == 3
    assert decision.rejections == 2
    assert decision.aggregate_confidence_bps == MIN_CONFIDENCE_BPS
    assert decision.analysis.confidence == 0.85
    assert decision.analysis.yara_rule is not None
    assert decision.analysis.yara_rule.rule_content == candidate.rule_content
    assert decision.analysis.yara_rule.confidence == 0.85


def test_four_of_six_complete_votes_approve() -> None:
    """Committees larger than five still require a strict total majority."""
    candidate, snapshot = make_context(6)
    votes = make_votes(
        candidate,
        snapshot,
        ["approve", "approve", "reject", "approve", "reject", "approve"],
    )

    decision = EnsembleVoter().evaluate(candidate, snapshot, votes)

    assert decision.approved is True
    assert decision.approvals == 4
    assert decision.committee_size == 6


@pytest.mark.parametrize(
    "decisions",
    [
        ["reject", "reject", "reject", "approve", "approve"],
        ["reject", "reject", "reject", "reject", "reject"],
    ],
)
def test_non_majority_fails_closed(decisions: list[str]) -> None:
    """A rejection majority or unanimous rejection cannot expose a rule."""
    candidate, snapshot = make_context()

    decision = EnsembleVoter().evaluate(
        candidate, snapshot, make_votes(candidate, snapshot, decisions)
    )

    assert decision.approved is False
    assert decision.analysis.should_submit is False
    assert decision.analysis.yara_rule is None
    assert decision.aggregate_confidence_bps is None


def test_even_committee_tie_fails_closed() -> None:
    """A complete 3:3 ballot is not a strict majority."""
    candidate, snapshot = make_context(6)
    votes = make_votes(
        candidate,
        snapshot,
        ["approve", "reject", "approve", "reject", "approve", "reject"],
    )

    decision = EnsembleVoter().evaluate(candidate, snapshot, votes)

    assert decision.approved is False
    assert decision.approvals == 3
    assert decision.rejections == 3
    assert decision.analysis.yara_rule is None


def test_missing_vote_fails_closed_instead_of_shrinking_quorum() -> None:
    """The majority denominator is never reduced by an absent Guardian."""
    candidate, snapshot = make_context()
    votes = make_votes(
        candidate,
        snapshot,
        ["approve", "approve", "approve", "reject", "reject"],
    )[:-1]

    decision = EnsembleVoter().evaluate(candidate, snapshot, votes)

    assert decision.approved is False
    assert decision.reason == "incomplete committee ballot"
    assert decision.analysis.yara_rule is None


def test_faulting_ballot_container_fails_closed_without_leaking_error() -> None:
    """An adapter failure while collecting votes is a generic failed ballot."""
    candidate, snapshot = make_context()

    class FaultingVotes:  # pylint: disable=too-few-public-methods
        """Minimal hostile adapter used to exercise the total failure envelope."""

        def __iter__(self) -> Iterator[GuardianVote]:
            raise RuntimeError("sensitive transport detail")

    decision = EnsembleVoter().evaluate(
        candidate,
        snapshot,
        FaultingVotes(),  # type: ignore[arg-type]
    )

    assert decision.approved is False
    assert decision.reason == "invalid ballot container"
    assert "sensitive" not in decision.analysis.analysis_notes


def test_duplicate_vote_fails_closed() -> None:
    """One Guardian cannot occupy two ballot slots."""
    candidate, snapshot = make_context()
    votes = make_votes(
        candidate,
        snapshot,
        ["approve", "approve", "approve", "reject", "reject"],
    )
    votes[-1] = votes[0]

    decision = EnsembleVoter().evaluate(candidate, snapshot, votes)

    assert decision.approved is False
    assert decision.reason == "duplicate committee vote"


def test_unknown_guardian_fails_closed() -> None:
    """A ballot identity outside the committed membership is invalid."""
    candidate, snapshot = make_context()
    votes = make_votes(candidate, snapshot, ["approve"] * 5)
    votes[0] = replace(votes[0], guardian_id=guardian_id(99))

    decision = EnsembleVoter().evaluate(candidate, snapshot, votes)

    assert decision.approved is False
    assert decision.reason == "invalid committee vote"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("membership_snapshot_id", "f" * 64),
        ("candidate_digest", "e" * 64),
        ("model_artifact_sha256", "d" * 64),
        ("model_tier", "70b"),
        ("protocol_version", ENSEMBLE_PROTOCOL_VERSION + 1),
    ],
)
def test_vote_binding_mismatch_fails_closed(field: str, value: object) -> None:
    """Every ballot binding must match the committed candidate and committee."""
    candidate, snapshot = make_context()
    votes = make_votes(candidate, snapshot, ["approve"] * 5)
    votes[0] = replace(votes[0], **{field: value})  # type: ignore[arg-type]

    decision = EnsembleVoter().evaluate(candidate, snapshot, votes)

    assert decision.approved is False
    assert decision.analysis.should_submit is False


@pytest.mark.parametrize("confidence", [8_499, -1, 10_001, True, False, "9000"])
def test_invalid_or_low_approval_confidence_fails_closed(confidence: object) -> None:
    """Approve votes require a real bounded integer at the 8500-bps policy."""
    candidate, snapshot = make_context()
    votes = make_votes(candidate, snapshot, ["approve"] * 5)
    votes[0] = replace(votes[0], confidence_bps=confidence)  # type: ignore[arg-type]

    decision = EnsembleVoter().evaluate(candidate, snapshot, votes)

    assert decision.approved is False
    assert decision.analysis.confidence == 0.0
    assert decision.analysis.yara_rule is None


@pytest.mark.parametrize("decision_value", [True, 1, "yes"])
def test_noncanonical_vote_decision_fails_closed(decision_value: object) -> None:
    """Only literal approve/reject strings are accepted."""
    candidate, snapshot = make_context()
    votes = make_votes(candidate, snapshot, ["approve"] * 5)
    votes[0] = replace(votes[0], decision=decision_value)  # type: ignore[arg-type]

    decision = EnsembleVoter().evaluate(candidate, snapshot, votes)

    assert decision.approved is False
    assert decision.analysis.yara_rule is None


def test_reject_vote_may_report_low_confidence() -> None:
    """The submission threshold applies to approvals, not explicit rejections."""
    candidate, snapshot = make_context()
    votes = make_votes(
        candidate,
        snapshot,
        ["approve", "approve", "approve", "reject", "reject"],
        [9_000, 9_100, 9_200, 0, 1_000],
    )

    decision = EnsembleVoter().evaluate(candidate, snapshot, votes)

    assert decision.approved is True
    assert decision.aggregate_confidence_bps == 9_000


def test_source_rule_confidence_caps_approved_result() -> None:
    """Committee confidence cannot raise the source rule above its own evidence."""
    candidate = EnsembleCandidate.create(make_rule(8_600), POLICY_HASH, MODEL_HASH)
    snapshot = MembershipSnapshot.create(make_members(), MEMBERSHIP_SOURCE_HASH)
    votes = make_votes(candidate, snapshot, ["approve"] * 5, [9_000] * 5)

    decision = EnsembleVoter().evaluate(candidate, snapshot, votes)

    assert decision.approved is True
    assert decision.aggregate_confidence_bps == 8_600
    assert decision.analysis.confidence == 0.86
    assert decision.analysis.yara_rule is not None
    assert decision.analysis.yara_rule.confidence == 0.86


def test_source_rule_confidence_changes_candidate_digest() -> None:
    """Canonical source confidence is committed as YARA candidate metadata."""
    lower = EnsembleCandidate.create(make_rule(8_500), POLICY_HASH, MODEL_HASH)
    higher = EnsembleCandidate.create(make_rule(9_500), POLICY_HASH, MODEL_HASH)

    assert lower.rule_confidence_bps == 8_500
    assert higher.rule_confidence_bps == 9_500
    assert lower.candidate_digest != higher.candidate_digest


def test_source_rule_below_submission_threshold_is_rejected() -> None:
    """Votes cannot promote a source rule that fails the existing 0.85 policy."""
    with pytest.raises(ValueError, match="submission policy"):
        EnsembleCandidate.create(make_rule(8_499), POLICY_HASH, MODEL_HASH)


@pytest.mark.parametrize("confidence_bps", [8_499.9, "8500", True])
def test_source_rule_requires_integer_basis_points(confidence_bps: object) -> None:
    """Non-integer source confidence cannot enter a canonical candidate."""
    with pytest.raises(ValueError, match="canonically bound"):
        EnsembleCandidate.create(make_rule(confidence_bps), POLICY_HASH, MODEL_HASH)


def test_source_rule_confidence_requires_canonical_basis_points() -> None:
    """Candidate construction rejects out-of-range source confidence."""
    with pytest.raises(ValueError, match="canonically bound"):
        EnsembleCandidate.create(make_rule(10_001), POLICY_HASH, MODEL_HASH)


def test_tampered_rule_bytes_invalidate_candidate() -> None:
    """Candidate digest verification binds the exact UTF-8 YARA bytes."""
    candidate, snapshot = make_context()
    tampered = replace(candidate, rule_content=candidate.rule_content + " ")

    decision = EnsembleVoter().evaluate(
        tampered, snapshot, make_votes(candidate, snapshot, ["approve"] * 5)
    )

    assert decision.approved is False
    assert decision.reason == "invalid candidate"
    assert decision.analysis.yara_rule is None


def test_non_utf8_encodable_rule_fails_closed_without_raising() -> None:
    """Malformed Unicode cannot escape candidate validation."""
    candidate, snapshot = make_context()
    tampered = replace(candidate, rule_content="rule PROM_TEST_RULE \ud800")

    decision = EnsembleVoter().evaluate(
        tampered, snapshot, make_votes(candidate, snapshot, ["approve"] * 5)
    )

    assert decision.approved is False
    assert decision.reason == "invalid candidate"
    assert decision.analysis.yara_rule is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("threat_hash", "f" * 64),
        ("rule_confidence_bps", 9_499),
        ("rule_sha256", "f" * 64),
        ("policy_sha256", "f" * 64),
        ("model_artifact_sha256", "f" * 64),
    ],
)
def test_tampered_candidate_hash_binding_fails_closed(
    field: str, value: object
) -> None:
    """All security-relevant candidate commitments are recomputed."""
    candidate, snapshot = make_context()
    tampered = replace(candidate, **{field: value})

    decision = EnsembleVoter().evaluate(
        tampered, snapshot, make_votes(candidate, snapshot, ["approve"] * 5)
    )

    assert decision.approved is False
    assert decision.analysis.yara_rule is None


def test_tampered_membership_snapshot_fails_closed() -> None:
    """Member changes cannot retain an earlier snapshot commitment."""
    candidate, snapshot = make_context()
    changed_member = replace(snapshot.members[0], guardian_id=guardian_id(99))
    tampered = replace(snapshot, members=(changed_member, *snapshot.members[1:]))

    decision = EnsembleVoter().evaluate(
        candidate, tampered, make_votes(candidate, snapshot, ["approve"] * 5)
    )

    assert decision.approved is False
    assert decision.reason == "invalid membership snapshot"


def test_snapshot_creation_sorts_members_deterministically() -> None:
    """Input ordering does not change a committee commitment."""
    members = make_members()

    forward = MembershipSnapshot.create(members, MEMBERSHIP_SOURCE_HASH)
    reverse = MembershipSnapshot.create(list(reversed(members)), MEMBERSHIP_SOURCE_HASH)

    assert forward == reverse
    assert forward.snapshot_id == reverse.snapshot_id


def test_candidate_creation_is_deterministic() -> None:
    """Identical rule and policy inputs produce one candidate digest."""
    first = EnsembleCandidate.create(make_rule(), POLICY_HASH, MODEL_HASH)
    second = EnsembleCandidate.create(make_rule(), POLICY_HASH, MODEL_HASH)

    assert first == second
    assert first.candidate_digest == second.candidate_digest


def test_canonical_commitment_public_vectors() -> None:
    """Pin the protocol-v1 canonical JSON commitments for interoperability."""
    candidate, snapshot = make_context()

    assert candidate.rule_sha256 == EXPECTED_RULE_SHA256
    assert candidate.candidate_digest == EXPECTED_CANDIDATE_DIGEST
    assert snapshot.snapshot_id == EXPECTED_SNAPSHOT_ID


def test_fewer_than_five_members_are_rejected() -> None:
    """The protocol cannot be configured below its 5-Guardian floor."""
    with pytest.raises(ValueError, match="at least five"):
        MembershipSnapshot.create(make_members(4), MEMBERSHIP_SOURCE_HASH)


def test_duplicate_members_are_rejected() -> None:
    """A committed committee cannot contain a duplicate Guardian identity."""
    members = make_members()
    members[-1] = members[0]

    with pytest.raises(ValueError, match="must be unique"):
        MembershipSnapshot.create(members, MEMBERSHIP_SOURCE_HASH)


def test_non_8b_member_is_rejected() -> None:
    """The local protocol cannot silently admit the 70B escalation tier."""
    members = make_members()
    members[0] = replace(members[0], model_tier="70b")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="fields are invalid"):
        MembershipSnapshot.create(members, MEMBERSHIP_SOURCE_HASH)


@pytest.mark.parametrize("confidence_bps", [-1, 10_001, True, False, None])
def test_invalid_candidate_rule_confidence_is_rejected(
    confidence_bps: object,
) -> None:
    """Candidate construction rejects malformed source-rule confidence."""
    with pytest.raises(ValueError, match="valid, canonically bound"):
        EnsembleCandidate.create(
            make_rule(confidence_bps),
            POLICY_HASH,
            MODEL_HASH,
        )
