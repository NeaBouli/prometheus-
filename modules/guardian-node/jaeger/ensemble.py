"""Fail-closed local voting for independent Guardian 8B committees.

This module validates an already collected committee ballot. It deliberately
does not discover Guardians, trust a membership source, transport or sign
votes, submit rules, or perform chain operations.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Literal

from .analyzer import AnalysisResult
from .yara_generator import MIN_CONFIDENCE, YaraRule

ENSEMBLE_PROTOCOL_VERSION: int = 1
MIN_ENSEMBLE_MEMBERS: int = 5
MIN_CONFIDENCE_BPS: int = int(MIN_CONFIDENCE * 10_000)

_CANDIDATE_DOMAIN = b"PROMETHEUS_GUARDIAN_ENSEMBLE_CANDIDATE_V1"
_SNAPSHOT_DOMAIN = b"PROMETHEUS_GUARDIAN_MEMBERSHIP_SNAPSHOT_V1"
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")

ModelTier = Literal["8b"]
VoteDecision = Literal["approve", "reject"]


@dataclass(frozen=True)
class GuardianMember:
    """One expected 8B voter in an externally sourced committee snapshot."""

    guardian_id: str
    model_tier: ModelTier
    model_artifact_sha256: str


@dataclass(frozen=True)
class MembershipSnapshot:
    """Immutable commitment to the complete expected Guardian committee."""

    protocol_version: int
    membership_source_sha256: str
    members: tuple[GuardianMember, ...]
    snapshot_id: str

    @classmethod
    def create(
        cls,
        members: Sequence[GuardianMember],
        membership_source_sha256: str,
    ) -> "MembershipSnapshot":
        """Validate, sort, and commit to a locally supplied membership set."""
        canonical_members = _validated_members(members)
        if not _is_sha256(membership_source_sha256):
            raise ValueError("membership source must be a canonical SHA-256 digest")

        payload = _snapshot_payload(
            ENSEMBLE_PROTOCOL_VERSION,
            membership_source_sha256,
            canonical_members,
        )
        return cls(
            protocol_version=ENSEMBLE_PROTOCOL_VERSION,
            membership_source_sha256=membership_source_sha256,
            members=canonical_members,
            snapshot_id=_canonical_digest(_SNAPSHOT_DOMAIN, payload),
        )


@dataclass(frozen=True)
class EnsembleCandidate:  # pylint: disable=too-many-instance-attributes
    """Canonical YARA candidate evaluated by every committee member."""

    protocol_version: int
    rule_type: Literal["yara"]
    threat_hash: str
    rule_name: str
    rule_content: str
    rule_generated_at: int
    rule_confidence_bps: int
    rule_sha256: str
    policy_sha256: str
    model_artifact_sha256: str
    candidate_digest: str

    @classmethod
    def create(
        cls,
        rule: YaraRule,
        policy_sha256: str,
        model_artifact_sha256: str,
    ) -> "EnsembleCandidate":
        """Build a domain-separated commitment to a validated YARA rule."""
        if not _is_safe_rule(rule):
            raise ValueError("rule must be a valid, canonically bound YARA rule")
        if not _is_sha256(policy_sha256):
            raise ValueError("policy must be a canonical SHA-256 digest")
        if not _is_sha256(model_artifact_sha256):
            raise ValueError("model artifact must be a canonical SHA-256 digest")

        rule_confidence_bps = _confidence_to_bps(rule.confidence)
        if rule_confidence_bps is None or rule_confidence_bps < MIN_CONFIDENCE_BPS:
            raise ValueError(
                "rule confidence must meet the canonical submission policy"
            )

        rule_sha256 = hashlib.sha256(rule.rule_content.encode("utf-8")).hexdigest()
        payload = _candidate_payload(
            ENSEMBLE_PROTOCOL_VERSION,
            rule.threat_hash,
            rule.name,
            rule.rule_content,
            rule.generated_at,
            rule_confidence_bps,
            rule_sha256,
            policy_sha256,
            model_artifact_sha256,
        )
        return cls(
            protocol_version=ENSEMBLE_PROTOCOL_VERSION,
            rule_type="yara",
            threat_hash=rule.threat_hash,
            rule_name=rule.name,
            rule_content=rule.rule_content,
            rule_generated_at=rule.generated_at,
            rule_confidence_bps=rule_confidence_bps,
            rule_sha256=rule_sha256,
            policy_sha256=policy_sha256,
            model_artifact_sha256=model_artifact_sha256,
            candidate_digest=_canonical_digest(_CANDIDATE_DOMAIN, payload),
        )


@dataclass(frozen=True)
class GuardianVote:  # pylint: disable=too-many-instance-attributes
    """One unsigned local ballot bound to a candidate and membership snapshot."""

    guardian_id: str
    membership_snapshot_id: str
    candidate_digest: str
    decision: VoteDecision
    confidence_bps: int
    model_tier: ModelTier
    model_artifact_sha256: str
    protocol_version: int = ENSEMBLE_PROTOCOL_VERSION


@dataclass(frozen=True)
class EnsembleDecision:  # pylint: disable=too-many-instance-attributes
    """Validated local ensemble result with a fail-closed analysis decision."""

    analysis: AnalysisResult
    membership_snapshot_id: str | None
    candidate_digest: str | None
    committee_size: int
    approvals: int
    rejections: int
    aggregate_confidence_bps: int | None
    approved: bool
    reason: str


@dataclass(frozen=True)
class _BallotTally:
    """Validated complete-ballot counts and approval confidences."""

    approval_confidences_bps: tuple[int, ...]
    rejections: int


class EnsembleVoter:  # pylint: disable=too-few-public-methods
    """Validate a complete committee ballot and require a strict majority."""

    def evaluate(
        self,
        candidate: EnsembleCandidate,
        snapshot: MembershipSnapshot,
        votes: Sequence[GuardianVote],
    ) -> EnsembleDecision:
        """Return a submittable rule only for a complete, valid majority ballot."""
        if not _is_valid_candidate(candidate):
            return _failed_decision(reason="invalid candidate")
        if not _is_valid_snapshot(snapshot):
            return _failed_decision(
                reason="invalid membership snapshot",
                threat_hash=candidate.threat_hash,
                candidate_digest=candidate.candidate_digest,
            )

        committee_size = len(snapshot.members)
        if any(
            member.model_artifact_sha256 != candidate.model_artifact_sha256
            for member in snapshot.members
        ):
            return _failed_decision(
                reason="committee model binding mismatch",
                threat_hash=candidate.threat_hash,
                candidate_digest=candidate.candidate_digest,
                membership_snapshot_id=snapshot.snapshot_id,
                committee_size=committee_size,
            )

        members_by_id = {member.guardian_id: member for member in snapshot.members}
        tally = _validate_ballot(votes, candidate, snapshot, members_by_id)
        if isinstance(tally, str):
            return _failed_ballot(candidate, snapshot, tally)

        approval_count = len(tally.approval_confidences_bps)
        if approval_count <= committee_size // 2:
            return _failed_decision(
                reason="strict committee majority not reached",
                threat_hash=candidate.threat_hash,
                candidate_digest=candidate.candidate_digest,
                membership_snapshot_id=snapshot.snapshot_id,
                committee_size=committee_size,
                approvals=approval_count,
                rejections=tally.rejections,
            )

        aggregate_confidence_bps = min(
            candidate.rule_confidence_bps,
            *tally.approval_confidences_bps,
        )
        confidence = aggregate_confidence_bps / 10_000
        approved_rule = YaraRule(
            name=candidate.rule_name,
            rule_content=candidate.rule_content,
            confidence=confidence,
            threat_hash=candidate.threat_hash,
            generated_at=candidate.rule_generated_at,
        )
        return EnsembleDecision(
            analysis=AnalysisResult(
                threat_hash=candidate.threat_hash,
                yara_rule=approved_rule,
                confidence=confidence,
                should_submit=True,
                analysis_notes="Guardian ensemble reached a strict complete-ballot majority.",
            ),
            membership_snapshot_id=snapshot.snapshot_id,
            candidate_digest=candidate.candidate_digest,
            committee_size=committee_size,
            approvals=approval_count,
            rejections=tally.rejections,
            aggregate_confidence_bps=aggregate_confidence_bps,
            approved=True,
            reason="strict committee majority approved",
        )


# Each early return names one distinct fail-closed ballot rejection.
# pylint: disable-next=too-many-return-statements
def _validate_ballot(
    votes: Sequence[GuardianVote],
    candidate: EnsembleCandidate,
    snapshot: MembershipSnapshot,
    members_by_id: dict[str, GuardianMember],
) -> _BallotTally | str:
    """Validate exactly one bound vote from every committed member."""
    try:
        ballot = tuple(votes)
    except Exception:  # pylint: disable=broad-except
        return "invalid ballot container"
    if len(ballot) != len(members_by_id):
        return "incomplete committee ballot"

    seen_guardians: set[str] = set()
    approval_confidences: list[int] = []
    rejections = 0
    for vote in ballot:
        if not _is_valid_vote(vote, candidate, snapshot, members_by_id):
            return "invalid committee vote"
        if vote.guardian_id in seen_guardians:
            return "duplicate committee vote"
        seen_guardians.add(vote.guardian_id)

        if vote.decision == "approve":
            if vote.confidence_bps < MIN_CONFIDENCE_BPS:
                return "approval below confidence policy"
            approval_confidences.append(vote.confidence_bps)
        else:
            rejections += 1

    if seen_guardians != set(members_by_id):
        return "incomplete committee ballot"
    return _BallotTally(tuple(approval_confidences), rejections)


def _validated_members(
    members: Sequence[GuardianMember],
) -> tuple[GuardianMember, ...]:
    """Return canonical members or raise for unsafe committee configuration."""
    try:
        canonical_members = tuple(
            sorted(members, key=lambda member: member.guardian_id)
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise ValueError("members must be a finite GuardianMember sequence") from exc

    if len(canonical_members) < MIN_ENSEMBLE_MEMBERS:
        raise ValueError("ensemble requires at least five Guardian members")
    if not all(_is_valid_member(member) for member in canonical_members):
        raise ValueError("ensemble member fields are invalid")

    guardian_ids = [member.guardian_id for member in canonical_members]
    if len(set(guardian_ids)) != len(guardian_ids):
        raise ValueError("ensemble Guardian IDs must be unique")
    return canonical_members


def _is_valid_member(member: object) -> bool:
    """Validate canonical identity and pinned 8B artifact fields."""
    return (
        isinstance(member, GuardianMember)
        and _is_sha256(member.guardian_id)
        and isinstance(member.model_tier, str)
        and member.model_tier == "8b"
        and _is_sha256(member.model_artifact_sha256)
    )


def _is_valid_snapshot(snapshot: object) -> bool:
    """Verify snapshot shape, canonical order, and self-commitment."""
    if not isinstance(snapshot, MembershipSnapshot):
        return False
    if (
        not _is_int(snapshot.protocol_version)
        or snapshot.protocol_version != ENSEMBLE_PROTOCOL_VERSION
        or not _is_sha256(snapshot.membership_source_sha256)
        or not _is_sha256(snapshot.snapshot_id)
        or not isinstance(snapshot.members, tuple)
    ):
        return False

    try:
        canonical_members = _validated_members(snapshot.members)
        expected_id = _canonical_digest(
            _SNAPSHOT_DOMAIN,
            _snapshot_payload(
                snapshot.protocol_version,
                snapshot.membership_source_sha256,
                canonical_members,
            ),
        )
    except (TypeError, ValueError, UnicodeError):
        return False
    return snapshot.members == canonical_members and snapshot.snapshot_id == expected_id


def _is_valid_candidate(candidate: object) -> bool:
    """Verify every candidate field and recompute its commitments."""
    if not isinstance(candidate, EnsembleCandidate):
        return False
    valid_protocol = (
        _is_int(candidate.protocol_version)
        and candidate.protocol_version == ENSEMBLE_PROTOCOL_VERSION
        and isinstance(candidate.rule_type, str)
        and candidate.rule_type == "yara"
    )
    valid_rule = (
        _is_sha256(candidate.threat_hash)
        and _is_rule_name(candidate.rule_name)
        and _is_rule_content(candidate.rule_name, candidate.rule_content)
        and _is_int(candidate.rule_generated_at)
        and candidate.rule_generated_at >= 0
        and _is_int(candidate.rule_confidence_bps)
        and MIN_CONFIDENCE_BPS <= candidate.rule_confidence_bps <= 10_000
    )
    valid_hashes = all(
        _is_sha256(value)
        for value in (
            candidate.rule_sha256,
            candidate.policy_sha256,
            candidate.model_artifact_sha256,
            candidate.candidate_digest,
        )
    )
    if not (valid_protocol and valid_rule and valid_hashes):
        return False

    try:
        expected_rule_hash = hashlib.sha256(
            candidate.rule_content.encode("utf-8")
        ).hexdigest()
        expected_digest = _canonical_digest(
            _CANDIDATE_DOMAIN,
            _candidate_payload(
                candidate.protocol_version,
                candidate.threat_hash,
                candidate.rule_name,
                candidate.rule_content,
                candidate.rule_generated_at,
                candidate.rule_confidence_bps,
                candidate.rule_sha256,
                candidate.policy_sha256,
                candidate.model_artifact_sha256,
            ),
        )
    except (TypeError, UnicodeError):
        return False
    return (
        candidate.rule_sha256 == expected_rule_hash
        and candidate.candidate_digest == expected_digest
    )


def _is_valid_vote(
    vote: object,
    candidate: EnsembleCandidate,
    snapshot: MembershipSnapshot,
    members_by_id: dict[str, GuardianMember],
) -> bool:
    """Validate one ballot against every committee and candidate binding."""
    if not isinstance(vote, GuardianVote):
        return False
    member = members_by_id.get(vote.guardian_id)
    return (
        member is not None
        and _is_int(vote.protocol_version)
        and vote.protocol_version == ENSEMBLE_PROTOCOL_VERSION
        and _is_sha256(vote.guardian_id)
        and vote.membership_snapshot_id == snapshot.snapshot_id
        and vote.candidate_digest == candidate.candidate_digest
        and isinstance(vote.decision, str)
        and vote.decision in ("approve", "reject")
        and _is_int(vote.confidence_bps)
        and 0 <= vote.confidence_bps <= 10_000
        and isinstance(vote.model_tier, str)
        and vote.model_tier == "8b"
        and vote.model_tier == member.model_tier
        and vote.model_artifact_sha256 == member.model_artifact_sha256
        and vote.model_artifact_sha256 == candidate.model_artifact_sha256
    )


def _is_safe_rule(rule: object) -> bool:
    """Validate the YARA metadata accepted into a candidate commitment."""
    return (
        isinstance(rule, YaraRule)
        and _is_sha256(rule.threat_hash)
        and _is_rule_name(rule.name)
        and _is_rule_content(rule.name, rule.rule_content)
        and _confidence_to_bps(rule.confidence) is not None
        and _is_int(rule.generated_at)
        and rule.generated_at >= 0
    )


def _is_valid_confidence(value: object) -> bool:
    """Require a finite, non-boolean numeric confidence in [0, 1]."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return math.isfinite(float(value)) and 0.0 <= float(value) <= 1.0


def _confidence_to_bps(value: object) -> int | None:
    """Convert a confidence with at most four decimal places to basis points."""
    if not _is_valid_confidence(value):
        return None
    try:
        scaled = Decimal(str(value)) * Decimal(10_000)
    except InvalidOperation:
        return None
    integral = scaled.to_integral_value()
    if scaled != integral:
        return None
    return int(integral)


def _is_rule_name(value: object) -> bool:
    """Require a non-empty single-token YARA identifier."""
    return (
        isinstance(value, str)
        and bool(value)
        and len(value) <= 128
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value) is not None
    )


def _is_rule_content(rule_name: str, value: object) -> bool:
    """Apply the repository's current basic YARA syntax envelope."""
    if not isinstance(value, str):
        return False
    try:
        content_size = len(value.encode("utf-8"))
    except UnicodeError:
        return False
    return (
        0 < content_size <= 1_000_000
        and f"rule {rule_name}" in value
        and "strings:" in value
        and "condition:" in value
    )


def _is_sha256(value: object) -> bool:
    """Require canonical lowercase SHA-256 hexadecimal text."""
    return isinstance(value, str) and _SHA256_PATTERN.fullmatch(value) is not None


def _is_int(value: object) -> bool:
    """Require a real integer while rejecting bool's integer subclass."""
    return isinstance(value, int) and not isinstance(value, bool)


def _canonical_digest(domain: bytes, payload: dict[str, object]) -> str:
    """Hash canonical JSON under an explicit protocol domain."""
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(domain + b"\x00" + encoded).hexdigest()


def _snapshot_payload(
    protocol_version: int,
    membership_source_sha256: str,
    members: tuple[GuardianMember, ...],
) -> dict[str, object]:
    """Build the canonical membership commitment payload."""
    return {
        "members": [
            {
                "guardian_id": member.guardian_id,
                "model_artifact_sha256": member.model_artifact_sha256,
                "model_tier": member.model_tier,
            }
            for member in members
        ],
        "membership_source_sha256": membership_source_sha256,
        "protocol_version": protocol_version,
    }


# Explicit parameters keep every security binding visible at the hash boundary.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def _candidate_payload(
    protocol_version: int,
    threat_hash: str,
    rule_name: str,
    rule_content: str,
    rule_generated_at: int,
    rule_confidence_bps: int,
    rule_sha256: str,
    policy_sha256: str,
    model_artifact_sha256: str,
) -> dict[str, object]:
    """Build the canonical candidate commitment payload."""
    return {
        "model_artifact_sha256": model_artifact_sha256,
        "policy_sha256": policy_sha256,
        "protocol_version": protocol_version,
        "rule_content": rule_content,
        "rule_confidence_bps": rule_confidence_bps,
        "rule_generated_at": rule_generated_at,
        "rule_name": rule_name,
        "rule_sha256": rule_sha256,
        "rule_type": "yara",
        "threat_hash": threat_hash,
    }


def _failed_ballot(
    candidate: EnsembleCandidate,
    snapshot: MembershipSnapshot,
    reason: str,
) -> EnsembleDecision:
    """Build a bound but non-submittable result for ballot failures."""
    return _failed_decision(
        reason=reason,
        threat_hash=candidate.threat_hash,
        candidate_digest=candidate.candidate_digest,
        membership_snapshot_id=snapshot.snapshot_id,
        committee_size=len(snapshot.members),
    )


# Explicit fields avoid an unvalidated loose metadata dictionary.
# pylint: disable-next=too-many-arguments,too-many-positional-arguments
def _failed_decision(
    reason: str,
    threat_hash: str = "",
    candidate_digest: str | None = None,
    membership_snapshot_id: str | None = None,
    committee_size: int = 0,
    approvals: int = 0,
    rejections: int = 0,
) -> EnsembleDecision:
    """Build a generic fail-closed ensemble decision."""
    return EnsembleDecision(
        analysis=AnalysisResult(
            threat_hash=threat_hash,
            yara_rule=None,
            confidence=0.0,
            should_submit=False,
            analysis_notes="Guardian ensemble validation failed closed.",
        ),
        membership_snapshot_id=membership_snapshot_id,
        candidate_digest=candidate_digest,
        committee_size=committee_size,
        approvals=approvals,
        rejections=rejections,
        aggregate_confidence_bps=None,
        approved=False,
        reason=reason,
    )
