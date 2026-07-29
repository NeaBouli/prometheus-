"""Local fail-closed ThreatHint-v2 acceptance: verified preflight, then consume.

The service accepts only raw wire bytes: one canonical v2 proof envelope, one
canonical observable bundle, one canonical Observable Approval, the trusted
report nonce, and the trusted current time. It never accepts a caller-supplied
preflight, verification, or consumption receipt, a pre-verified object, a
policy value, a manifest anchor, or any derived statement. Every check is
re-derived inside this single call path from the owner-pinned configuration.

The fail-closed order is fixed. The owner-pinned verified preflight runs
first: canonical binding, statement derivation, disclosure and nonce checks,
commitment recomputation, approval verification, and the hash-pinned Groth16
verifier subprocess. Only after every non-consuming check has passed does the
final state-changing step run: the durable Observable Approval consumption
re-verifies the raw approval and bundle, compares the expected approval
identifier and observable commitment before its atomic ledger insert, and
durably consumes exactly once. A failed proof, privacy, or approval check
therefore never consumes an approval and never advances the ledger high-water
mark.

Construction loads the verified-preflight configuration and preflight policy
first, then builds the consumption service through its restrictive factory:
the consumption policy is loaded once and must exactly match the preflight
policy network, approver x-only public key, and recipient scope before any
ledger file is created or opened. A mismatch is trusted-material failure, not
candidate failure.

Errors are stable and redacted. ``ThreatHintV2AcceptanceError`` (invalid)
rejects bad candidate data, including a failed proof or privacy check.
``ThreatHintV2AcceptanceUnavailableError`` covers unavailable or mismatched
trusted material, verifier timeout, process failure, and generic durable
failure. ``ThreatHintV2AcceptanceReplayError`` reports an already-consumed
approval identity, authority nonce, or a high-water rollback; it is final and
must not be retried with the same inputs. ``ThreatHintV2AcceptanceBusyError``
is the only retryable classification and covers the occupied nonblocking
verifier lock and a temporarily locked ledger. No error message contains
policy keys, scopes, nonces, digests, or wire material.

Concurrency is fail-closed: concurrent calls serialize on the single verifier
slot (the loser gets busy) and on the atomic ledger insert (exactly one
winner; losers get busy or replay). The service requires POSIX because the
verified preflight does; other platforms fail as unavailable at construction.

Crash semantics: the durable consume is the only write and it is atomic; a
governed service built with the durable outbox enabled enqueues one
recoverable outbox record inside that same atomic commit. If the process
crashes after that commit but before the caller receives the receipt, the
approval is consumed; a retry of the same inputs fails as replay and never
double-consumes. Receipt construction performs no I/O and cannot roll the
ledger back; any process failure after the commit is recovered as replay
rather than a second consumption.

The returned receipt grants no authority. It is not privacy/disclosure,
transport, analyzer, promotion, outbox, wallet, chain, deployment,
reputation, KAS/PROM, slash, commit-reveal, or rollout evidence, and a
caller-supplied receipt must never substitute for rerunning this service.
"""

# Exact built-in types are protocol requirements.
# pylint: disable=unidiomatic-typecheck,too-many-branches

from __future__ import annotations

import hmac
from dataclasses import dataclass
from pathlib import Path

from jaeger.observable_approval_consumption import (
    ObservableApprovalBusyError,
    ObservableApprovalConsumptionError,
    ObservableApprovalConsumptionService,
    ObservableApprovalGovernanceCandidateError,
    ObservableApprovalGovernanceUnavailableError,
    ObservableApprovalReplayError,
)
from jaeger.threat_hint_v2_preflight import ThreatHintV2PreflightError
from jaeger.threat_hint_v2_proof_envelope import (
    ThreatHintV2ProofEnvelope,
    ThreatHintV2ProofEnvelopeError,
)
from jaeger.threat_hint_v2_verified_preflight import (
    ThreatHintV2VerifiedPreflightBusyError,
    ThreatHintV2VerifiedPreflightError,
    ThreatHintV2VerifiedPreflightReceipt,
    ThreatHintV2VerifiedPreflightService,
    ThreatHintV2VerifiedPreflightUnavailableError,
)
from jaeger.threat_observable import ObservableKind


class ThreatHintV2AcceptanceError(ValueError):
    """Stable redacted rejection for invalid candidate data."""

    _MESSAGE = "invalid threat-hint v2 acceptance"

    def __init__(self) -> None:
        super().__init__(self._MESSAGE)


class ThreatHintV2AcceptanceUnavailableError(ThreatHintV2AcceptanceError):
    """Stable redacted failure for unavailable trusted material or state."""

    _MESSAGE = "threat-hint v2 acceptance unavailable"


class ThreatHintV2AcceptanceReplayError(ThreatHintV2AcceptanceError):
    """The approval identity, authority nonce, or time was already consumed."""

    _MESSAGE = "threat-hint v2 acceptance replay"


class ThreatHintV2AcceptanceBusyError(ThreatHintV2AcceptanceError):
    """Retryable failure while the verifier slot or ledger is occupied."""

    _MESSAGE = "threat-hint v2 acceptance busy"


@dataclass(frozen=True, init=False, repr=False, eq=False)
class ThreatHintV2AcceptanceReceipt:
    """Immutable data-only acceptance receipt; it grants no authority.

    Direct construction is disabled; ``accept`` is the only supported
    construction path. The receipt binds the verified statement digest,
    approval identifier, observable commitment, manifest and envelope hashes,
    and verifier executable hash to the durable consumption time. It never
    contains proof, statement, bundle, approval, policy key or scope, or
    observable material, and it is not serializable.
    """

    statement_digest: bytes
    approval_id: bytes
    observable_commitment: bytes
    consumed_at: int
    raw_manifest_sha256_hex: str
    envelope_sha256_hex: str
    verifier_executable_sha256_hex: str

    def __init__(self) -> None:
        raise TypeError(
            "direct threat-hint v2 acceptance receipt construction is disabled"
        )

    def __reduce__(self) -> object:
        raise TypeError("threat-hint v2 acceptance receipt is not serializable")


class ThreatHintV2AcceptanceService:  # pylint: disable=too-few-public-methods
    """Run the verified preflight first and durably consume last, in one call."""

    def __init__(
        self,
        config_path: Path,
        preflight_policy_path: Path,
        consumption_policy_path: Path,
    ) -> None:
        self._governed = False
        self._durable_outbox = False
        try:
            self._verified_preflight = ThreatHintV2VerifiedPreflightService(
                config_path, preflight_policy_path
            )
        except (ThreatHintV2VerifiedPreflightError, ThreatHintV2PreflightError):
            raise ThreatHintV2AcceptanceUnavailableError() from None
        try:
            self._consumption = (
                ObservableApprovalConsumptionService.from_expected_identity(
                    consumption_policy_path,
                    expected_network_id=self._verified_preflight.trusted_network_id,
                    expected_approver_xonly_public_key=(
                        self._verified_preflight.trusted_approver_xonly_public_key
                    ),
                    expected_recipient_scope=(
                        self._verified_preflight.trusted_recipient_scope
                    ),
                )
            )
        except ObservableApprovalBusyError:
            raise ThreatHintV2AcceptanceBusyError() from None
        except ObservableApprovalConsumptionError:
            raise ThreatHintV2AcceptanceUnavailableError() from None

    @classmethod
    def from_governed_policies(  # pylint: disable=too-many-arguments
        cls,
        config_path: Path,
        preflight_policy_path: Path,
        consumption_policy_path: Path,
        governance_policy_path: Path,
        retention_policy_path: Path,
        *,
        expected_allowed_observable_kinds: frozenset[ObservableKind],
        expected_promotion_policy_sha256: bytes,
        durable_outbox: bool = False,
    ) -> ThreatHintV2AcceptanceService:
        """Build one governed service before opening or migrating its ledger."""
        if type(durable_outbox) is not bool:
            raise ThreatHintV2AcceptanceUnavailableError()
        service = object.__new__(cls)
        service._governed = True
        service._durable_outbox = durable_outbox
        try:
            service._verified_preflight = ThreatHintV2VerifiedPreflightService(
                config_path, preflight_policy_path
            )
        except (ThreatHintV2VerifiedPreflightError, ThreatHintV2PreflightError):
            raise ThreatHintV2AcceptanceUnavailableError() from None
        try:
            service._consumption = (
                ObservableApprovalConsumptionService.from_governed_expected_identity(
                    consumption_policy_path,
                    governance_policy_path,
                    retention_policy_path,
                    expected_network_id=(
                        service._verified_preflight.trusted_network_id
                    ),
                    expected_approver_xonly_public_key=(
                        service._verified_preflight.trusted_approver_xonly_public_key
                    ),
                    expected_recipient_scope=(
                        service._verified_preflight.trusted_recipient_scope
                    ),
                    expected_allowed_observable_kinds=(
                        expected_allowed_observable_kinds
                    ),
                    expected_promotion_policy_sha256=(expected_promotion_policy_sha256),
                    durable_outbox=durable_outbox,
                )
            )
        except ObservableApprovalBusyError:
            raise ThreatHintV2AcceptanceBusyError() from None
        except ObservableApprovalConsumptionError:
            raise ThreatHintV2AcceptanceUnavailableError() from None
        return service

    # pylint: disable-next=too-many-arguments
    def accept(
        self,
        envelope_wire: bytes,
        bundle_wire: bytes,
        approval_wire: bytes,
        *,
        report_nonce: bytes,
        current_time: int,
    ) -> ThreatHintV2AcceptanceReceipt:
        """Verify every check from raw wires, then consume exactly once.

        The verified preflight runs first and consumes nothing; only its
        success reaches the final durable consumption step. The expected
        approval identifier and observable commitment from the verified
        preflight are re-checked inside the consumption call path before the
        atomic ledger insert, so no mismatch can be discovered after a commit.
        """
        if self._governed:
            try:
                self._consumption.precheck_governance(
                    approval_wire,
                    bundle_wire,
                    report_nonce=report_nonce,
                    current_time=current_time,
                )
            except ObservableApprovalGovernanceUnavailableError:
                raise ThreatHintV2AcceptanceUnavailableError() from None
            except ObservableApprovalBusyError:
                raise ThreatHintV2AcceptanceBusyError() from None
            except (
                ObservableApprovalGovernanceCandidateError,
                ObservableApprovalConsumptionError,
            ):
                raise ThreatHintV2AcceptanceError() from None
        try:
            verified = self._verified_preflight.preflight(
                envelope_wire,
                bundle_wire,
                approval_wire,
                report_nonce=report_nonce,
                current_time=current_time,
            )
        except ThreatHintV2VerifiedPreflightBusyError:
            raise ThreatHintV2AcceptanceBusyError() from None
        except ThreatHintV2VerifiedPreflightUnavailableError:
            raise ThreatHintV2AcceptanceUnavailableError() from None
        except ThreatHintV2VerifiedPreflightError:
            raise ThreatHintV2AcceptanceError() from None
        statement_wire: bytes | None = None
        if self._durable_outbox:
            statement_wire = _verified_statement_wire(
                envelope_wire,
                self._verified_preflight.trusted_network_id,
                verified.statement_digest,
            )
        try:
            consumed = (
                self._consumption._consume_expected(  # pylint: disable=protected-access
                    approval_wire,
                    bundle_wire,
                    report_nonce=report_nonce,
                    current_time=current_time,
                    expected_approval_id=verified.approval_id,
                    expected_observable_commitment=verified.observable_commitment,
                    statement_wire=statement_wire,
                )
            )
        except ObservableApprovalReplayError:
            raise ThreatHintV2AcceptanceReplayError() from None
        except ObservableApprovalBusyError:
            raise ThreatHintV2AcceptanceBusyError() from None
        except ObservableApprovalGovernanceCandidateError:
            raise ThreatHintV2AcceptanceError() from None
        except ObservableApprovalGovernanceUnavailableError:
            raise ThreatHintV2AcceptanceUnavailableError() from None
        except ObservableApprovalConsumptionError:
            raise ThreatHintV2AcceptanceUnavailableError() from None
        return _build_receipt(verified, consumed.consumed_at)


def _build_receipt(
    verified: ThreatHintV2VerifiedPreflightReceipt,
    consumed_at: int,
) -> ThreatHintV2AcceptanceReceipt:
    receipt = object.__new__(ThreatHintV2AcceptanceReceipt)
    object.__setattr__(receipt, "statement_digest", verified.statement_digest)
    object.__setattr__(receipt, "approval_id", verified.approval_id)
    object.__setattr__(receipt, "observable_commitment", verified.observable_commitment)
    object.__setattr__(receipt, "consumed_at", consumed_at)
    object.__setattr__(
        receipt,
        "raw_manifest_sha256_hex",
        verified.raw_manifest_sha256_hex,
    )
    object.__setattr__(receipt, "envelope_sha256_hex", verified.envelope_sha256_hex)
    object.__setattr__(
        receipt,
        "verifier_executable_sha256_hex",
        verified.verifier_executable_sha256_hex,
    )
    return receipt


def _verified_statement_wire(
    envelope_wire: bytes,
    trusted_network_id: str,
    expected_statement_digest: bytes,
) -> bytes:
    try:
        envelope = ThreatHintV2ProofEnvelope.parse_canonical(
            envelope_wire, trusted_network_id
        )
        statement_wire = envelope.parsed_statement.canonical_bytes
        statement_digest = envelope.parsed_statement.statement_digest()
    except (ThreatHintV2ProofEnvelopeError, ValueError):
        raise ThreatHintV2AcceptanceUnavailableError() from None
    if type(expected_statement_digest) is not bytes or not hmac.compare_digest(
        statement_digest, expected_statement_digest
    ):
        raise ThreatHintV2AcceptanceUnavailableError()
    return statement_wire
