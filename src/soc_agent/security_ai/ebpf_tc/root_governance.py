"""Record independently pinned human policy/budget decisions in the existing chain.

Approval of a historical exact Binding does not authorize changed build bytes.
No installer, namespace helper, authentication, socket or Native executor exists here.
"""

import time
from pathlib import Path
from typing import Literal

from pydantic import Field

from soc_agent.security_ai.ebpf_tc.reassessment import Contract, Hash, Identity, digest, held_json
from soc_agent.security_ai.ebpf_tc.root_operations import RootBinding, RootPolicy
from soc_agent.security_ai.native_campaign import NativeCampaign, sha
from soc_agent.security_ai.operation_budget import (
    ALLOCATION_EVENT,
    DNS_ALLOCATION_EVENT,
    batch_root_limit,
    totals,
)


class RootAllocation(Contract):
    contract: Literal["SOC_BATCH3_ROOT_ALLOCATION_V1"] = "SOC_BATCH3_ROOT_ALLOCATION_V1"
    decision: Literal["APPROVED"]
    approver: Identity
    human_reference_sha: Hash
    approved_binding: RootBinding
    review_package_sha: Hash
    budget_sha: Hash
    baseline_sha: Hash
    ledger_tip_sha: Hash
    policy_record_sha: Hash
    batch: Literal["BATCH3"] = "BATCH3"
    previous_root_max: Literal[2] = 2
    root_max: Literal[3] = 3
    native_max: Literal[2] = 2
    campaign_root_max: Literal[10] = 10
    setup_allowance: Literal[1] = 1
    installation_allowance: Literal[2] = 2
    issued_at: int = Field(ge=0)
    expires_at: int = Field(gt=0)
    refund: Literal[False] = False
    authorize_root: Literal[False] = False
    authorize_native: Literal[False] = False


class RootDNSAllocation(RootAllocation):
    contract: Literal["SOC_BATCH3_ROOT_DNS_ALLOCATION_V1"] = "SOC_BATCH3_ROOT_DNS_ALLOCATION_V1"
    previous_root_max: Literal[3] = 3
    root_max: Literal[4] = 4
    dns_allowance: Literal[1] = 1
    previous_allocation_record_sha: Hash
    budget_only: Literal[True] = True
    authorize_dns_execution: Literal[False] = False


def _review(path: Path, pin: str) -> dict:
    value = held_json(path, pin)
    if value.get("contract") != "SOC_ROOT_POLICY_AND_NAMESPACE_BUDGET_REVIEW_V1":
        raise ValueError("ROOT_GOVERNANCE_REVIEW_CONTRACT")
    return value


def _validity(issued: int, expires: int) -> None:
    if not issued <= time.time() < expires or not 0 < expires - issued <= 86400:
        raise ValueError("ROOT_GOVERNANCE_VALIDITY")


def _tip(rows: list[dict]) -> str:
    return rows[-1].get("record_sha256", digest(rows[-1]))


def activate_policy(
    campaign,
    *,
    review_file: Path,
    review_sha: str,
    policy_file: Path,
    policy_sha: str,
    expected_tip: str,
) -> dict:
    review = _review(review_file, review_sha)
    policy = RootPolicy.model_validate(held_json(policy_file, policy_sha))
    if (
        campaign.batch != policy.binding.batch
        or policy.binding != RootBinding.model_validate(review["binding"])
        or policy.implementation_sha != review["policy_activation"]["implementation_sha256"]
        or policy.budget_sha != sha(campaign.budget_body)
        or policy.baseline_sha != sha(campaign.baseline_body)
        or expected_tip != review["execution_request"]["ledger_tip_sha256"]
    ):
        raise ValueError("ROOT_POLICY_REVIEW_BINDING")

    def append(rows):
        _validity(policy.issued_at, policy.expires_at)
        if any(
            r.get("event") == "ROOT_POLICY_ACTIVATED_V1"
            and (
                r.get("policy_sha256") == policy_sha
                or r.get("binding") == policy.binding.model_dump()
            )
            for r in rows
        ):
            raise ValueError("ROOT_POLICY_ACTIVATION_REPLAY")
        if _tip(rows) != expected_tip:
            raise ValueError("ROOT_GOVERNANCE_STALE_LEDGER")
        return dict(
            event="ROOT_POLICY_ACTIVATED_V1",
            policy_sha256=policy_sha,
            policy=policy.model_dump(),
            binding=policy.binding.model_dump(),
            review_package_sha=review_sha,
            authorizes_execution=False,
            activation_scope="APPROVED_EXACT_BINDING_ONLY_NOT_CHANGED_ARTIFACT",
        )

    return NativeCampaign._locked(campaign, append)


def allocate_root(
    campaign, *, review_file: Path, review_sha: str, allocation_file: Path, allocation_sha: str
) -> dict:
    review = _review(review_file, review_sha)
    allocation = RootAllocation.model_validate(held_json(allocation_file, allocation_sha))
    a = allocation
    if (
        a.approved_binding != RootBinding.model_validate(review["binding"])
        or a.review_package_sha != review_sha
        or a.budget_sha != sha(campaign.budget_body)
        or a.baseline_sha != sha(campaign.baseline_body)
        or review["budget"]["B"]["proposed_batch3_total_root_cap"] != a.root_max
        or campaign.batch != a.batch
    ):
        raise ValueError("ROOT_ALLOCATION_REVIEW_BINDING")

    def append(rows):
        _validity(a.issued_at, a.expires_at)
        if any(r.get("event") == ALLOCATION_EVENT for r in rows):
            raise ValueError("ROOT_ALLOCATION_REPLAY_OR_DUPLICATE")
        if _tip(rows) != a.ledger_tip_sha:
            raise ValueError("ROOT_GOVERNANCE_STALE_LEDGER")
        policies = [
            r
            for r in rows
            if r.get("record_sha256") == a.policy_record_sha
            and r.get("event") == "ROOT_POLICY_ACTIVATED_V1"
        ]
        if len(policies) != 1:
            raise ValueError("ROOT_ALLOCATION_POLICY_RECORD")
        p = RootPolicy.model_validate(policies[0]["policy"])
        _validity(p.issued_at, p.expires_at)
        if (
            p.binding != a.approved_binding
            or p.approver != a.approver
            or p.human_reference_sha != a.human_reference_sha
            or a.expires_at > p.expires_at
            or a.issued_at < p.issued_at
        ):
            raise ValueError("ROOT_ALLOCATION_POLICY_BINDING")
        # A grant changes only a cap, never usage or the immutable budget anchor.
        return dict(
            event=ALLOCATION_EVENT,
            allocation=a.model_dump(),
            allocation_receipt_sha=allocation_sha,
            allocation_payload_sha=digest(a.model_dump()),
            campaign_usage=totals(rows),
            batch_usage=totals(rows, batch=a.batch),
            old_root_cap=2,
            new_root_cap=3,
            authorizes_execution=False,
        )

    return NativeCampaign._locked(campaign, append)


def apply_packet(campaign, packet: dict) -> dict:
    """Existing native-recovery reassess dispatch, never a privileged command runner."""
    if packet.get("kind") == "DEVELOPMENT_METERING_POLICY_ACTIVATION":
        from soc_agent.security_ai.ebpf_tc.development_session import activate

        return activate(campaign, packet)
    if packet.get("kind") == "ROOT_POLICY_ACTIVATION":
        return activate_policy(
            campaign,
            review_file=Path(packet["review_file"]),
            review_sha=packet["review_sha"],
            policy_file=Path(packet["policy_file"]),
            policy_sha=packet["policy_sha"],
            expected_tip=packet["expected_tip"],
        )
    if packet.get("kind") == "ROOT_BATCH_ALLOCATION":
        return allocate_root(
            campaign,
            review_file=Path(packet["review_file"]),
            review_sha=packet["review_sha"],
            allocation_file=Path(packet["allocation_file"]),
            allocation_sha=packet["allocation_sha"],
        )
    if packet.get("kind") == "ROOT_DNS_ALLOCATION":
        return allocate_dns_root(
            campaign,
            review_file=Path(packet["review_file"]),
            review_sha=packet["review_sha"],
            allocation_file=Path(packet["allocation_file"]),
            allocation_sha=packet["allocation_sha"],
        )
    raise ValueError("ROOT_GOVERNANCE_PACKET_KIND")


def allocate_dns_root(
    campaign, *, review_file: Path, review_sha: str, allocation_file: Path, allocation_sha: str
) -> dict:
    """One append-only 3→4 amendment; no historical grant/charge replacement."""
    review = _review(review_file, review_sha)
    a = RootDNSAllocation.model_validate(held_json(allocation_file, allocation_sha))
    if (
        a.approved_binding != RootBinding.model_validate(review["binding"])
        or a.review_package_sha != review_sha
        or a.budget_sha != sha(campaign.budget_body)
        or a.baseline_sha != sha(campaign.baseline_body)
        or review["budget"]["DNS"]["proposed_batch3_total_root_cap"] != 4
        or review["budget"]["DNS"]["human_reference_sha"] != a.human_reference_sha
        or review["budget"]["DNS"]["approver"] != a.approver
        or campaign.batch != a.batch
    ):
        raise ValueError("ROOT_DNS_ALLOCATION_REVIEW_BINDING")

    def append(rows):
        _validity(a.issued_at, a.expires_at)
        if any(r.get("event") == DNS_ALLOCATION_EVENT for r in rows):
            raise ValueError("ROOT_DNS_ALLOCATION_REPLAY")
        if _tip(rows) != a.ledger_tip_sha:
            raise ValueError("ROOT_GOVERNANCE_STALE_LEDGER")
        bases = [r for r in rows if r.get("event") == ALLOCATION_EVENT]
        policies = [
            r
            for r in rows
            if r.get("event") == "ROOT_POLICY_ACTIVATED_V1"
            and r.get("record_sha256") == a.policy_record_sha
        ]
        if (
            len(bases) != 1
            or len(policies) != 1
            or bases[0].get("record_sha256") != a.previous_allocation_record_sha
            or batch_root_limit(rows, campaign.budget, a.batch) != 3
            or a.expires_at > bases[0]["allocation"]["expires_at"]
            or bases[0]["allocation"]["approved_binding"] != a.approved_binding.model_dump()
            or bases[0]["allocation"]["policy_record_sha"] != a.policy_record_sha
        ):
            raise ValueError("ROOT_DNS_ALLOCATION_PARENT")
        p = RootPolicy.model_validate(policies[0]["policy"])
        _validity(p.issued_at, p.expires_at)
        if (
            p.binding != a.approved_binding
            or p.approver != a.approver
            or not p.issued_at <= a.issued_at < a.expires_at <= p.expires_at
        ):
            raise ValueError("ROOT_DNS_ALLOCATION_POLICY_BINDING")
        return dict(
            event=DNS_ALLOCATION_EVENT,
            allocation=a.model_dump(),
            allocation_receipt_sha=allocation_sha,
            allocation_payload_sha=digest(a.model_dump()),
            old_root_cap=3,
            new_root_cap=4,
            campaign_usage=totals(rows),
            batch_usage=totals(rows, batch=a.batch),
            authorizes_execution=False,
            binding_scope="PARENT_BUDGET_PROVENANCE_NOT_NEW_EXECUTION_APPROVAL",
        )

    return NativeCampaign._locked(campaign, append)
