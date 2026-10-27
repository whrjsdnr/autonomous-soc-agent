"""Shared accounting for legacy Native reservations and opt-in Root-only work.

No refunds: cancellation and failure close a reservation but retain its charge.
This module never grants permission or invokes an executor.
"""

import hashlib
import json
import time
from typing import Literal

Operation = Literal[
    "ROOT_SETUP", "ROOT_INSTALL", "ROOT_DNS_DIAGNOSTIC", "NATIVE_DIAGNOSTIC", "ROOT_AND_NATIVE"
]
COSTS = {
    "ROOT_SETUP": (0, 1),
    "ROOT_INSTALL": (0, 1),
    "ROOT_DNS_DIAGNOSTIC": (0, 1),
    "NATIVE_DIAGNOSTIC": (1, 0),
    "ROOT_AND_NATIVE": (1, 1),
}
ROOT_RESERVED = "ROOT_OPERATION_RESERVED_V1"
ROOT_FINISHED = "ROOT_OPERATION_FINISHED_V1"


ALLOCATION_EVENT = "ROOT_BATCH_ALLOCATION_RECORDED_V1"
DNS_ALLOCATION_EVENT = "ROOT_BATCH_DNS_ALLOCATION_RECORDED_V1"


def batch_root_limit(rows: list[dict], budget: dict, batch: str) -> int:
    """Only the one reviewed Batch 3 allocation can enlarge the immutable base cap."""
    grants = [
        r
        for r in rows
        if r.get("event") == ALLOCATION_EVENT and r.get("allocation", {}).get("batch") == batch
    ]
    if not grants:
        if any(r.get("event") == DNS_ALLOCATION_EVENT for r in rows):
            raise ValueError("ROOT_DNS_ALLOCATION_PARENT")
        return budget["root_per_batch_max"]
    if len(grants) != 1 or batch != "BATCH3":
        raise ValueError("ROOT_ALLOCATION_DUPLICATE_OR_BATCH")
    event = grants[0]
    grant = event["allocation"]
    payload = (json.dumps(grant, sort_keys=True, separators=(",", ":")) + "\n").encode()
    expected = dict(
        contract="SOC_BATCH3_ROOT_ALLOCATION_V1",
        decision="APPROVED",
        batch="BATCH3",
        previous_root_max=2,
        root_max=3,
        native_max=2,
        campaign_root_max=10,
        setup_allowance=1,
        installation_allowance=2,
        refund=False,
        authorize_root=False,
        authorize_native=False,
    )
    if (
        hashlib.sha256(payload).hexdigest() != event.get("allocation_payload_sha")
        or any(type(grant.get(k)) is not type(v) or grant[k] != v for k, v in expected.items())
        or budget["root_installations_max"] != 10
        or budget["root_per_batch_max"] != 2
    ):
        raise ValueError("ROOT_ALLOCATION_INVALID")
    amendments = [r for r in rows if r.get("event") == DNS_ALLOCATION_EVENT]
    limit = 3
    if amendments:
        if len(amendments) != 1:
            raise ValueError("ROOT_DNS_ALLOCATION_DUPLICATE")
        amendment = amendments[0]
        a = amendment["allocation"]
        expected_dns = expected | dict(
            contract="SOC_BATCH3_ROOT_DNS_ALLOCATION_V1",
            previous_root_max=3,
            root_max=4,
            dns_allowance=1,
            budget_only=True,
            authorize_dns_execution=False,
        )
        body = (json.dumps(a, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if (
            any(type(a.get(k)) is not type(v) or a[k] != v for k, v in expected_dns.items())
            or hashlib.sha256(body).hexdigest() != amendment.get("allocation_payload_sha")
            or a.get("previous_allocation_record_sha") != event.get("record_sha256")
            or not grant["issued_at"] <= a["issued_at"] < a["expires_at"] <= grant["expires_at"]
        ):
            raise ValueError("ROOT_DNS_ALLOCATION_INVALID")
        if a["issued_at"] <= time.time() < a["expires_at"]:
            limit = 4
    if not grant["issued_at"] <= time.time() < grant["expires_at"]:
        return budget["root_per_batch_max"]  # Never refunds charges or extends validity.
    return limit


def totals(rows: list[dict], *, batch: str | None = None) -> tuple[int, int]:
    native = root = 0
    for row in rows:
        if batch is not None and row.get("batch") != batch:
            continue
        if row.get("event") == "NATIVE_ATTEMPT_RESERVED":
            cost = row["root_cost"]
            if type(cost) is not int or cost not in (0, 1):
                raise ValueError("OPERATION_LEDGER_COST")
            native += 1
            root += cost
        elif row.get("event") == ROOT_RESERVED:
            if row.get("operation") not in (
                "ROOT_SETUP",
                "ROOT_INSTALL",
                "ROOT_DNS_DIAGNOSTIC",
            ) or (
                type(row.get("root_cost")) is not int
                or row["root_cost"] != 1
                or type(row.get("native_cost")) is not int
                or row["native_cost"] != 0
            ):
                raise ValueError("OPERATION_LEDGER_COST")
            root += 1
    return native, root


def guard_reservation(rows: list[dict], event: dict, budget: dict, batch: str | None) -> None:
    """Run under the existing campaign lock, including legacy admission paths."""
    if event["event"] not in (ROOT_RESERVED, "NATIVE_ATTEMPT_RESERVED"):
        return
    pending = [r for r in rows if r.get("event") == ROOT_RESERVED]
    for prior in pending:
        finished = [
            r
            for r in rows
            if r.get("event") == ROOT_FINISHED and r.get("attempt_id") == prior["attempt_id"]
        ]
        if len(finished) != 1 or finished[0].get("outcome") not in (
            "SUCCEEDED",
            "CANCELLED_BEFORE_EXECUTION",
        ):
            raise ValueError("ROOT_OPERATION_UNRESOLVED")
    native, root = totals(rows)
    dn, dr = (1, event["root_cost"]) if event["event"] == "NATIVE_ATTEMPT_RESERVED" else (0, 1)
    if (
        budget["native_used"] + native + dn > budget["native_max"]
        or budget["root_installations_used"] + root + dr > budget["root_installations_max"]
    ):
        raise ValueError("NATIVE_CAMPAIGN_BUDGET_EXHAUSTED")
    if batch is not None:
        bn, br = totals(rows, batch=batch)
        limit = batch_root_limit(rows, budget, batch)
        dns = sum(
            r.get("event") == ROOT_RESERVED
            and r.get("operation") == "ROOT_DNS_DIAGNOSTIC"
            and r.get("batch") == batch
            for r in rows
        )
        new_dns = int(event.get("operation") == "ROOT_DNS_DIAGNOSTIC")
        if new_dns and limit != 4:
            raise ValueError("ROOT_DNS_ALLOCATION_REQUIRED")
        if limit in (3, 4):
            setups = sum(
                r.get("event") == ROOT_RESERVED
                and r.get("operation") == "ROOT_SETUP"
                and r.get("batch") == batch
                for r in rows
            )
            new_setup = int(
                event["event"] == ROOT_RESERVED and event.get("operation") == "ROOT_SETUP"
            )
            if (
                setups + new_setup > 1
                or dns + new_dns > 1
                or br - setups - dns + dr - new_setup - new_dns > 2
            ):
                raise ValueError("STABILIZATION_ROOT_SUBALLOCATION_EXHAUSTED")
        if bn + dn > budget["native_per_batch_max"] or br + dr > limit:
            raise ValueError("STABILIZATION_BATCH_BUDGET_EXHAUSTED")
    event.update(
        native_used=budget["native_used"] + native + dn,
        root_installations_used=budget["root_installations_used"] + root + dr,
    )
