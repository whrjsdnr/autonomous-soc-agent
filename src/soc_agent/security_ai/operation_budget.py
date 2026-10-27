"""Shared accounting for legacy Native reservations and opt-in Root-only work.

No refunds: cancellation and failure close a reservation but retain its charge.
This module never grants permission or invokes an executor.
"""

from typing import Literal

Operation = Literal["ROOT_SETUP", "ROOT_INSTALL", "NATIVE_DIAGNOSTIC", "ROOT_AND_NATIVE"]
COSTS = {
    "ROOT_SETUP": (0, 1),
    "ROOT_INSTALL": (0, 1),
    "NATIVE_DIAGNOSTIC": (1, 0),
    "ROOT_AND_NATIVE": (1, 1),
}
ROOT_RESERVED = "ROOT_OPERATION_RESERVED_V1"
ROOT_FINISHED = "ROOT_OPERATION_FINISHED_V1"


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
            if row.get("operation") not in ("ROOT_SETUP", "ROOT_INSTALL") or (
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
        if bn + dn > budget["native_per_batch_max"] or br + dr > budget["root_per_batch_max"]:
            raise ValueError("STABILIZATION_BATCH_BUDGET_EXHAUSTED")
    event.update(
        native_used=budget["native_used"] + native + dn,
        root_installations_used=budget["root_installations_used"] + root + dr,
    )
