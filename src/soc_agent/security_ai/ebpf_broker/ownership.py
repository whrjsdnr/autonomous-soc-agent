"""Transactional ownership fixture. No Linux TC implementation is admitted in B-1."""

from collections.abc import Callable

from soc_agent.security_ai.ebpf_broker.contracts import BrokerPlan, Ownership
from soc_agent.security_ai.ebpf_native.contracts import RunIdentity


class Registry:
    def __init__(self):
        self.qdisc = "clsact"
        self.filters: dict[tuple[str, int, int, int], Ownership | str] = {
            ("INGRESS", 0, 1, 1): "FOREIGN_INGRESS",
            ("EGRESS", 0, 2, 2): "FOREIGN_EGRESS",
        }
        self.next_program_id = 100
        self.pending_owner: Ownership | None = None

    def snapshot(self) -> dict:
        return dict(
            qdisc=self.qdisc,
            filters={
                str(k): v.model_dump(mode="json") if isinstance(v, Ownership) else v
                for k, v in sorted(self.filters.items())
            },
        )

    @staticmethod
    def key(owner: Ownership) -> tuple[str, int, int, int]:
        return owner.hook, owner.chain, owner.priority, owner.handle

    def attach(self, plan: BrokerPlan, run: RunIdentity, record: Callable) -> Ownership:
        if self.qdisc != "clsact":
            raise ValueError("BROKER_EXISTING_QDISC_UNSUPPORTED")
        scope = plan.application.scope
        handle = run.capture_session.int & 0xFFFFFFFF
        key = scope.hook, 0, 49152, handle
        if not handle or key in self.filters:
            raise ValueError("BROKER_FILTER_COLLISION")
        before = self.snapshot()
        record("ATTACH_REQUESTED", before=before, run=run.model_dump(mode="json"))
        owner = Ownership(
            owner_session=plan.application.application_session,
            capture_session=run.capture_session,
            generation=run.generation,
            namespace=scope.net_namespace,
            ifindex=scope.ifindex,
            hook=scope.hook,
            handle=handle,
            program_id=self.next_program_id,
            program_tag=scope.program_sha256[:16],
            program_sha256=scope.program_sha256,
        )
        self.next_program_id += 1
        self.pending_owner = owner
        self.filters[key] = owner
        try:
            # Read back the complete identity, not just the chosen filter handle.
            if self.filters.get(key) != owner or self.qdisc != before["qdisc"]:
                raise ValueError("BROKER_ATTACH_READBACK_FAILED")
            record(
                "ATTACH_VERIFIED", ownership=owner.model_dump(mode="json"), after=self.snapshot()
            )
        except BaseException:
            # Roll back only when identity still proves this transaction owns the slot.
            if self.filters.get(key) == owner:
                del self.filters[key]
                self.pending_owner = None
            raise
        self.pending_owner = None
        return owner

    def detach(self, owner: Ownership, record: Callable) -> None:
        key = self.key(owner)
        if self.qdisc != owner.qdisc_type or self.filters.get(key) != owner:
            raise ValueError("BROKER_HOOK_OWNERSHIP_MISMATCH")
        before = self.snapshot()
        record("DETACH_REQUESTED", ownership=owner.model_dump(mode="json"), before=before)
        del self.filters[key]
        after = self.snapshot()
        expected = dict(before["filters"])
        del expected[str(key)]
        if after != dict(qdisc=before["qdisc"], filters=expected):
            raise ValueError("BROKER_FOREIGN_TC_PRESERVATION_FAILED")
        # If recording fails here, callers retain the owner and report cleanup UNVERIFIED.
        record("DETACH_VERIFIED", ownership=owner.model_dump(mode="json"), after=after)
