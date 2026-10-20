"""TC ownership fixture. Contains no qdisc/filter syscall or command executor."""

from dataclasses import dataclass
from uuid import UUID, uuid4

from soc_agent.review.models import Hash
from soc_agent.security_ai.research.models import Frozen


class Attachment(Frozen):
    application_session: UUID
    capture_session: UUID
    attach_identity: UUID
    scope_digest: Hash
    program_sha256: Hash
    priority: int
    handle: int
    source: str = "TC_OWNERSHIP_FIXTURE_NOT_KERNEL"


@dataclass
class FixtureTC:
    """Existing qdisc/foreign filters survive every simulated start/stop/failure."""

    qdisc: str = "EXISTING_CLSACT_FIXTURE"

    def __post_init__(self):
        self.filters: dict[tuple[int, int], Attachment | str] = {(1, 1): "FOREIGN_FILTER"}

    def attach(self, application, run) -> Attachment:
        # Exclusive slots, no replace flag, no qdisc creation or deletion.
        handle = run.capture_session.int & 0xFFFFFFFF
        key = (49152, handle)
        if not handle or key in self.filters:
            raise ValueError("EBPF_TC_SLOT_CONFLICT")
        lease = Attachment(
            application_session=application.application_session,
            capture_session=run.capture_session,
            attach_identity=uuid4(),
            scope_digest=run.scope_digest,
            program_sha256=application.scope.program_sha256,
            priority=key[0],
            handle=key[1],
        )
        self.filters[key] = lease
        return lease

    def detach(self, expected: Attachment) -> None:
        key = (expected.priority, expected.handle)
        if self.filters.get(key) != expected:
            raise ValueError("EBPF_TC_OWNERSHIP_UNVERIFIED")
        del self.filters[key]
        if key in self.filters:
            raise ValueError("EBPF_TC_CLEANUP_UNVERIFIED")
