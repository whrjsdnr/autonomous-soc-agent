"""Sealed Continuous windows composed through unchanged Phase D evidence validators.

No VERIFIED string is trusted. Each rotation uses a fresh owned map, bounded
metadata and real PRE_ATTACH/POST_DETACH snapshots. No cross-window flow claim.
The Root peer authenticates transport; retained files alone remain declared evidence.
"""

from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import Field

from soc_agent.review.models import Hash
from soc_agent.security_ai.ebpf.clock import ClockSample
from soc_agent.security_ai.ebpf_tc.capture_evidence import assess_capture
from soc_agent.security_ai.ebpf_tc.window_evidence import COUNTERS
from soc_agent.security_ai.research.models import Frozen, digest
from soc_agent.security_ai.workflow_models import TCXAnalysisJob


class CaptureSeal(Frozen):
    contract: str = "soc-continuous-seal:v1"
    namespace: str = Field(pattern=r"^net:\[[1-9][0-9]*\]$")
    session: UUID
    generation: int = Field(gt=0, strict=True)
    program_sha256: Hash
    policy_sha256: Hash
    release_manifest: Hash
    cpu_windows: tuple[dict, ...] = Field(min_length=2, max_length=256)
    clock_samples: tuple[dict, ...] = Field(min_length=6, max_length=6)
    callbacks: int = Field(ge=0, le=4096, strict=True)
    transport_dropped: int = Field(ge=0, strict=True)
    cleanup: str
    drain_result: int
    seal_sha256: Hash

    @property
    def identity(self):
        return digest(dict(session=str(self.session), generation=self.generation))

    def check(self):
        if self.contract != "soc-continuous-seal:v1" or self.seal_sha256 != digest(
            self.model_dump(mode="json", exclude={"seal_sha256"})
        ):
            raise ValueError("CONTINUOUS_CAPTURE_SEAL_DIGEST")
        count = len(self.cpu_windows) // 2
        if not 1 <= count <= 128 or len(self.cpu_windows) != count * 2:
            raise ValueError("CONTINUOUS_CAPTURE_CPU_BOUND")
        for i, row in enumerate(self.cpu_windows):
            if (
                row["cpu"] != i % count
                or row["possible_cpus"] != count
                or row["phase"] != ("PRE_ATTACH" if i < count else "POST_DETACH")
                or not 0 < row["before_ns"] <= row["after_ns"]
                or set(row["counters"]) != set(COUNTERS)
                or any(
                    type(v) is not int or not 0 <= v < 2**64 - 1 for v in row["counters"].values()
                )
                or row["counters"]["observed"]
                != sum(v for k, v in row["counters"].items() if k != "observed")
            ):
                raise ValueError("CONTINUOUS_CAPTURE_CPU_SCHEMA")
            if i % count and (row["before_ns"], row["after_ns"]) != (
                self.cpu_windows[i - 1]["before_ns"],
                self.cpu_windows[i - 1]["after_ns"],
            ):
                raise ValueError("CONTINUOUS_CAPTURE_CPU_LOOKUP")
        for i, row in enumerate(self.clock_samples):
            ClockSample.model_validate({k: row[k] for k in ("before_ns", "wall_ns", "after_ns")})
            if row["phase"] != (1 if i < 3 else 2) or row["generation"] != self.generation:
                raise ValueError("CONTINUOUS_CAPTURE_CLOCK_EPOCH")
        if self.session != uuid5(NAMESPACE_URL, str(self.generation)):
            raise ValueError("CONTINUOUS_CAPTURE_SESSION_EPOCH")
        if self.cpu_windows[-1]["after_ns"] - self.cpu_windows[0]["before_ns"] > 300_000_000_000:
            raise ValueError("CONTINUOUS_CAPTURE_WINDOW_BOUND")


def sealed_jobs(seal: CaptureSeal, events, *, origin="REAL_NATIVE", profiles=("quality", "edge")):
    """Recompute features and exact evidence before model-action admission, no model call."""
    from soc_agent.continuous.native_windows import NativeWindows

    seal.check()
    if len(events) > 4096:
        raise ValueError("CONTINUOUS_CAPTURE_EVENT_BOUND")
    windows = NativeWindows(seal.namespace, str(seal.session))
    intervals = {}
    rows = []
    for ordinal, event in enumerate(events, 1):
        if (
            event.generation != seal.generation
            or event.session_id != seal.session
            or event.program_sha256 != seal.program_sha256
            or event.ifindex != 1
            or event.hook != "INGRESS"
            or event.clock != "KERNEL_MONOTONIC_NS"
            or event.delivery_sequence != ordinal
        ):
            raise ValueError("CONTINUOUS_CAPTURE_EVENT_BINDING")
        item = intervals.setdefault(
            str(event.cpu), dict(received=0, first_ns=event.ns, last_ns=event.ns, last_sequence=0)
        )
        if event.cpu_sequence <= item["last_sequence"]:
            raise ValueError("CONTINUOUS_CAPTURE_EVENT_REPLAY")
        item.update(
            received=item["received"] + 1,
            first_ns=min(item["first_ns"], event.ns),
            last_ns=max(item["last_ns"], event.ns),
            last_sequence=event.cpu_sequence,
        )
        rows.extend(job.summary for job in windows.add(event))
    rows.extend(job.summary for job in windows.close())
    # Original diagnostic input validation bounds retained vectors to four. Split
    # projections, preserving the complete independently recomputed window evidence.
    plan = dict(
        session_id=str(seal.session),
        generation=seal.generation,
        program_sha256=seal.program_sha256,
        source_digest=seal.policy_sha256,
        net_namespace=seal.namespace,
        interface="lo",
        hook="INGRESS",
    )
    summary = dict(
        plan=plan,
        plan_digest=digest(plan),
        received=len(events),
        accepted=len(events),
        cpu_sequence=dict(intervals=intervals, unrepresented_attempts=0),
        clock=dict(domain="KERNEL_MONOTONIC_NS"),
        ordering=windows.ordering.snapshot(),
        queue_rejected=seal.transport_dropped,
        queue_discarded=0,
    )
    n = len(seal.cpu_windows) // 2
    totals = {k: sum(r["counters"][k] for r in seal.cpu_windows[n:]) for k in COUNTERS}
    counter = dict(
        generation=seal.generation, retrieval="SUCCESS", delivered=len(events), totals=totals
    )
    delivery = dict(
        generation=seal.generation,
        callbacks=seal.callbacks,
        delivered=len(events),
        budget_excluded=seal.transport_dropped,
        invalid=0,
        send_failed=0,
        drain_result=seal.drain_result,
    )
    error = None if seal.cleanup == "VERIFIED" else "CONTINUOUS_CAPTURE_CLEANUP_UNVERIFIED"
    if totals["disabled"] or any(r["last_sequence"] != r["received"] for r in intervals.values()):
        error = error or "CONTINUOUS_DISABLED_OR_CPU_ATTEMPT_GAP"
    capture = assess_capture(
        counter,
        delivery,
        summary,
        closed=True,
        error=error,
        source=1 if origin == "REAL_NATIVE" else 2,
        scope=dict(program_sha256=seal.program_sha256, approval_digest=seal.policy_sha256),
        cpu_windows=list(seal.cpu_windows),
        clock_samples=list(seal.clock_samples),
    )
    jobs = []
    for index in range(0, len(rows), 4):
        transport = dict(
            processing=summary | dict(feature_tail=rows[index : index + 4]),
            source="KERNEL_TCX_NATIVE"
            if origin == "REAL_NATIVE"
            else "ORDINARY_UID_PACKET_FIXTURE",
            capture_evidence=capture,
            counter_evidence=counter,
            delivery_accounting=delivery,
            cpu_windows=list(seal.cpu_windows),
            clock_samples=list(seal.clock_samples),
            terminal_closed_observed=True,
            drain_state=seal.cleanup,
            error=error,
            cleanup_error=error,
            continuous_window=dict(id=seal.identity, seal=seal.model_dump(mode="json")),
        )
        jobs.append(
            TCXAnalysisJob(
                kind="tcx_analysis",
                origin=origin,
                session=seal.session,
                namespace=seal.namespace,
                release_manifest=seal.release_manifest,
                profiles=profiles,
                result=dict(
                    tcx=dict(release_manifest_digest=seal.release_manifest, data_plane=transport)
                ),
            )
        )
    return jobs, capture


class CaptureWindows:
    """Bounded in-flight window; durable raw records are replayed before live receive.

    Identity is epoch+ordinal, not process lifetime or worker attempt. A reused
    sealed identity with different contents is rejected by durable storage.
    """

    def __init__(self, namespace, policy_sha256, profiles=("quality", "edge")):
        self.namespace = namespace
        self.policy_sha256 = policy_sha256
        self.profiles = profiles
        self.events = []
        self.generation = None
        self.last_capture = dict(status="UNKNOWN", reasons=["WINDOW_NOT_SEALED"])
        self.last_window = None
        self.sealed = set()
        self.abandoned = 0

    def accept(self, raw):
        from soc_agent.continuous.tcx_producer import decode

        if raw["kind"] == "native_tcx":
            event = decode(
                bytes.fromhex(raw["wire_hex"]),
                namespace=self.namespace,
                session=UUID(raw["session"]),
                program=raw["program"],
                sequence=raw.get("window_sequence", raw["sequence"]),
            )
            if event.generation in self.sealed:
                raise ValueError("CONTINUOUS_SEALED_EPOCH_REPLAY")
            if self.generation not in (None, event.generation):
                if event.generation <= self.generation or event.delivery_sequence != 1:
                    raise ValueError("CONTINUOUS_UNSEALED_EPOCH_REPLAY")
                self.abandoned += 1
                self.events = []
                self.last_capture = dict(status="INCOMPLETE", reasons=["CRASH_PARTIAL_WINDOW"])
            if len(self.events) >= 4096:
                raise ValueError("CONTINUOUS_UNSEALED_EPOCH_OR_EVENT_BOUND")
            self.generation = event.generation
            # Delivery ordinal belongs to this retained capture window, not the
            # lifetime of a receiver connection. Immutable Kernel CPU sequence and
            # timestamp remain untouched; final per-CPU populations prove recovery.
            event = event.model_copy(update=dict(delivery_sequence=len(self.events) + 1))
            self.events.append(event)
            return [], None
        seal = CaptureSeal.model_validate(raw["seal"])
        if (
            seal.namespace != self.namespace
            or seal.policy_sha256 != self.policy_sha256
            or self.generation not in (None, seal.generation)
        ):
            raise ValueError("CONTINUOUS_CAPTURE_POLICY_SCOPE")
        if seal.generation in self.sealed or len(self.sealed) >= 10000:
            raise ValueError("CONTINUOUS_SEAL_REPLAY_OR_RETENTION_BOUND")
        jobs, capture = sealed_jobs(seal, self.events, profiles=self.profiles)
        self.sealed.add(seal.generation)
        self.last_capture, self.last_window = capture, seal.identity
        self.events = []
        self.generation = None
        return jobs, capture
