"""Prepared-only Native collector and bounded file-fixture ring delivery.

Reuses Network14 arithmetic, not Zeek provenance/admission. No loader or model worker.
"""

import json
import math
import os
import time
from collections import deque
from pathlib import Path

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.security_ai.collectors.packet_input import Packet
from soc_agent.security_ai.collectors.packet_producer import FlowAssembly
from soc_agent.security_ai.ebpf.checkpoint import CheckpointFailure, CheckpointWriter
from soc_agent.security_ai.ebpf.clock import ClockContract, EventOrdering, OrderedEvent
from soc_agent.security_ai.ebpf.models import Counters, Event, Plan
from soc_agent.security_ai.ebpf.ring import decode
from soc_agent.security_ai.research.models import digest


class EBPFCollector:
    def __init__(self, directory: Path, plan: Plan):
        self.directory, self.plan = directory.absolute(), plan
        self.state = "IDLE"
        self.last_error: str | None = None
        self.queue: deque[Event] = deque()
        self.queue_peak = self.received = self.accepted = self.dns_candidates = 0
        self.discarded = self.overflow_rejected = 0
        self.discard_reasons = dict(
            REORDER_REJECT=0, QUEUE_REJECT=0, ERROR_PENDING_ABORT=0, POST_ERROR_POLICY_DISCARD=0
        )
        self.flow = FlowAssembly(str(plan.session_id))
        self.cpu_sequences: dict[int, int] = {}
        self.attempt_gaps = 0
        self.sequence_examples: list[dict[str, int | str]] = []
        self.counter_snapshots: dict[int, Counters] = {}
        self.loss: int | None = None
        self.store: RuntimeStore | None = None
        self.chain = digest(dict(plan=plan.identity))
        self.deadline: float | None = None
        self.last_processing: float | None = None
        self.clock_contract: ClockContract | None = None
        self.ordering = EventOrdering()
        self.post_error_discarded = 0
        self.checkpoint_writer: CheckpointWriter | None = None
        self.stage_timing = {
            name: dict(calls=0, total_ns=0, max_ns=0)
            for name in ("clock_reordering", "flow_reconstruction", "audit_checkpoint")
        }

    def _duration(self, name: str, started: int) -> None:
        elapsed = time.perf_counter_ns() - started
        row = self.stage_timing[name]
        row["calls"] += 1
        row["total_ns"] += elapsed
        row["max_ns"] = max(row["max_ns"], elapsed)

    async def prepare(self) -> dict:
        return self.prepare_metadata()

    def prepare_metadata(self) -> dict:
        if os.geteuid() == 0 or self.state != "IDLE":
            raise ValueError("EBPF_PREPARE_DENIED")
        create_private_directory(self.directory)
        self.store = RuntimeStore.create(
            self.directory,
            RuntimeConfig(
                incident_id=self.plan.session_id,
                repeated_failures=5,
                multiple_accounts=3,
                assessment_mode="READ_ONLY",
            ),
        )
        with self.store.database.transaction() as db:
            db.execute("CREATE TABLE ebpf_checkpoint(value TEXT NOT NULL,digest TEXT NOT NULL)")
            self.store._audit(
                db,
                "EBPF_PREPARED",
                dict(plan=self.plan.model_dump(mode="json"), plan_digest=self.plan.identity),
            )
        self.state = "NATIVE_HOOK_PENDING"
        self.checkpoint()
        return self.snapshot()

    async def start(self) -> dict:
        # There is deliberately no path from Python/GUI to a BPF loader/TC hook.
        raise ValueError("EBPF_NATIVE_HOOK_APPROVAL_REQUIRED")

    def begin_fixture(self, monotonic: float) -> None:
        if self.plan.origin != "EBPF_TC_FIXTURE" or self.state != "NATIVE_HOOK_PENDING":
            raise ValueError("EBPF_FIXTURE_SCOPE_REQUIRED")
        if not math.isfinite(monotonic) or monotonic < 0:
            raise ValueError("EBPF_PROCESSING_CLOCK_INVALID")
        self.last_processing = monotonic
        self.state = "FIXTURE_ACTIVE"
        self.deadline = monotonic + self.plan.duration_seconds

    def begin_metadata_stream(self, monotonic: float, clock: ClockContract) -> None:
        if (
            self.state != "NATIVE_HOOK_PENDING"
            or clock.session_id != self.plan.session_id
            or clock.domain != self.plan.clock
        ):
            raise ValueError("TCX_CLOCK_SESSION_SCOPE")
        if not math.isfinite(monotonic) or monotonic < 0:
            raise ValueError("EBPF_PROCESSING_CLOCK_INVALID")
        self.clock_contract = clock
        self.flow = FlowAssembly(
            digest(
                dict(
                    session=str(self.plan.session_id),
                    generation=self.plan.generation,
                    source=self.plan.identity,
                    policy="TCX_C3_BOUNDED_EVENT_ORDER_V1",
                    clock=clock.domain,
                )
            ),
            event_watermark=True,
            compact=True,
        )
        self.last_processing = monotonic
        self.deadline = monotonic + self.plan.duration_seconds
        self.state = "METADATA_STREAM_ACTIVE"

    def end_metadata_stream(self, reason: str) -> None:
        if self.flow.closed:
            return
        if self.state == "ERROR":
            self.discard_reasons["ERROR_PENDING_ABORT"] += len(self.queue)
            self.discarded += len(self.queue)
            self.queue.clear()
        while self.queue and self.state == "METADATA_STREAM_ACTIVE":
            self.drain(final=True)
        self.flow.finish("INCOMPLETE" if self.attempt_gaps else reason)
        for flow in self.flow.finalized:
            flow.pop("packets", None)
            if self.attempt_gaps:
                flow["eligible"] = False
        self.state = "ERROR" if self.last_error else "STOPPED"
        self.request_checkpoint()

    def fail(self, code: str) -> None:
        self.state, self.last_error = "ERROR", self.last_error or code
        if self.store:
            try:
                self.request_checkpoint()
            except CheckpointFailure as audit_error:
                raise ValueError(code) from audit_error
        raise ValueError(code)

    def _observe_cpu_sequence(self, event: Event, *, discard: bool = False) -> None:
        """CPU sequence counts observed skb attempts, not emitted ring records.

        Native forward gaps are incomplete observation evidence, not proof of a
        broken authenticated data channel. Reuse still stops feature processing.
        """
        previous = self.cpu_sequences.get(event.cpu, 0)
        if len(self.cpu_sequences) >= 128 and event.cpu not in self.cpu_sequences:
            self.fail("EBPF_CPU_STATE_LIMIT")
        gap = event.cpu_sequence - previous - 1
        if gap != 0 and len(self.sequence_examples) < 8:
            self.sequence_examples.append(
                dict(
                    cpu=event.cpu,
                    previous=previous,
                    actual=event.cpu_sequence,
                    delivery_sequence=event.delivery_sequence,
                    kind="FORWARD_ATTEMPT_GAP" if gap > 0 else "REUSE_OR_REGRESSION",
                )
            )
        if gap < 0 or gap > 0 and self.clock_contract is None:
            if not discard:
                self.fail("EBPF_CPU_SEQUENCE_GAP_OR_REUSE")
        if gap > 0:
            self.attempt_gaps += gap
        self.cpu_sequences[event.cpu] = max(previous, event.cpu_sequence)

    def ingest(self, raw: bytes, *, monotonic: float) -> None:
        if self.state not in {"FIXTURE_ACTIVE", "METADATA_STREAM_ACTIVE"}:
            raise ValueError("EBPF_INPUT_NOT_ACTIVE")
        if (
            not math.isfinite(monotonic)
            or self.last_processing is None
            or monotonic < self.last_processing
        ):
            self.fail("EBPF_PROCESSING_CLOCK_INVALID")
        self.last_processing = monotonic
        if self.deadline is None or monotonic >= self.deadline:
            self.fail("EBPF_SESSION_DEADLINE")
        if self.received >= self.plan.event_limit:
            self.fail("EBPF_EVENT_LIMIT")
        try:
            e = decode(raw, self.plan, self.received + 1)
        except ValueError:
            self.fail("EBPF_EVENT_SCHEMA_REJECTED")
        if (e.generation, e.ifindex, e.hook) != (
            self.plan.generation,
            self.plan.ifindex,
            self.plan.hook,
        ):
            self.fail("EBPF_SOURCE_IDENTITY_MISMATCH")
        self._observe_cpu_sequence(e)
        self.received += 1
        if self.clock_contract is not None:
            started = time.perf_counter_ns()
            try:
                self.ordering.observe(e)
            except ValueError as error:
                self.discard_reasons["REORDER_REJECT"] += 1
                self.discarded += 1
                self.fail(str(error))
            finally:
                self._duration("clock_reordering", started)
        if len(self.queue) >= self.plan.queue_capacity:
            self.overflow_rejected += 1
            self.discard_reasons["QUEUE_REJECT"] += 1
            self.discarded += 1
            self.fail("EBPF_QUEUE_OVERFLOW_CAPTURE_GAP")
        self.queue.append(e)
        self.queue_peak = max(self.queue_peak, len(self.queue))

    def drain(self, limit: int = 32, *, final: bool = False) -> None:
        if self.state not in {"FIXTURE_ACTIVE", "METADATA_STREAM_ACTIVE"} or not 1 <= limit <= 32:
            raise ValueError("EBPF_DRAIN_DENIED")
        processed = 0
        for _ in range(min(limit, len(self.queue))):
            e = (
                min(self.queue, key=lambda row: (row.ns, row.sequence))
                if self.clock_contract
                else self.queue[0]
            )
            if (
                self.clock_contract
                and not final
                and e.ns > self.ordering.maximum - self.ordering.lateness_ns
            ):
                break
            if self.clock_contract is None and (
                e.clock != "FIXTURE_PCAP_EVENT_NS" or e.timestamp_ns % 1000
            ):
                self.fail("EBPF_CLOCK_PARITY_UNVERIFIED")
            sec, ns = divmod(e.timestamp_ns, 10**9)
            try:
                p = (
                    e
                    if self.clock_contract is not None
                    else Packet(
                        sequence=self.accepted + 1,
                        seconds=sec,
                        microseconds=ns // 1000,
                        frame_length=e.frame_length,
                        captured_length=e.frame_length,
                        kind=e.protocol,
                        source=e.source,
                        destination=e.destination,
                        source_port=e.source_port,
                        destination_port=e.destination_port,
                        ip_length=e.ip_length,
                        tcp_flags=e.tcp_flags,
                    )
                )
                if self.clock_contract:
                    # Receive sequence stays on the event/receipt. The shared flow
                    # assembler consumes its own contiguous sorted-input sequence.
                    p = OrderedEvent(e, self.accepted + 1)
                started = time.perf_counter_ns()
                try:
                    self.flow.add(p)
                finally:
                    self._duration("flow_reconstruction", started)
                if self.attempt_gaps:
                    for flow in self.flow.finalized:
                        flow["eligible"] = False
            except ValueError as error:
                self.fail(
                    "EBPF_CLOCK_INVALID"
                    if "CLOCK" in str(error) or "TIMESTAMP" in str(error)
                    else "EBPF_FLOW_METADATA_INTEGRITY_FAILED"
                )
            if self.clock_contract:
                self.ordering.reordered += int(e is not self.queue[0])
                self.ordering.emitted = e.ns
                self.queue.remove(e)
            else:
                self.queue.popleft()
            self.accepted += 1
            processed += 1
            self.dns_candidates += int(53 in (e.source_port, e.destination_port))
            self.chain = digest(dict(previous=self.chain, event=e.model_dump(mode="json")))
        if processed and self.accepted % 64 == 0:
            self.request_checkpoint()

    def discard_after_error(self, raw: bytes) -> None:
        """Validate and count delivery after processing stops; never infer again."""
        if self.state != "ERROR" or not self.flow.closed:
            raise ValueError("EBPF_DISCARD_STATE")
        event = decode(raw, self.plan, self.received + 1)
        if (event.generation, event.ifindex, event.hook) != (
            self.plan.generation,
            self.plan.ifindex,
            self.plan.hook,
        ):
            raise ValueError("EBPF_SOURCE_IDENTITY_MISMATCH")
        if (
            self.received >= self.plan.event_limit
            or event.cpu not in self.cpu_sequences
            and len(self.cpu_sequences) >= 128
        ):
            raise ValueError("EBPF_DISCARD_BUDGET")
        # Already failed processing cannot resume. Continue verifying ABI/source
        # and accounting discarded metadata so terminal/counter evidence can drain.
        self._observe_cpu_sequence(event, discard=True)
        self.received += 1
        self.discarded += 1
        self.post_error_discarded += 1
        self.discard_reasons["POST_ERROR_POLICY_DISCARD"] += 1
        self.ordering.cpu_counts[event.cpu] = self.ordering.cpu_counts.get(event.cpu, 0) + 1

    def counters(self, value: Counters) -> None:
        if self.state not in {"FIXTURE_ACTIVE", "METADATA_STREAM_ACTIVE"}:
            raise ValueError("EBPF_COUNTER_INPUT_DENIED")
        if value.generation != self.plan.generation or value.hook != self.plan.hook:
            self.fail("EBPF_COUNTER_SCOPE_MISMATCH")
        old = self.counter_snapshots.get(value.cpu)
        if old and any(
            getattr(value, k) < getattr(old, k)
            for k in (
                "observed",
                "emitted",
                "ring_lost",
                "unsupported",
                "malformed",
                "disabled",
                "budget",
            )
        ):
            self.fail("EBPF_COUNTER_RESET_OR_WRAP")
        if len(self.counter_snapshots) >= 128 and value.cpu not in self.counter_snapshots:
            self.fail("EBPF_COUNTER_CPU_LIMIT")
        self.counter_snapshots[value.cpu] = value
        self.loss = sum(v.ring_lost for v in self.counter_snapshots.values())
        if self.loss or value.malformed or value.budget or value.disabled or value.unsupported:
            self.fail("EBPF_COUNTER_LOSS_OR_UNSUPPORTED_WINDOW")

    async def stop(self) -> dict:
        if self.state in {"STOPPED", "ERROR", "RESTORED_NO_REATTACH"}:
            return self.snapshot()
        if self.state == "FIXTURE_ACTIVE":
            while self.queue:
                self.drain()
            self.flow.finish()
        self.state = "STOPPED"
        if self.store:
            self.checkpoint()
        for flow in self.flow.finalized:
            flow.pop("packets", None)
        return self.snapshot()

    def _summary(self) -> dict:
        features = [
            dict(
                flow_id=f["flow_id"],
                close_reason=f["close_reason"],
                packet_count=f["packet_count"],
                flow_completeness="CANDIDATE_TIMEOUT"
                if f["eligible"] and not self.attempt_gaps
                else "INCOMPLETE",
                feature_eligibility="BLOCKED_CAPTURE_INTEGRITY",
                values_digest=f["values_digest"],
                values=f["values"],
                feature_names=f["feature_names"],
                native_ai="BLOCKED",
            )
            for f in self.flow.finalized
        ]
        from soc_agent.security_ai.ebpf.eligibility import candidate_rca

        eligibility = candidate_rca(
            dict(
                feature_tail=features,
                finalized_count=len(features),
                cpu_sequence=dict(unrepresented_attempts=self.attempt_gaps),
                clock=self.clock_contract.snapshot() if self.clock_contract else None,
                ordering=self.ordering.snapshot() if self.clock_contract else None,
                last_error=self.last_error,
                queue_discarded=self.discarded,
                queue_rejected=self.overflow_rejected,
            )
        )
        return dict(
            candidate_eligibility=eligibility,
            plan=self.plan.model_dump(mode="json"),
            plan_digest=self.plan.identity,
            producer_version="TCX_METADATA_NETWORK14_C3"
            if self.clock_contract
            else "EBPF_FIXTURE_V1",
            state=self.state,
            clock=self.clock_contract.snapshot() if self.clock_contract else None,
            ordering=self.ordering.snapshot() if self.clock_contract else None,
            post_error_discarded=self.post_error_discarded,
            discard_accounting=self.discard_accounting(),
            cpu_sequence=dict(
                contract="PER_CPU_KERNEL_OBSERVATION_ATTEMPTS_NOT_RING_DELIVERIES",
                unrepresented_attempts=self.attempt_gaps,
                status="GAPS_UNRECONCILED_CAPTURE_INELIGIBLE"
                if self.attempt_gaps
                else "NO_GAP_OBSERVED_NOT_CAPTURE_PROOF",
                examples=self.sequence_examples,
                kernel_loss="UNKNOWN_REQUIRES_COUNTER_EVIDENCE",
            ),
            flow_policy="OBSERVED_EVENT_WATERMARK" if self.flow.event_watermark else "SAME_KEY",
            last_error=self.last_error,
            received=self.received,
            accepted=self.accepted,
            queue_pending=len(self.queue),
            queue_discarded=self.discarded,
            queue_rejected=self.overflow_rejected,
            queue_peak=self.queue_peak,
            dns_candidates=self.dns_candidates,
            ring_loss=self.loss,
            counter_evidence_digest=digest(
                [
                    self.counter_snapshots[cpu].model_dump(mode="json")
                    for cpu in sorted(self.counter_snapshots)
                ]
            )
            if self.counter_snapshots
            else None,
            counter_status="FIXTURE_DECLARATION_ONLY" if self.counter_snapshots else "NOT_OBSERVED",
            event_chain=self.chain,
            feature_digest=digest(features),
            feature_tail=features[-4:],
            finalized_count=len(features),
            native_ai="BLOCKED",
            stage_timing={k: dict(v) for k, v in self.stage_timing.items()},
            checkpoint_writer=self.checkpoint_writer.snapshot() if self.checkpoint_writer else None,
        )

    def _checkpoint_text(self) -> tuple[str, str]:
        if self.store is None:
            raise ValueError("EBPF_STORE_NOT_PREPARED")
        if sum(p.stat().st_size for p in self.directory.iterdir() if p.is_file()) > 8 * 1024**2:
            self.state, self.last_error = "ERROR", "EBPF_SESSION_DISK_LIMIT"
            raise ValueError(self.last_error)
        value = self._summary()
        text, sha = json.dumps(value), digest(value)
        if len(text.encode()) > 16384:
            raise ValueError("EBPF_CHECKPOINT_SIZE")
        return text, sha

    def request_checkpoint(self) -> str:
        """Explicit pending request during Native processing, never a durable receipt."""
        if self.checkpoint_writer is None:
            self.checkpoint()
            return "COMMITTED"
        self.checkpoint_writer.submit(*self._checkpoint_text())
        return "PENDING"

    def checkpoint(self) -> None:
        """Keep the synchronous API: returning means this snapshot committed FULL."""
        if self.checkpoint_writer is not None:
            self.checkpoint_writer.flush()
        self._persist_checkpoint(*self._checkpoint_text())

    def _persist_checkpoint(self, text: str, sha: str) -> None:
        started = time.perf_counter_ns()
        try:
            with self.store.database.transaction() as db:
                db.execute("DELETE FROM ebpf_checkpoint")
                db.execute("INSERT INTO ebpf_checkpoint VALUES(?,?)", (text, sha))
                self.store._audit(
                    db,
                    "EBPF_CHECKPOINT",
                    dict(
                        summary_digest=sha,
                        plan_digest=self.plan.identity,
                        program_sha256=self.plan.program_sha256,
                        native_ai="BLOCKED",
                    ),
                )
        finally:
            self._duration("audit_checkpoint", started)

    async def recover(self) -> dict:
        if self.state != "IDLE":
            raise ValueError("EBPF_RECOVERY_REQUIRES_FRESH_OWNER")
        store = RuntimeStore(self.directory)
        store.verify_audit()
        with store.database.transaction(write=False) as db:
            row = db.execute("SELECT value,digest FROM ebpf_checkpoint").fetchone()
            audits = [
                json.loads(r[0])
                for r in db.execute("SELECT payload FROM monitor_audit ORDER BY sequence")
            ]
        value = json.loads(row[0])
        initial = [a["details"] for a in audits if a["kind"] == "EBPF_PREPARED"]
        checkpoints = [a["details"] for a in audits if a["kind"] == "EBPF_CHECKPOINT"]
        if (
            digest(value) != row[1]
            or value["plan"] != self.plan.model_dump(mode="json")
            or initial != [dict(plan=value["plan"], plan_digest=self.plan.identity)]
            or not checkpoints
            or checkpoints[-1]["summary_digest"] != row[1]
            or checkpoints[-1]["plan_digest"] != self.plan.identity
            or checkpoints[-1]["program_sha256"] != self.plan.program_sha256
        ):
            raise ValueError("EBPF_CHECKPOINT_BINDING_FAILED")
        self.state = "RESTORED_NO_REATTACH"
        return self.snapshot() | dict(
            restored_evidence=value, runtime_audit_integrity=store.verify_audit()
        )

    def health(self) -> dict:
        return dict(state=self.state, native_hook="PENDING", last_error=self.last_error)

    def network_events(self) -> list[dict]:
        return []  # No AI receipt/operational event is fabricated from kernel metadata.

    def dns_events(self) -> list[dict]:
        return []  # Port 53 candidates are not Zeek DNS transactions.

    def discard_accounting(self) -> dict:
        """Disjoint userspace domains, never an inferred kernel loss counter."""
        return dict(
            domain="DECODED_USERSPACE_METADATA",
            session_id=str(self.plan.session_id),
            generation=self.plan.generation,
            reasons=dict(self.discard_reasons),
            reason_sum=sum(self.discard_reasons.values()),
            discarded=self.discarded,
            received=self.received,
            applied=self.accepted,
            pending=len(self.queue),
            balanced=self.received == self.accepted + len(self.queue) + self.discarded,
            kernel_drop=None,
            post_error_is_subset=True,
        )

    def metrics(self) -> dict:
        return dict(
            fixture_events=self.received if self.plan.origin.endswith("FIXTURE") else None,
            high_watermark=24,
            low_watermark=8,
            backpressure="HIGH" if len(self.queue) >= 24 else "NORMAL",
            capture_gaps=self.attempt_gaps or (1 if self.last_error else None),
            kernel_drops=None,
            kernel_events=None,
            ring_loss=self.loss,
            queue_depth=len(self.queue),
            queue_discarded=self.discarded,
            queue_rejected=self.overflow_rejected,
            queue_peak=self.queue_peak,
            normalized_packets=self.accepted,
        )

    def snapshot(self) -> dict:
        detail = dict(
            collector_type="EBPF_TC",
            hook=self.plan.hook,
            interface=self.plan.interface,
            ifindex=self.plan.ifindex,
            namespace=self.plan.net_namespace,
            program_sha256=self.plan.program_sha256,
            metrics=self.metrics(),
            counter_provenance="TC_HOOK_CPU_CUMULATIVE_GENERATION_NOT_ZEEK_HANDLE",
            capture_integrity="UNVERIFIED",
            feature_eligibility="BLOCKED_NATIVE_POLICY",
            clock=self.clock_contract.snapshot() if self.clock_contract else None,
            ordering=self.ordering.snapshot() if self.clock_contract else None,
            post_error_discarded=self.post_error_discarded,
            discard_accounting=self.discard_accounting(),
            finalized_flows=len(self.flow.finalized),
            active_flows=len(self.flow.active),
            dns_state="PORT53_CANDIDATE" if self.dns_candidates else "DNS_VISIBILITY_UNKNOWN",
            dns_candidates=self.dns_candidates,
            correlation="UNKNOWN_NO_SHARED_PACKET_ID",
            native_ai="BLOCKED",
            verifier="PENDING",
            native_hook="PENDING",
        )
        return dict(
            state=self.state,
            session_id=str(self.plan.session_id),
            input_origin=self.plan.origin,
            collection_live=False,
            last_error=self.last_error,
            ebpf=detail,
            collector=dict(
                type="EBPF_TC",
                health=self.state,
                capture_integrity="UNVERIFIED",
                metrics=self.metrics(),
            ),
            network=dict(state=self.state),
            dns=dict(state="DNS_VISIBILITY_UNKNOWN"),
            research=dict(records=[]),
            operational_gate="BLOCKED",
            dns9="BLOCKED",
            listener_ready=False,
            command_valid=False,
        )
