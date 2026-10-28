"""Bounded monotonic Native feature candidates, never a capture or model authorization.

Reuse incremental Network14 arithmetic without interpreting Kernel ns as UTC.
Root streaming counters are not automatically the Phase D P02/P03 attestation.
"""

from soc_agent.security_ai.collectors.packet_producer import Window
from soc_agent.security_ai.ebpf.clock import EventOrdering, OrderedEvent
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.workflow_models import ContinuousNativeWindowJob


class NativeWindows:
    def __init__(self, scope, session, limit=128):
        self.scope = scope
        self.session = session
        self.limit = limit
        self.active = {}
        self.generation = None
        self.count = 0
        self.ordering = EventOrdering()
        self.pending = []
        self.failed = False

    def emit(self, window, reason, witness=None):
        summary = window.finish(reason, self.session, witness)
        summary["candidate_timeout_complete"] = summary.pop("eligible")
        summary["native_eligibility"] = "UNKNOWN"
        return ContinuousNativeWindowJob(
            kind="continuous_native_window",
            namespace=self.scope,
            session=self.session,
            summary=summary,
            quality="UNKNOWN" if reason in ("IDLE_TIMEOUT", "ACTIVE_TIMEOUT") else "INCOMPLETE",
            reasons=(
                "CONTINUOUS_CAPTURE_ATTESTATION_REQUIRED",
                "NATIVE_MODEL_ACTION_GRANT_REQUIRED",
            ),
        )

    def process(self, event):
        result = []
        self.count += 1
        packet = OrderedEvent(event, self.count)
        for key, window in tuple(self.active.items()):
            if packet.ns - window.packets[0].ns >= 120_000_000_000:
                result.append(self.emit(window, "ACTIVE_TIMEOUT", packet.ns))
                del self.active[key]
            elif packet.ns - window.packets[-1].ns >= 30_000_000_000:
                result.append(self.emit(window, "IDLE_TIMEOUT", packet.ns))
                del self.active[key]
        if packet.key not in self.active:
            if len(self.active) >= self.limit:
                raise ValueError("CONTINUOUS_NATIVE_FLOW_CAPACITY")
            self.active[packet.key] = Window(compact=True)
        window = self.active[packet.key]
        window.add(packet)
        if window.count >= 4096:
            result.append(self.emit(window, "PACKET_LIMIT"))
            del self.active[packet.key]
        return result

    def add(self, event):
        if self.failed:
            raise ValueError("CONTINUOUS_NATIVE_FLOW_QUARANTINED")
        if event.net_namespace != self.scope or self.generation not in (None, event.generation):
            self.failed = True
            raise ValueError("CONTINUOUS_NATIVE_FLOW_EPOCH_SCOPE")
        self.generation = event.generation
        try:
            self.ordering.observe(event)
        except ValueError:
            self.failed = True
            raise
        self.pending.append(event)
        self.pending.sort(key=lambda e: (e.ns, e.sequence))
        result = []
        watermark = self.ordering.maximum - self.ordering.lateness_ns
        while self.pending and (self.pending[0].ns <= watermark or len(self.pending) >= 32):
            item = self.pending.pop(0)
            self.ordering.emitted = item.ns
            result.extend(self.process(item))
        return result

    def close(self):
        # Final drain does not advance event-time or establish a live-window proof.
        result = []
        if not self.failed:
            for event in self.pending:
                result.extend(self.process(event))
        self.pending.clear()
        for window in self.active.values():
            result.append(self.emit(window, "SHUTDOWN"))
        self.active.clear()
        return result


def validate_candidate(job):
    from soc_agent.security_ai.collectors.parity import NETWORK14

    summary = job.summary
    import math

    if (
        summary.get("feature_names") != [name for name, _, _ in NETWORK14]
        or len(summary.get("values", [])) != 14
        or any(type(v) not in (float, int) or not math.isfinite(v) for v in summary["values"])
        or summary.get("values_digest") != digest(summary["values"])
    ):
        raise ValueError("CONTINUOUS_NATIVE_FEATURE_SCHEMA")
    return job.quality
