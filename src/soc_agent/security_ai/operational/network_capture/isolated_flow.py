"""Total-mode event-time partitions over the unchanged bounded Flow/Statistics engine.

Other keys never advance a key's expiry. Key tombstones last the entire session;
there is no lateness window, timestamp repair, reordering or automatic unquarantine.
"""

from dataclasses import dataclass, field
from uuid import UUID

from soc_agent.security_ai.operational.network_capture.flows import FlowTable
from soc_agent.security_ai.operational.network_capture.models import PacketObservation
from soc_agent.security_ai.operational.network_capture.streaming_flow import (
    CompletedFlow,
    StreamingFlows,
)
from soc_agent.security_ai.research.live_input import timestamp_ns
from soc_agent.security_ai.research.models import digest

POLICY = "soc-total-flow-isolation:v1:SAME_KEY_EVENT_TIME_ONLY"


@dataclass
class Partition:
    engine: StreamingFlows
    last_ns: int | None = None
    quarantine: dict | None = None
    completed: list[str] = field(default_factory=list)


class IsolatedFlows:
    def __init__(self, *, max_flows=128, metadata_bytes=8 * 1024**2, records=1024, packets=38656):
        if (
            not 1 <= max_flows <= 128
            or not 1 <= records <= 1024
            or not 1 <= packets <= 38656
            or not 8192 <= metadata_bytes <= 16 * 1024**2
        ):
            raise ValueError("TOTAL_ISOLATION_BUDGET_INVALID")
        self.max_flows, self.limit, self.records, self.packet_limit = (
            max_flows,
            metadata_bytes,
            records,
            packets,
        )
        self.partitions: dict[str, Partition] = {}
        self.flow_keys: dict[str, str] = {}
        self.seen: set[UUID] = set()
        self.last_events: list[dict] = []
        self.high_ns: int | None = None
        self.peak_bytes = self.observed = self.completed = self.cross_flow = 0

    @staticmethod
    def key(packet: PacketObservation) -> str:
        return digest(FlowTable.key(packet))

    @property
    def bytes(self) -> int:
        return sum(p.engine.bytes for p in self.partitions.values())

    @property
    def active_count(self) -> int:
        return sum(len(p.engine.table.flows) for p in self.partitions.values())

    def quarantine(self, key: str, *, reason: str, **context) -> dict:
        partition = self.partitions[key]  # Unknown keys cannot be locally isolated.
        if partition.quarantine is None:
            value = dict(
                policy=POLICY,
                flow_key_digest=key,
                reason=reason,
                discarded_packet_references=len(partition.engine.packets),
                affected_flow_ids=list(partition.completed),
                **context,
            )
            value["quarantine_reference"] = digest(value)
            partition.quarantine = value
            partition.engine.close("RESTART_GAP")
        return partition.quarantine

    def allowed(self, flow_id: str) -> bool:
        key = self.flow_keys.get(flow_id)
        return key is not None and self.partitions[key].quarantine is None

    def add(self, packet: PacketObservation, identity: UUID) -> list[CompletedFlow]:
        self.last_events = []
        if identity in self.seen:
            raise ValueError("STREAM_DUPLICATE_PACKET")
        if len(self.seen) >= self.packet_limit:
            raise ValueError("TOTAL_PACKET_REFERENCE_LIMIT")
        key, ns = self.key(packet), timestamp_ns(packet)
        partition = self.partitions.get(key)
        if partition is None:
            if len(self.partitions) >= self.records:
                raise ValueError("TOTAL_FLOW_HISTORY_BACKPRESSURE")
            partition = Partition(StreamingFlows(max_flows=1, metadata_bytes=self.limit))
            self.partitions[key] = partition
        self.seen.add(identity)
        self.observed += 1
        if partition.quarantine is not None:
            self.last_events = [dict(kind="QUARANTINED_PACKET_EXCLUDED", flow_key_digest=key)]
            return []
        if partition.last_ns is not None and ns < partition.last_ns:
            value = self.quarantine(
                key,
                reason="FLOW_EVENT_TIME_REVERSED",
                previous_event_ns=partition.last_ns,
                rejected_event_ns=ns,
                regression_ns=partition.last_ns - ns,
                packet_identity=str(identity),
            )
            self.last_events = [dict(kind="FLOW_QUARANTINED", **value)]
            return []
        if self.high_ns is not None and ns < self.high_ns:
            self.cross_flow += 1
            self.last_events.append(
                dict(
                    kind="CROSS_FLOW_EVENT_TIME_NON_MONOTONIC",
                    flow_key_digest=key,
                    high_event_ns=self.high_ns,
                    event_ns=ns,
                    delta_ns=self.high_ns - ns,
                    independence="DISJOINT_KEYS_NO_SHARED_EXPIRY",
                )
            )
        if not partition.engine.table.flows and self.active_count >= self.max_flows:
            raise ValueError("STREAM_ACTIVE_FLOW_BACKPRESSURE")
        projected_bytes = self.bytes + len(packet.model_dump_json().encode())
        if projected_bytes > self.limit:
            raise ValueError("STREAM_METADATA_MEMORY_BACKPRESSURE")
        # One existing engine per bidirectional key: its global check is flow-local.
        result = partition.engine.add(packet, identity)
        partition.last_ns = ns
        self.high_ns = ns if self.high_ns is None else max(self.high_ns, ns)
        self.peak_bytes = max(self.peak_bytes, projected_bytes)
        for item in result:
            if len(self.flow_keys) >= self.records:
                raise ValueError("TOTAL_COMPLETED_FLOW_HISTORY_BACKPRESSURE")
            self.flow_keys[item.flow.flow_id] = key
            partition.completed.append(item.flow.flow_id)
            self.completed += 1
        return result

    def close(self, reason="SHUTDOWN") -> list[CompletedFlow]:
        return [item for p in self.partitions.values() for item in p.engine.close(reason)]

    def snapshot(self) -> dict:
        quarantines = {
            key: p.quarantine["quarantine_reference"]
            for key, p in self.partitions.items()
            if p.quarantine is not None
        }
        return dict(
            policy=POLICY,
            healthy_flow_keys=len(self.partitions) - len(quarantines),
            quarantined_flow_keys=len(quarantines),
            quarantine_references=quarantines,
            cross_flow_regressions=self.cross_flow,
            history_keys=len(self.partitions),
            packet_references=len(self.seen),
            quarantine_metadata_bytes=sum(
                len(str(p.quarantine).encode())
                for p in self.partitions.values()
                if p.quarantine is not None
            ),
        )
