"""Read-only retained-session assessment; never creates a capture, namespace or traffic."""

import math
import sqlite3
from collections import Counter
from pathlib import Path

from soc_agent.realtime.queue import EventQueue
from soc_agent.security_ai.operational.network_capture.models import FlowSummary, PacketObservation
from soc_agent.security_ai.research.live_evidence import verify


def projected_frames(frames, elapsed, seconds, *, extra=16, safety=1.0):
    """Constant-observed-rate planning estimate, never a future upper bound."""
    if (
        type(frames) is not int
        or frames <= 0
        or type(extra) is not int
        or extra < 0
        or any(
            type(n) not in (int, float) or not math.isfinite(n) for n in (elapsed, seconds, safety)
        )
        or elapsed <= 0
        or seconds <= 0
        or safety < 1
    ):
        raise ValueError("FRAME_BUDGET_INPUT_UNKNOWN_OR_INVALID")
    return math.ceil(frames * seconds * safety / elapsed) + extra


def assessment(directory: Path) -> dict:
    saved = verify(directory)
    # Decode metadata only after the existing source/provenance/audit verifier.
    queue = EventQueue(directory / "runtime/network/queue.sqlite")
    packets, flows = {}, []
    with queue.database.transaction(write=False) as connection:
        rows = connection.execute("SELECT * FROM realtime_events ORDER BY rowid").fetchall()
    for row in rows:
        event = queue._decode(row)
        cls = PacketObservation if event.metadata.code == "packet" else FlowSummary
        record = cls.model_validate_json("".join(v for _, v in event.normalized_fields))
        if isinstance(record, PacketObservation):
            packets[str(event.event_id)] = record
        else:
            flows.append(record)
    from soc_agent.linux_runtime.store import RuntimeStore
    from soc_agent.security_ai.operational.network_capture.helper_transport import Message

    network = RuntimeStore(directory / "runtime").state()["network"]
    ready = Message.model_validate_json((directory / "verified-ready.json").read_bytes())
    closed = Message.model_validate_json((directory / "verified-closed.json").read_bytes())
    with sqlite3.connect(
        (directory / "runtime/network/sources.sqlite").as_uri() + "?mode=ro", uri=True
    ) as connection:
        source_counts = dict(
            connection.execute("SELECT status,count(*) FROM operational_sources GROUP BY status")
        )
    verified = saved["capture_status"] == "CAPTURE_VERIFIED"
    total_refs, summaries = [], []
    for flow in flows:
        refs = flow.source_event_ids
        observed = [packets[ref] for ref in refs]
        first = observed[0]
        forward = sum(
            (p.source_address, p.source_port) == (first.source_address, first.source_port)
            for p in observed
        )
        duration = (observed[-1].timestamp - first.timestamp).total_seconds()
        if (
            len(set(refs)) != len(refs)
            or (forward, len(refs) - forward) != (flow.forward_packets, flow.backward_packets)
            or duration != flow.duration_seconds
        ):
            raise ValueError("FLOW_REFERENCE_COUNTER_OR_DURATION_MISMATCH")
        total_refs.extend(refs)
        times = [p.capture_timestamp_ns for p in observed]
        summaries.append(
            dict(
                flow_id=flow.flow_id,
                protocol=flow.transport,
                packets=len(refs),
                forward=flow.forward_packets,
                backward=flow.backward_packets,
                duration_seconds=duration,
                max_interpacket_seconds=max(
                    ((b - a) / 1e9 for a, b in zip(times, times[1:], strict=False)), default=None
                ),
                close_reason=flow.close_reason,
            )
        )
    if len(set(total_refs)) != len(total_refs) or set(total_refs) != set(packets):
        raise ValueError("DUPLICATE_OR_UNACCOUNTED_FLOW_PACKET")
    first_ns = min(p.capture_timestamp_ns for p in packets.values())
    bins = Counter((p.capture_timestamp_ns - first_ns) // 10**9 for p in packets.values())
    elapsed, frames = closed.elapsed_seconds, closed.received_frames
    projections = (
        [
            dict(
                seconds=seconds,
                observed_rate_only=projected_frames(frames, elapsed, seconds, extra=0),
                plus_scenario_16_frames=projected_frames(frames, elapsed, seconds),
                safety_1_5_plus_16=projected_frames(frames, elapsed, seconds, safety=1.5),
            )
            for seconds in (31, 33, 40, 59)
        ]
        if verified
        else []
    )
    return {
        "session_directory": directory.name,
        "session_id": saved["session_id"],
        "capture_status": saved["capture_status"],
        "persistence_status": saved["persistence_status"],
        "transport_status": saved["transport_status"],
        "counter_status": closed.counter_status,
        "counter_sequence_ready": ready.counter_sequence,
        "counter_sequence_closed": closed.counter_sequence,
        "kernel_packets_total": closed.kernel_packets_total,
        "capture_drops_total": closed.capture_drops_total,
        "received_frames": frames,
        "sent_packets": closed.sent_packets,
        "stored_packets": len(packets),
        "flows": summaries,
        "queue": saved["queue"],
        "source_status_counts": source_counts,
        "finalization": saved["finalization"],
        "transport_queue_depth": network["transport_queue_depth"],
        "transport_queue_high_water": network["transport_queue_high_water"],
        "capture_gap_count": saved["capture_gap_count"],
        "elapsed_seconds": elapsed,
        "packet_timestamp_span_seconds": (
            max(p.capture_timestamp_ns for p in packets.values()) - first_ns
        )
        / 1e9,
        "observed_frames_per_second": frames / elapsed if verified else None,
        "metadata_one_second_bins": {str(k): v for k, v in sorted(bins.items())},
        "ip_versions": dict(Counter(str(p.ip_version) for p in packets.values())),
        "protocols": dict(Counter(p.transport for p in packets.values())),
        "frame_budget": "FRAME_BUDGET_INSUFFICIENT"
        if verified and elapsed < 31 and frames == 512
        else "UNKNOWN",
        "projection_assumption": "CONSTANT_OBSERVED_RATE_NOT_A_FUTURE_BOUND",
        "projections": projections,
        "eligible_flows": saved["flow_eligibility"]["eligible"],
        "model_receipts": len(saved["models"]),
        "audit_digest": saved["audit_digest"],
        "research_audit": saved["research_audit"],
        "sqlite_integrity": saved["sqlite_integrity"],
        "database_unchanged": saved["database_unchanged"],
        "capabilities": {
            k: saved["capabilities"][k]
            for k in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd", "NoNewPrivs")
        },
        "helper_rss_peak_bytes": closed.rss_peak_bytes,
        "helper_cpu_ready_seconds": ready.cpu_seconds,
        "helper_cpu_closed_seconds": closed.cpu_seconds,
        "runtime_process_rss_peak_bytes": network["runtime_rss_peak_bytes"],
        "runtime_process_cpu_seconds": network["runtime_cpu_seconds"],
        "runtime_rate_window_seconds": network["rate_window_seconds"],
        "runtime_metadata_packets_per_second": network["packets_per_second"],
        "operational_gate": saved["operational_gate"],
        "action_policy": saved["action_policy"],
        "assessment_scope": "RETAINED_NATIVE_READ_ONLY_NO_NEW_INFERENCE",
    }
