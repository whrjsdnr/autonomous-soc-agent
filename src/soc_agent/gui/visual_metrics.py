"""Bounded presentation observations, separated by session and input provenance.

Rates use counter deltas and monotonic observation time, not event timestamps or
lifetime means. First/missing/reset values stay unknown. This confers no eligibility.
"""

import math
from collections import deque
from dataclasses import dataclass


def number(value: object) -> float | None:
    return (
        float(value)
        if type(value) in (int, float) and math.isfinite(value) and value >= 0
        else None
    )


@dataclass(frozen=True)
class Observation:
    at: float
    values: dict[str, float | None]


class VisualHistory:
    def __init__(self, capacity: int = 60):
        if not 2 <= capacity <= 120:
            raise ValueError("VISUAL_HISTORY_BOUND")
        self.samples: deque[Observation] = deque(maxlen=capacity)
        self.identity = None
        self.previous = None
        self.publication = None
        self.last_stamp = -1.0
        self.state = "NOT_OBSERVED"

    def observe(self, snapshot: dict, *, at: float) -> bool:
        if not math.isfinite(at) or at <= self.last_stamp:
            return False
        self.last_stamp = at
        identity = (snapshot.get("session_id"), snapshot.get("input_origin"))
        if identity != self.identity:
            self.samples.clear()
            self.previous = None
            self.publication = None
            self.identity = identity
        self.state = snapshot.get("state", "UNKNOWN")
        # No stopped/error/degraded/retained sample can extend a live graph.
        offline = (
            snapshot.get("collector", {}).get("type") == "zeek"
            and identity[1] in {"ZEEK_OFFLINE_PCAP", "SYNTHETIC_ZEEK_JSON"}
            and self.state == "OFFLINE_PROCESSING"
        )
        running = (
            offline
            or (
                snapshot.get("collector", {}).get("type") == "zeek-live"
                and self.state in {"ACTIVE", "DEGRADED"}
                and snapshot.get("collection_live") is True
            )
            or self.state == "LIVE_COLLECTION"
            and (snapshot.get("collection_live") is True or identity[1] == "FIXTURE")
        )
        if not identity[0] or not running or snapshot.get("last_error"):
            self.previous = None
            return False
        net = snapshot.get("network", {})
        publication = tuple(
            number(net.get(key))
            for key in (
                "collector_network_events",
                "collector_dns_events",
                "capture_uptime_seconds",
                "received_frames",
                "sent_packets",
                "transport_delivered_packets",
                "dns_queries",
                "dns_responses",
                "runtime_cpu_seconds",
                "runtime_rss_bytes",
                "queue_backlog",
                "transport_queue_depth",
                "capture_drops",
                "gap_count",
                "token_balance",
            )
        )
        if publication == self.publication:
            return False  # Re-polling a cached publication is not a new measurement.
        self.publication = publication
        counts = {
            "zeek_network": number(net.get("collector_network_events")),
            "zeek_dns": number(net.get("collector_dns_events")),
            "raw": number(net.get("received_frames")),
            "normalized": number(net.get("normalized_packets"))
            if net.get("accounting_contract") == "soc-direction-accounting:v3"
            else number(net.get("sent_packets")),
            "delivered": number(net.get("transport_delivered_packets")),
            "queries": number(net.get("dns_queries")),
            "responses": number(net.get("dns_responses")),
            "cpu_seconds": number(net.get("runtime_cpu_seconds")),
        }
        values = {
            "limit": number(net.get("approved_raw_frames_per_second")),
            "analysis_limit": number(net.get("approved_analysis_packets_per_second")),
            "filtered": number(net.get("direction_filtered_frames")),
            "observation_tokens": number(net.get("observation_tokens")),
            "analysis_tokens": number(net.get("analysis_tokens")),
            "queue": number(net.get("queue_backlog")),
            "transport_queue": number(net.get("transport_queue_depth")),
            "rss": number(net.get("runtime_rss_bytes")),
            "drops": number(net.get("capture_drops")),
            "gaps": number(net.get("gap_count")),
            "tokens": number(net.get("token_balance")),
        }
        values["rss"] = values["rss"] / 1024**2 if values["rss"] is not None else None
        for key, count in counts.items():
            old = self.previous[1].get(key) if self.previous else None
            dt = at - self.previous[0] if self.previous else None
            values[key] = (
                (count - old) / dt
                if count is not None and old is not None and count >= old and dt
                else None
            )
        values["cpu"] = values.pop("cpu_seconds")
        if values["cpu"] is not None:
            values["cpu"] *= 100  # One logical CPU; may exceed 100 with multiple threads.
        self.previous = (at, counts)
        self.samples.append(Observation(at, values))
        return True


def record_series(snapshot: dict, metric: str) -> list[tuple[str, float | None, str]]:
    """Receipt/timeline data only: no invented progress percentage or risk probability."""
    points = []
    records = snapshot.get("research", {}).get("records", [])[:64]
    if metric == "progress":
        records = records[-1:]  # Independent investigations never share a progress axis.
    for record in records:
        receipt = record.get("receipt") or {}
        if (
            receipt.get("capture_session")
            and snapshot.get("session_id")
            and receipt["capture_session"] != snapshot["session_id"]
        ):
            continue
        if receipt.get("origin") and snapshot.get("input_origin") not in (
            None,
            "NO_DATA",
            receipt["origin"],
        ):
            continue
        # Preserve revoked provenance visually; never display it as healthy model output.
        label = str(receipt.get("inferred_at", "UNKNOWN"))
        source = str(receipt.get("origin", "UNKNOWN"))
        profile = str(receipt.get("profile", "UNKNOWN"))
        if metric == "latency":
            value = number(receipt.get("inference_latency_ms"))
            points.append((label, value, profile + " · " + source))
        elif metric in ("quality", "edge"):
            if profile == metric:
                points.append((label, float(len(points) + 1), source))
        elif metric == "severity":
            assessment = (record.get("investigation") or {}).get("assessment") or {}
            threat = assessment.get("threat_assessment", {}) if isinstance(assessment, dict) else {}
            severity = threat.get("severity")
            if str(record.get("advisory_current", "")).startswith("WITHDRAWN"):
                severity = None
            level = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(severity)
            points.append(
                (label, float(level) if level is not None else None, str(severity or "UNKNOWN"))
            )
        elif metric == "progress":
            investigation = record.get("investigation") or {}
            timeline = investigation.get("timeline") or {}
            entries = timeline.get("entries", []) if isinstance(timeline, dict) else []
            for entry in entries[-16:]:
                content = entry.get("content", {})
                result = content.get("result", {})
                points.append(
                    (
                        str(investigation.get("incident_id", "UNKNOWN"))[:8]
                        + ":"
                        + str(content.get("sequence", "UNKNOWN")),
                        number(content.get("sequence")),
                        str(result.get("reason", "UNKNOWN")),
                    )
                )
    return points[-64:]
