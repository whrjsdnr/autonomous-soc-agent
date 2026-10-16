"""Bounded presentation of existing DTOs; these labels never issue model/response authority."""

import math
from datetime import datetime

MODEL_NAMES = {"quality": "Network Quality", "edge": "Network Edge", "dns": "DNS Security"}


def number(value) -> str:
    if type(value) in (int, float) and math.isfinite(value) and value >= 0:
        return str(value) if type(value) is int else f"{value:.2f}"
    return "UNKNOWN"


def stamp(value) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            return "UNKNOWN"
        from datetime import UTC

        return parsed.astimezone(UTC).strftime("%H:%M:%S UTC")
    except (ValueError, TypeError, AttributeError):
        return "UNKNOWN"


def dated_stamp(value) -> str:
    if stamp(value) == "UNKNOWN":
        return "UNKNOWN"
    from datetime import UTC

    return (
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        .astimezone(UTC)
        .strftime("%m-%d %H:%M UTC")
    )


def operational(value: dict) -> str:
    """Research readiness is never operational readiness. Unknown claims stay unknown."""
    research = value.get("research", {})
    states = [research.get("operational_inference"), value.get("inference_status")]
    states += [g.get("inference") for g in value.get("network", {}).get("gates", {}).values()]
    if "BLOCKED" in states:
        return "BLOCKED"
    return "NOT_INFERABLE" if "NOT_INFERABLE" in states else "UNKNOWN"


def status_items(value: dict) -> list[tuple[str, str, str]]:
    r, n = value.get("research", {}), value.get("network", {})
    runtime = value.get("runtime_state", "UNKNOWN")
    healthy = (
        runtime == "RUNNING"
        and value.get("readiness") == "READY"
        and value.get("health") == "HEALTHY"
        and not value.get("last_error")
    )
    runtime_status = "ERROR" if value.get("last_error") or runtime == "FAILED" else runtime
    collector = value.get("collector_state", "UNKNOWN")
    auth = (
        "READY"
        if healthy and collector in ("INITIAL_READ", "RESUMED_EXACT", "RESUMED_WITH_REPLAY")
        else "STOPPED"
        if runtime == "STOPPED"
        else "UNKNOWN"
    )
    network = n.get("state", "UNKNOWN")
    if n.get("last_error"):
        network = "ERROR"
    elif network == "RUNNING":
        network = (
            "LIVE"
            if runtime == "RUNNING" and n.get("input_origin") == "NATIVE_AF_PACKET"
            else "UNKNOWN"
        )
    elif network in ("DEGRADED", "FAILED"):
        network = "ERROR"
    elif network == "DISABLED":
        network = "STOPPED"
    research = (
        "RESEARCH"
        if r.get("status") == "READY" or r.get("dns", {}).get("status") == "READY"
        else r.get("status", "UNKNOWN")
    )
    return [
        ("RUNTIME", runtime_status, value.get("readiness", "UNKNOWN")),
        ("AUTH COLLECTOR", auth, collector),
        ("NETWORK", network, "Packet observation"),
        ("DNS COLLECTOR", network, "Shared packet collector"),
        ("RESEARCH AI", research, r.get("demo_state", "UNKNOWN")),
        ("OPERATIONAL AI", operational(value), "Separate from research"),
        ("QUEUE BACKLOG", number(value.get("queue_backlog")), "Persisted queue"),
        ("INVESTIGATING", number(value.get("running_investigations")), "Current jobs"),
    ]


def model_view(value: dict, profile: str) -> dict:
    r = value.get("research", {})
    model = (
        r.get("dns", {})
        if profile == "dns"
        else next((m for m in r.get("models", []) if m.get("profile") == profile), {})
    )
    metrics = r.get("model_metrics", {}).get(profile, {})
    env = r.get("dns", {}).get("status") if profile == "dns" else r.get("status")
    worker = metrics.get("state", "UNKNOWN")
    if worker == "RUNNING" and not (
        r.get("worker_running") is True and r.get("active_model") == profile
    ):
        worker = "IDLE" if r.get("worker_running") is False else "UNKNOWN"
    return {
        "name": MODEL_NAMES[profile],
        "readiness": "READY_FOR_OFFLINE_REPLAY" if env == "READY" else env or "UNKNOWN",
        "worker": worker,
        "artifact": model.get("artifact", "UNKNOWN"),
        "count": number(metrics.get("successful")),
        "unknown": number(metrics.get("unknown")),
        "origin": "FIXTURE" if profile == "dns" else "OFFLINE_PCAP",
        "validation": ("DNS9 fixture only" if profile == "dns" else "Offline replay only")
        if type(metrics.get("successful")) is int and metrics["successful"] > 0
        else "NOT_RUN"
        if type(metrics.get("successful")) is int and metrics["successful"] == 0
        else "UNKNOWN",
        "last": dated_stamp(metrics.get("last_inference")),
        "error": metrics.get("last_error")
        or model.get("reason")
        or ("NONE_RECORDED" if env == "READY" else "Check environment / artifact"),
        "operational": operational(value),
    }


def measured_receipts(research: dict) -> list[dict] | None:
    if research.get("inference_counts") is None:
        return None
    receipts = []
    for record in research.get("records", [])[:10]:
        p = record.get("receipt")
        if not p or p.get("profile") not in MODEL_NAMES or stamp(p.get("inferred_at")) == "UNKNOWN":
            continue
        score = p.get("score")
        if type(score) not in (int, float) or not math.isfinite(score) or not 0 <= score <= 1:
            continue
        receipts.append(p)
    return sorted(
        receipts, key=lambda p: datetime.fromisoformat(p["inferred_at"].replace("Z", "+00:00"))
    )
