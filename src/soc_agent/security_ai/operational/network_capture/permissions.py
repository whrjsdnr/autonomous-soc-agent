"""Read-only Linux privilege diagnostics. Never grants or changes capabilities."""

import os
from pathlib import Path

from soc_agent.security_ai.operational.network_capture.capture import (
    CaptureUnavailable,
    PacketCapture,
)
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig, model_gates

NET_RAW = 1 << 13
NET_ADMIN = 1 << 12


def privileges() -> dict[str, int | None]:
    result: dict[str, int | None] = {"euid": os.geteuid(), "egid": os.getegid()}
    fields = ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd", "NoNewPrivs")
    try:
        lines = Path("/proc/self/status").read_text().splitlines()
        values = dict(line.split(":", 1) for line in lines if ":" in line)
        for field in fields:
            result[field] = int(values[field].strip(), 10 if field == "NoNewPrivs" else 16)
    except (OSError, KeyError, ValueError):
        result.update(dict.fromkeys(fields))
    return result


def capture_permission(interface: str) -> dict:
    """Open/bind/close only. Availability never implies captured traffic or model parity."""
    config = CaptureConfig(interface=interface)
    before = privileges()
    capture = None
    try:
        capture = PacketCapture(config)
        capture.open()
        status = "AVAILABLE"
    except CaptureUnavailable as error:
        status = str(error)
    finally:
        if capture is not None:
            capture.close()
    effective = before["CapEff"]
    return {
        "capture": status,
        "privileges": before,
        "cap_net_raw": None if effective is None else bool(effective & NET_RAW),
        "cap_net_admin": None if effective is None else bool(effective & NET_ADMIN),
        "requires_net_admin_for_bound_receive": False,
        "actual_packets_verified": False,
        "capture_drops": None,
        "automatic_privilege_escalation": False,
        "privileges_unchanged": before == privileges(),
        "operational_models": model_gates(),
    }
