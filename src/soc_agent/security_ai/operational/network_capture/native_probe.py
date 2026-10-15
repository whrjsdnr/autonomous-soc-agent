"""Opt-in, bounded loopback capture process; never elevates itself or calls models.

An operator must provision this process with only CAP_NET_RAW beforehand. The SOC
Runtime remains unprivileged. Capture is implementation-level receive-only, not
a kernel sandbox against compromise of this Python process.
"""

import argparse
import asyncio
import ctypes
import json
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from uuid import uuid4

from soc_agent.linux_runtime.models import RuntimeConfig
from soc_agent.linux_runtime.network_monitor import NetworkMonitor, configure
from soc_agent.linux_runtime.service import initialize
from soc_agent.linux_runtime.store import RuntimeStore
from soc_agent.security_ai.operational.network_capture.capture import (
    CaptureUnavailable,
    PacketCapture,
)
from soc_agent.security_ai.operational.network_capture.models import CaptureConfig, model_gates
from soc_agent.security_ai.operational.network_capture.permissions import NET_RAW, privileges
from soc_agent.security_ai.operational.provenance import build_receipt, verify_receipt


def validate_probe_privileges() -> None:
    state = privileges()
    if state["euid"] == 0:
        raise CaptureUnavailable("ROOT_SOC_PROCESS_FORBIDDEN")
    if state["CapEff"] is None or not state["CapEff"] & NET_RAW:
        raise CaptureUnavailable("CAP_NET_RAW_REQUIRED")
    if any(
        state[name] is None or state[name] & ~NET_RAW
        for name in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")
    ):
        raise CaptureUnavailable("EXCESS_OR_UNKNOWN_CAPABILITIES")
    if state["NoNewPrivs"] != 1:
        raise CaptureUnavailable("NO_NEW_PRIVILEGES_REQUIRED")


def drop_capabilities() -> None:
    """Drop this process's capability sets after opening the single capture socket."""

    class Header(ctypes.Structure):
        _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

    class Data(ctypes.Structure):
        _fields_ = [
            ("effective", ctypes.c_uint32),
            ("permitted", ctypes.c_uint32),
            ("inheritable", ctypes.c_uint32),
        ]

    libc = ctypes.CDLL(None, use_errno=True)
    capset = libc.capset
    capset.argtypes = [ctypes.POINTER(Header), ctypes.POINTER(Data)]
    capset.restype = ctypes.c_int
    if capset(ctypes.byref(Header(0x20080522, 0)), (Data * 2)()) != 0:
        raise CaptureUnavailable("CAPABILITY_DROP_FAILED")
    state = privileges()
    if any(state[name] != 0 for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")):
        raise CaptureUnavailable("CAPABILITY_DROP_NOT_VERIFIED")


class ProbeCapture(PacketCapture):
    def __init__(self, config):
        super().__init__(config)
        self.received = 0
        self.stop = None

    def receive(self):
        if self.received >= 128:
            self.stop.set()
            return None
        value = super().receive()
        if value is not None:
            self.received += 1
        return value

    def open(self):
        validate_probe_privileges()
        super().open()
        try:
            drop_capabilities()
        except (OSError, AttributeError, CaptureUnavailable):
            self.close()
            raise CaptureUnavailable("CAPABILITY_DROP_FAILED") from None


async def probe(seconds: float) -> dict:
    if not 1 <= seconds <= 10:
        raise ValueError("PROBE_DURATION_OUT_OF_RANGE")
    validate_probe_privileges()
    config = CaptureConfig(interface="lo", packet_batch=8, max_flows=16)
    # New private diagnostic databases only; never accepts an existing runtime path.
    with TemporaryDirectory(prefix="soc-native-probe-") as temporary:
        root = Path(temporary) / "runtime"
        initialize(
            root, RuntimeConfig(incident_id=uuid4(), repeated_failures=5, multiple_accounts=3)
        )
        configure(root, config)
        capture = ProbeCapture(config)
        store = RuntimeStore(root)
        monitor = NetworkMonitor(root, store, capture=capture)
        capture.stop = monitor.stopped
        started = monotonic()

        async def stop():
            await asyncio.sleep(seconds)
            monitor.stopped.set()

        timer = asyncio.create_task(stop())
        try:
            await monitor.run()
        finally:
            timer.cancel()
            await asyncio.gather(timer, return_exceptions=True)
            capture.close()
        pipeline = monitor.pipeline
        receipts = 0
        with pipeline.queue.database.transaction(write=False) as connection:
            rows = connection.execute("SELECT * FROM realtime_events ORDER BY rowid").fetchall()
        for row in rows:
            event = pipeline.queue._decode(row)
            source = pipeline._source(event, pipeline.decode(event))
            receipt = build_receipt(
                pipeline.sources, incident_id=pipeline.incident, sources=(source,)
            )
            verify_receipt(
                receipt, pipeline.sources, incident_id=pipeline.incident, sources=(source,)
            )
            receipts += 1
        counts = pipeline.queue.counts()
        recovered = NetworkMonitor(root, RuntimeStore(root)).pipeline
        recovered.recover()
        while recovered.step() != "IDLE":
            pass
        integrity = []
        for name in ("monitor.sqlite", "network/queue.sqlite", "network/sources.sqlite"):
            with sqlite3.connect(f"file:{root / name}?mode=ro", uri=True) as connection:
                integrity.append(connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok")
        verified = (
            receipts > 0
            and all(integrity)
            and not monitor.metrics["last_error"]
            and monitor.metrics["capture_drops"] == 0
            and counts == {"DONE": receipts}
            and recovered.queue.counts() == counts
        )
        return {
            "input_origin": "NATIVE_AF_PACKET_LOOPBACK_TEST",
            "status": "VERIFIED" if verified else "INCONCLUSIVE",
            "requested_seconds": seconds,
            "elapsed_seconds": monotonic() - started,
            "packets_collected": monitor.metrics["packets_collected"],
            "packets_rejected": monitor.metrics["packets_rejected"],
            "dns_queries": monitor.metrics["dns_queries"],
            "capture_drops": monitor.metrics["capture_drops"],
            "capture_error": monitor.metrics["last_error"],
            "queue_counts": counts,
            "receipts_verified": receipts,
            "restart_queue_counts": recovered.queue.counts(),
            "audit_verified": bool(store.verify_audit()),
            "sqlite_integrity": all(integrity),
            "remaining_capabilities": privileges(),
            "payload_stored": False,
            "operational_models": model_gates(),
            "write_disposition": "WRITE_DENIED",
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=float, default=5)
    args = parser.parse_args()
    try:
        result = asyncio.run(probe(args.seconds))
    except (CaptureUnavailable, ValueError) as error:
        print(json.dumps({"status": "BLOCKED", "reason": str(error)}))
        return 2
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
