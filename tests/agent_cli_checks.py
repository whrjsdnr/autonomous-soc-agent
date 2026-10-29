"""Explicit ordinary CLI + real pinned PCAP/models + actual Tk. No Live collection/API."""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from soc_agent.cli import main
from soc_agent.continuous.store import Store
from soc_agent.security_ai.offline_workflow import verify_result
from soc_agent.security_ai.research.environment import catalogue
from tests.research_adapter_support import research_paths


def command(home, name, *arguments, expected=0):
    result = subprocess.run(
        [sys.executable, "-m", "soc_agent.cli", name, "--home", str(home), *map(str, arguments)],
        capture_output=True,
        text=True,
        timeout=65,
        check=False,
    )
    assert result.returncode == expected, (result.stdout, result.stderr)
    return json.loads(result.stdout if expected == 0 else result.stderr)


def open_gui(home, monkeypatch, *, state):
    """Exercise gui CLI/real mainloop and backend; instrumentation only closes our window."""
    from soc_agent.gui import production

    desktop = production.Desktop
    snapshots, errors = [], []
    pages = ["Dashboard", "Continuous", "AI Analysis", "Investigation", "System"]

    class CheckedDesktop(desktop):
        def __init__(self, root, config):
            super().__init__(root, config)
            self.deadline = time.monotonic() + 60
            root.after(50, self.inspect_view)

        def inspect_view(self):
            try:
                assert time.monotonic() < self.deadline, "GUI backend/view timeout"
                if self.busy or not self.startup_complete:
                    self.root.after(50, self.inspect_view)
                    return
                assert self.snapshot["continuous"]["state"] == state
                assert not self.snapshot["collection_live"]
                assert self.snapshot["input_origin"] == "OFFLINE_PCAP"
                assert self.snapshot["network"]["inference_count"] >= 2
                assert self.snapshot["research"]["records"]
                assert self.snapshot["analysis"]["result"]["audit"] == "VERIFIED"
                snapshots.append(dict(page=self.page, state=state))
                if pages:
                    self.navigate(pages.pop(0))
                    self.root.after(100, self.inspect_view)
                else:
                    self.close()
            except BaseException as error:
                errors.append(error)
                self.close()

    with monkeypatch.context() as patch:
        patch.setattr(production, "Desktop", CheckedDesktop)
        assert main(["gui", "--home", str(home)]) == 0
    if errors:
        raise errors[0]
    assert {s["page"] for s in snapshots} >= {
        "Dashboard",
        "Continuous",
        "AI Analysis",
        "Investigation",
        "System",
    }
    return snapshots


@pytest.mark.skipif(not os.getenv("DISPLAY"), reason="Explicit actual Tk/WSLg check")
def test_cli_pcap_to_models_incident_audit_gui_and_detach(tmp_path, monkeypatch):
    paths = research_paths()
    original = paths.ml / catalogue()["raw_relative_path"]
    if not original.exists() or not paths.python.exists():
        pytest.skip("Pinned research PCAP/interpreter unavailable")
    # An exact prefix of stored packet bytes/timestamps, not generated traffic.
    # Bound this lifecycle check independently of the large-PCAP retention/Drop test.
    body = original.read_bytes()
    assert hashlib.sha256(body).hexdigest() == catalogue()["raw_sha256"]
    assert body[:4] == b"\xd4\xc3\xb2\xa1"
    offset = 24
    for _ in range(128):
        size = int.from_bytes(body[offset + 8 : offset + 12], "little")
        offset += 16 + size
        assert offset <= len(body)
    pcap = tmp_path / "stored-prefix-128.pcap"
    pcap.write_bytes(body[:offset])
    pcap.chmod(0o600)
    home = tmp_path / "application"
    configured = command(home, "setup", "--replay", pcap, "--ml-root", paths.ml)
    assert configured["source"] == "PCAP_REPLAY" and not configured["root_installed"]
    assert configured["native_authority"] == "NOT_GRANTED"
    doctor = command(home, "doctor")
    assert set(doctor["checks"]["models"].values()) == {"VERIFIED_SHA"}
    runtime = Path(configured["runtime"])
    store = Store(runtime)
    started = command(home, "start")
    assert started["status"] == "SERVICE_HEARTBEAT_VERIFIED"
    try:
        assert command(home, "start", expected=2)["error"] == "AGENT_ALREADY_RUNNING"
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            current = command(home, "status")
            assert current["last_error"] is None, current["last_error"]
            if current["metrics"]["predictions"] >= 2 and current["collector"] == "EOF_NOT_LIVE":
                break
            time.sleep(0.2)
        else:
            pytest.fail("Actual PCAP did not produce RF/LR receipts")
        assert current["collector"] == "EOF_NOT_LIVE"
        assert current["metrics"]["eligible"] >= 1 and current["metrics"]["flows"] >= 1
        assert current["metrics"]["queue_dropped"] == 0
        assert current["metrics"]["incidents"] >= 1 and current["audit"] == "VERIFIED"
        gui_running = open_gui(home, monkeypatch, state="RUNNING")
        assert command(home, "status")["state"] == "RUNNING"  # GUI does not own service
    finally:
        stopped = command(home, "stop")
    assert stopped["runtime"]["cleanup"] == "VERIFIED"
    assert stopped["runtime"]["collector"] == stopped["runtime"]["worker"] == "STOPPED"
    assert stopped["queue_drain"] in {"PENDING_RETAINED", "NO_PENDING_JOBS"}
    assert command(home, "stop")["status"] == "ALREADY_STOPPED"
    state = store.state()  # Existing audit validation, not merely JSON stdout.
    reports = []
    for row in state["recent_results"]:
        outcome = verify_result(Path(row["output"]))
        assert outcome.external_provider_calls == 0
        assert all(e.origin != "REAL_NATIVE" for e in outcome.evidence)
        reports.append(dict(incident=str(outcome.incident_id), predictions=len(outcome.inference)))
    assert sum(r["predictions"] for r in reports) >= 2
    gui_stopped = open_gui(home, monkeypatch, state="STOPPED")
    assert store.state() == state  # Viewing/reconnecting does not write service state/audit.
    (tmp_path / "verification.json").write_text(
        json.dumps(
            dict(
                scope="ACTUAL_STORED_PCAP_REAL_MODELS_NO_NATIVE_NO_API",
                source=dict(
                    parent_sha256=catalogue()["raw_sha256"],
                    prefix_packets=128,
                    prefix_sha256=hashlib.sha256(body[:offset]).hexdigest(),
                    timestamps_and_packet_bytes="UNCHANGED_PREFIX",
                ),
                configured=configured,
                doctor=doctor,
                started=started,
                stopped=stopped,
                verified_reports=reports,
                gui_running=gui_running,
                gui_stopped=gui_stopped,
            ),
            indent=2,
        )
    )
