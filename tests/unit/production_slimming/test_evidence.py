"""Measured claims, actual screenshot files and immutable contracts stay traceable."""

import hashlib
import json
import struct
from pathlib import Path

from soc_agent.security_ai.operational.network_capture import calibrated_session
from soc_agent.security_ai.research.models import SPECS, digest

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads((ROOT / "docs/linux-soc-v1/production-slimming-evidence.json").read_text())


def test_sources_screenshots_and_signed_helper_are_exact():
    doc = evidence()
    for name, expected in doc["source_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == expected, name
    for name, entry in doc["screenshots"].items():
        data = (ROOT / "docs/linux-soc-v1/production-slimming-screenshots" / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"]
        assert data.startswith(b"\x89PNG\r\n\x1a\n")
        assert list(struct.unpack(">II", data[16:24])) == entry["dimensions"]
    files = calibrated_session.verify_bundle()
    assert files["calibrated_helper.py"] == doc["helper_sha256"]
    assert digest(files) == doc["bundle_digest"]


def test_benchmarks_are_scoped_and_do_not_invent_native_success():
    doc = evidence()
    for mode in ("before", "after"):
        rows = doc["idle_comparison"][mode]
        assert len(rows) == 3
        for row in rows:
            assert row["explicit_identical_native_status_paths"] is True
            assert row["remaining_child_processes"] == row["idle_child_processes"] == 0
            assert row["gui_worker_stopped"]
            assert row["idle_rss_bytes"] > 0 and row["startup_seconds"] > 0
        active = doc["active_comparison"][mode]["active_fixture"]
        assert "NOT_NATIVE" in active["scope"]
        assert active["finalization"] == "VERIFIED" and active["final_queue_backlog"] == 0
        assert {m["profile"] for m in active["models"]} == {"quality", "edge"}
    assert doc["boundaries"]["native_capture_executed"] is False
    assert doc["boundaries"]["privileged_commands_executed"] is False
    assert doc["boundaries"]["dns9"] == "PARITY_BLOCKED"
    assert doc["boundaries"]["operational_promotion"] == "BLOCKED"
    assert doc["known_native_crash"]["root_cause"] == "UNKNOWN"
    assert doc["known_native_crash"]["interrupted_run_counted_as_pass"] is False


def test_actual_fixture_receipts_have_unchanged_model_and_feature_identity():
    doc = evidence()
    actual = doc["actual_gui_fixture"]
    assert "NOT_NATIVE" in actual["scope"]
    assert len(actual["records"]) == 2 and actual["audit_integrity"] == "VERIFIED"
    for row in actual["records"]:
        receipt = row["receipt"]
        assert receipt["artifact_digest"] == SPECS[receipt["profile"]]["sha256"]
        assert receipt["origin"] == "FIXTURE" and receipt["producer_version"] == "1.1.0"
        assert len(receipt["feature_values"]) == 14
        assert row["investigation"]["status"] == "ASSESSED_READ_ONLY"
