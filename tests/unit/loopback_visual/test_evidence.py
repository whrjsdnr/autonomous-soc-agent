"""Current source, real screenshots and model receipts have separate provenance."""

import hashlib
import json
import struct
from pathlib import Path

from soc_agent.security_ai.operational.network_capture.calibrated_session import verify_bundle
from soc_agent.security_ai.research.models import SPECS, digest

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads((ROOT / "docs/linux-soc-v1/loopback-rate-visual-evidence.json").read_text())


def test_sources_screenshots_and_unchanged_signed_contract():
    doc = evidence()
    for name, sha in doc["source_sha256"].items():
        historical = {
            "src/soc_agent/gui/production.py": "production.txt",
            "src/soc_agent/gui/visual_charts.py": "visual_charts.txt",
            "tests/unit/production_slimming/test_evidence.py": "slimming_test.txt",
            "src/soc_agent/gui/operator_view.py": "src__soc_agent__gui__operator_view.py.txt",
            "src/soc_agent/gui/visual_metrics.py": "src__soc_agent__gui__visual_metrics.py.txt",
            "src/soc_agent/security_ai/research/stream_service.py": "stream_service.txt",
            "src/soc_agent/security_ai/research/packet_accounting.py": "packet_accounting.txt",
            "tests/unit/loopback_visual/test_evidence.py": "loopback_evidence_test.txt",
        }
        source = (
            ROOT / "tests/fixtures/filtering-ebfd20b" / historical[name]
            if name in historical
            else ROOT / name
        )
        assert hashlib.sha256(source.read_bytes()).hexdigest() == sha, name
    assert len(doc["screenshots"]) == 12
    for name, entry in doc["screenshots"].items():
        body = (ROOT / "docs/linux-soc-v1/loopback-visual-screenshots" / name).read_bytes()
        assert body[:8] == b"\x89PNG\r\n\x1a\n"
        assert hashlib.sha256(body).hexdigest() == entry["sha256"]
        assert list(struct.unpack(">II", body[16:24])) == entry["dimensions"]
        assert "NATIVE" not in entry["scope"]
    files = verify_bundle()
    assert files["calibrated_helper.py"] == doc["helper_sha256"]
    assert digest(files) == doc["bundle_digest"]


def test_native_failure_is_not_promoted_and_unknown_counters_stay_unknown():
    native = evidence()["native"]
    assert native["received_raw_frames"] == 1217 and native["normalized_packets_sent"] == 608
    assert native["delivered_packets"] == 608 and native["kernel_packets"] == 1218
    assert native["capture_drops"] == 0 and native["verified_closed"] == "MISSING"
    assert native["actual_duplicate_pairs"] == native["actual_burst"] == "UNKNOWN"
    assert native["native_inference_receipts"] == native["investigations"] == 0
    assert native["audit"]["status"] == "VERIFIED"
    doc = evidence()
    assert doc["boundaries"]["native_capture_executed"] is False
    assert doc["boundaries"]["rate_policy_changed"] is False
    assert doc["boundaries"]["dns9"] == "PARITY_BLOCKED"
    assert doc["boundaries"]["operational_gate"] == "BLOCKED"


def test_real_model_fixture_and_measured_performance_have_scoped_evidence():
    doc = evidence()
    for mode in ("before", "after"):
        rows = doc["idle_comparison"][mode]
        assert len(rows) == 3
        assert all(row["idle_child_processes"] == 0 for row in rows)
        assert all(row["controller_sqlite_statements_total"] == 0 for row in rows)
        active = doc["active_comparison"][mode]["active_fixture"]
        assert active["finalization"] == active["audit_integrity"] == "VERIFIED"
        assert active["final_queue_backlog"] == 0
        assert len(active["models"]) == 2
    for row in doc["actual_gui_fixture"]["records"]:
        receipt = row["receipt"]
        assert receipt["origin"] == "FIXTURE" and receipt["producer_version"] == "1.1.0"
        assert receipt["artifact_digest"] == SPECS[receipt["profile"]]["sha256"]
        assert row["investigation"]["status"] == "ASSESSED_READ_ONLY"
