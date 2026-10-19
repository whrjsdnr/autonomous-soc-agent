"""Actual-artifact fixture evidence, helper identities and screenshot integrity."""

import hashlib
import json
import struct
from pathlib import Path

from soc_agent.security_ai.operational.network_capture import calibrated_session, direction_session
from soc_agent.security_ai.operational.network_capture.direction_policy import DirectionPolicy
from soc_agent.security_ai.research.models import SPECS, digest

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads((ROOT / "docs/linux-soc-v1/capture-policy-v3-evidence.json").read_text())


def test_v3_policy_helper_bundle_and_legacy_are_distinct_and_exact():
    e = evidence()
    assert e["policy"] == DirectionPolicy().model_dump(mode="json")
    current = direction_session.verify_bundle()
    assert current == e["bundle_files"] and digest(current) == e["bundle_digest"]
    assert current["direction_helper.py"] == e["helper_sha256"] != e["legacy_helper_sha256"]
    legacy = calibrated_session.verify_bundle()
    assert legacy["calibrated_helper.py"] == e["legacy_helper_sha256"]
    assert digest(legacy) == e["legacy_bundle_digest"]
    for name, sha in e["source_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha


def test_native_unknowns_fixture_receipts_and_recovery_are_not_combined():
    e = evidence()
    n = e["native"]["native"]
    assert n["received_raw_frames"] == 1217 and n["normalized_packets_sent"] == 608
    assert n["actual_burst"] == n["actual_duplicate_pairs"] == "UNKNOWN"
    assert n["native_inference_receipts"] == 0
    assert e["native"]["verified_closed"] == "MISSING"
    assert all(result == "ok" for result in e["native"]["sqlite_integrity"].values())
    m = e["actual_models"]
    assert len(m["receipts"]) == m["read_only_investigations"] == 4
    assert m["network"]["queue_backlog"] == 0 and m["network"]["finalization"] == "VERIFIED"
    assert m["network"]["selected_rate_policy"] == "direction-v3"
    assert m["recovery"] == "VERIFIED_NO_NEW_INFERENCE" and m["original_audit_prefix_unchanged"]
    for receipt in m["receipts"]:
        assert receipt["artifact_digest"] == SPECS[receipt["profile"]]["sha256"]
        assert receipt["origin"] == "FIXTURE" and receipt["producer_version"] == "1.1.0"
        assert len(receipt["feature_values"]) == 14
    assert e["boundaries"]["native_capture"] is e["boundaries"]["privileged_commands"] is False
    assert e["boundaries"]["dns9"] == "PARITY_BLOCKED"
    assert e["boundaries"]["operational_promotion"] == "BLOCKED"


def test_screenshots_and_performance_are_real_scoped_artifacts():
    e = evidence()
    for name, record in e["screenshots"].items():
        data = (ROOT / "docs/linux-soc-v1/capture-policy-v3-screenshots" / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == record["sha256"]
        assert data[:8] == b"\x89PNG\r\n\x1a\n"
        assert list(struct.unpack(">II", data[16:24])) == record["dimensions"]
        assert "FIXTURE_NOT_NATIVE" in record["scope"]
    p = e["performance"]
    assert p["native_throughput"] == "UNKNOWN"
    assert p["repeats"] == 5 and p["iterations"] == 4000
    for variant in ("balanced_v2", "direction_v3"):
        assert all(
            row["normalized_packets"] == 2000 and row["errors"] == 0 for row in p[variant]["runs"]
        )
    for variant in ("before", "after"):
        assert len(e["idle_comparison"][variant]) == 3
        assert all(r["idle_child_processes"] == 0 for r in e["idle_comparison"][variant])
        a = e["active_comparison"][variant]["active_fixture"]
        assert a["finalization"] == "VERIFIED" and a["final_queue_backlog"] == 0
