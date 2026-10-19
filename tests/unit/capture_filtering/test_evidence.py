"""Measured scope, immutable UI/helper and actual Fixture provenance are verifiable."""

import hashlib
import json
from pathlib import Path

from soc_agent.security_ai.operational.network_capture.calibrated_session import verify_bundle
from soc_agent.security_ai.research.models import SPECS, digest

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads(
        (ROOT / "docs/linux-soc-v1/native-capture-filtering-evidence.json").read_text()
    )


def test_current_sources_unchanged_gui_and_helper_bundle():
    e = evidence()
    for name, sha in {**e["source_sha256"], **e["immutable_gui_sha256"]}.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha, name
    files = verify_bundle()
    assert files["calibrated_helper.py"] == e["helper_sha256"]
    assert digest(files) == e["bundle_digest"]
    assert (
        e["raw_policy_changed"]
        is e["deduplication_enabled"]
        is e["native_capture_executed"]
        is False
    )


def test_native_unknowns_and_microbenchmark_scope():
    e = evidence()
    n = e["native"]
    assert n["actual_duplicate_pairs"] == n["actual_burst"] == "UNKNOWN"
    assert n["received_raw_frames"] == 1217 and n["normalized_packets_sent"] == 608
    assert n["capture_drops"] == 0 and n["verified_closed"] == "MISSING"
    assert n["native_inference_receipts"] == 0
    perf = e["performance"]
    assert perf["scope"] == "SYNTHETIC_FIXTURE_NO_CAPTURE_NO_SUPPRESSION"
    for row in perf["stages"].values():
        assert row["repeats"] == 5 and row["iterations"] == 4000
        assert all(r["error_count"] == 0 and r["p99_us"] >= r["p50_us"] for r in row["runs"])
    assert not perf["active_deduplication"] and not perf["raw_rate_policy_changed"]


def test_model_fixture_actual_artifacts_producer_dns_and_recovery():
    m = evidence()["actual_models"]
    assert m["read_only_investigations"] == len(m["receipts"]) == 4
    assert m["network"]["packets_collected"] == 7 and m["network"]["queue_backlog"] == 0
    assert m["network"]["analysis_network_metadata_reused"] == 4
    assert m["network"]["analysis_network_metadata_copies"] == 3
    assert m["network"]["finalization"] == "VERIFIED"
    assert m["dns"]["counts"]["MATCHED_RESPONSE"] == 1 and m["dns"]["dns9_inference"] == "BLOCKED"
    assert m["recovery"] == "VERIFIED_NO_NEW_INFERENCE" and m["original_audit_prefix_unchanged"]
    for r in m["receipts"]:
        assert r["artifact_digest"] == SPECS[r["profile"]]["sha256"]
        assert r["origin"] == "FIXTURE" and len(r["feature_values"]) == 14
        assert r["producer_version"] == "1.1.0"
