"""Committed redacted fixture evidence is internally bound and never claims native capture."""

import hashlib
import json
from pathlib import Path

from soc_agent.security_ai.operational.network_capture.total_session import verify_bundle
from soc_agent.security_ai.research.models import SPECS, digest, parse_receipt

ROOT = Path(__file__).resolve().parents[3]


def test_actual_model_fixture_evidence_binding():
    data = json.loads(
        (
            ROOT / "docs/linux-soc-v1/continuous-network-ai-scope-bound-fixture-evidence.json"
        ).read_text()
    )
    assert data["validation"] == "ACTUAL_MODELS_SYNTHETIC_PACKET_FIXTURE_NOT_NATIVE_CAPTURE"
    assert not data["raw_capture_performed"]
    assert data["network_origin"] == "FIXTURE"
    assert data["inference_count"] == len(data["receipts"]) == 2
    assert data["packet_count"] == 4 and data["source_commit_count"] == 1
    assert data["queue"] == {"DONE": 1}
    assert data["eligible_flow_count"] == data["excluded_flow_count"] == 1
    assert data["active_metadata_bytes"] == data["transient_input_files"] == 0
    for item in data["receipts"]:
        receipt = parse_receipt(item["receipt"])
        assert receipt.origin == "FIXTURE" and receipt.status == "RESEARCH_ONLY"
        assert receipt.artifact_digest == SPECS[receipt.profile]["sha256"]
        assert item["receipt_digest"] == digest(item["receipt"])
        assert item["checkpoint_restored"] is True
        assert item["write_policy"] == "WRITE_DENIED"
    assert data["restart_new_inference_count"] == 0
    assert data["recovery_state"] == "RETAINED_STREAM_NOT_LIVE"
    assert data["native_continuous_capture"] == "PENDING_USER_APPROVAL"
    helper = ROOT / "src/soc_agent/security_ai/operational/network_capture/stream_helper.py"
    assert data["helper_sha256"] == (
        "1cc1c1f39007d1e8f53207dcd5f79f2128b12ea8077d5d09fcb6a72c5d037c84"
    )
    current = hashlib.sha256(helper.read_bytes()).hexdigest()
    assert current == verify_bundle()["stream_helper.py"]
    assert current != data["helper_sha256"]  # Historical fixture evidence is not a new approval.


def test_resource_evidence_preserves_fixture_and_known_limitations():
    data = json.loads(
        (ROOT / "docs/linux-soc-v1/continuous-network-ai-validation.json").read_text()
    )
    soak = data["soak"]
    assert soak["input_origin"] == "FIXTURE"
    assert soak["elapsed_seconds"] >= 1800
    assert soak["actual_model_inferences"] == 0
    assert soak["mock_unknown_calls"] == 1
    assert soak["metrics"]["capture_drops"] is None
    assert soak["metrics"]["finalization"] == "PARTIAL"
    assert soak["active_metadata_bytes"] == soak["transient_input_files"] == 0
    assert soak["state"] == "STOPPED" and soak["queue"] == {"DONE": 50}
    assert soak["sampled_peak_rss_bytes"] <= 768 * 1024**2
    assert data["native_continuous_capture_executions"] == 0
    assert data["helper_approval"] == "NEW_APPROVAL_REQUIRED_WITH_SESSION_DIGEST"
    assert data["clock_issue"]["security_validation_relaxed"] is False
    assert data["operational_gate"] == "OPERATIONAL_INFERENCE_BLOCKED"
