"""Public recovery evidence must match preserved code and honest validation scopes."""

import hashlib
import json
from pathlib import Path

import pytest

from soc_agent.security_ai.operational.network_capture import calibrated_session, total_session
from soc_agent.security_ai.operational.network_capture.calibrated_policy import CANDIDATES, policy
from soc_agent.security_ai.research.models import digest

ROOT = Path(__file__).resolve().parents[3]
EVIDENCE = ROOT / "docs/linux-soc-v1/native-capture-capacity-calibration-evidence.json"


@pytest.fixture
def evidence():
    return json.loads(EVIDENCE.read_text())


def test_frozen_source_and_bundle_integrity(evidence):
    # Immutable validation at 89a7989; current preparation/UI behavior has its
    # own regressions. Do not restamp historical proof as newly executed.
    historical = {
        "src/soc_agent/gui/live_view.py": "live-view.txt",
        "src/soc_agent/security_ai/research/stream_service.py": "stream-service.txt",
    }
    for name, expected in evidence["source_files_sha256"].items():
        path = (
            ROOT / "tests/fixtures/calibration-89a7989" / historical[name]
            if name in historical
            else ROOT / name
        )
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, name
    reviewed = calibrated_session.verify_bundle()
    assert evidence["helper"]["bundle_files"] == reviewed
    assert evidence["helper"]["bundle_digest"] == digest(reviewed)
    assert evidence["helper"]["sha256"] == reviewed["calibrated_helper.py"]
    assert digest(total_session.verify_bundle()) == (
        "e26057b77534b552701826dd1c4d6829e76d94fcfc0bb8c263fd661f2038ac0f"
    )


def test_reported_policies_are_exact_and_default_not_promoted(evidence):
    assert evidence["policies"] == {n: policy(n).model_dump(mode="json") for n in CANDIDATES}
    assert evidence["default_policy"] == "legacy"
    assert evidence["dynamic_rate_increase"] is False
    assert evidence["helper"]["minimum_available_memory_bytes"] == 2 * 1024**3
    assert evidence["helper"]["approval"].startswith("SEPARATE_USER_APPROVAL_REQUIRED")


def test_reused_measurements_do_not_claim_native_or_final_integration(evidence):
    profile = evidence["profiling"]
    assert profile["scope"] == "REUSED_PRE_INTERRUPTION_FIXTURE_NOT_NATIVE"
    assert profile["measurement_source_sha"] == "UNKNOWN_NOT_RECORDED_AT_MEASUREMENT"
    for stage in profile["stages"].values():
        assert stage["scope"] == "FIXTURE_NOT_NATIVE"
        result = stage["result"]
        assert result["errors"] == 0 and result["repetitions"] > 0
        q = result["latency_seconds"]
        assert 0 <= q["0.5"] <= q["0.95"] <= q["0.99"]
    previous = evidence["prior_actual_model_comparison"]
    assert previous["scope"].startswith("EARLIER_SHORT_PREFIX_BEFORE_FINAL")
    assert all(r["policy"]["total_frames"] == 38656 for r in previous["records"].values())
    assert evidence["prior_mock_soak"]["scope"].endswith("NO_REAL_MODELS")


def test_historical_failures_and_current_approval_remain_explicit(evidence):
    assert evidence["initial_recovery_verdict"] == "PARTIAL_VALIDATION_BLOCKED_NO_COMMIT"
    assert evidence["verdict"] == "FIXTURE_CALIBRATED_NATIVE_CALIBRATION_PENDING"
    failure = evidence["last_full_fixture_attempt"]
    assert failure["failed"] == 3 and failure["count_as_success"] is False
    assert failure["error"] == "STREAM_GRACEFUL_DEADLINE_UNKNOWN_NO_RETRY"
    assert evidence["current_checks"]["low_cost"]["actual_models_run"] is False
    assert evidence["native_capture_executed"] is False
    assert evidence["privileged_commands_executed"] is False
    assert evidence["test_network_traffic_generated"] is False
    assert evidence["boundaries"]["dns9"] == "PARITY_BLOCKED"
    assert evidence["boundaries"]["operational_promotion"] == "BLOCKED"
    assert evidence["boundaries"]["os_security_write"] == "WRITE_DENIED"


def test_native_average_cannot_substitute_missing_arrival_evidence(evidence):
    native = evidence["native_baseline"]
    assert native["actual_burst"] == "UNKNOWN"
    assert native["per_frame_arrival_times"] == "MISSING"
    assert native["token_balance_at_rejection"] == "UNKNOWN"
    assert native["verified_closed"] == "MISSING"
    assert native["token_envelope_using_elapsed"] > native["received_raw_frames"]
    assert native["quality_receipts"] == native["edge_receipts"] == 0


def test_resume_preserves_successes_and_blocks_unexecuted_cases_on_pressure(evidence):
    resumed = evidence["resumed_final_validation"]
    assert resumed["status"] == "PARTIAL_RESOURCE_PRESSURE_STOP"
    assert resumed["initial_22_file_export_sha_match"] is True
    assert resumed["runtime_or_helper_policy_changed"] is False
    assert resumed["helper_sha256"] == evidence["helper"]["sha256"]
    assert resumed["bundle_digest"] == evidence["helper"]["bundle_digest"]
    cases = resumed["actual_cases"]
    assert {(c["scope"], c["profile"]) for c in cases} == {
        ("workspace", "conservative-v2"),
        ("workspace", "balanced-v2"),
        ("workspace", "performance-v2"),
        ("export", "conservative-v2"),
    }
    for case in cases:
        assert case["status"] == "PASS" and case["exit_code"] == 0
        assert case["automatic_retry"] is case["native"] is False
        result = case["actual_comparison"]
        assert result["finalization"] == "VERIFIED" and result["inference_queue"]["depth"] == 0
        assert len(result["models"]) == result["investigations"] == 4
        assert result["native"] is False and result["errors"] == 0
        assert result["policy"] == policy(case["profile"]).model_dump(mode="json")
    assert {c["profile"] for c in resumed["blocked_cases"]} == {
        "balanced-v2",
        "performance-v2",
    }
    assert all(c["scope"] == "export" for c in resumed["blocked_cases"])
    assert resumed["stop_observation"]["memory_psi"]["some"]["avg10"] == 0.12
    assert evidence["commit_push"]["staged"] is False
    assert evidence["commit_push"]["committed"] is evidence["commit_push"]["pushed"] is False
    assert evidence["commit_push"]["scope"] == "HISTORICAL_RESUME_RUN_NOT_FINAL_DELIVERY_STATUS"


def test_completion_verifies_remaining_export_cases_without_native_promotion(evidence):
    final = evidence["completion_validation"]
    assert final["status"] == "FIXTURE_VALIDATION_COMPLETE_NATIVE_APPROVAL_PENDING"
    assert final["workspace_model_cases_passed"] == final["export_model_cases_passed"] == 3
    assert final["workspace_and_export_prior_cases_reused"] == 4
    assert final["same_features_predictions_and_scores_across_six_cases"] is True
    assert final["runtime_and_helper_policy_changed"] is False
    assert final["producer_feature_semantics_changed"] is False
    assert final["helper_sha256"] == evidence["helper"]["sha256"]
    assert final["bundle_digest"] == evidence["helper"]["bundle_digest"]
    assert final["native_capture_executed"] is final["privileged_commands_executed"] is False
    assert final["automatic_retry"] is False
    assert {c["profile"] for c in final["new_actual_cases"]} == {"balanced-v2", "performance-v2"}
    for case in final["new_actual_cases"]:
        assert case["scope"] == "export" and case["status"] == "PASS" and case["exit_code"] == 0
        assert all(s["memory"]["MemAvailable"] >= 2 * 1024**3 for s in case["preflight"])
        result = case["integration"]
        assert result["finalization"] == "VERIFIED" and result["inference_queue"]["depth"] == 0
        assert len(result["models"]) == result["investigations"] == 4
        assert result["native"] is False and result["errors"] == 0
        for model in result["models"]:
            assert len(model["values"]) == 14
            assert model["artifact_digest"] == final[f"{model['profile']}_artifact_sha256"]
        assert len(case["drain_observer"]) == 1
        drain = case["drain_observer"][0]
        assert drain["drain_deadline_seconds"] == 30
        assert 0 < drain["elapsed_monotonic_seconds"] < 30
        assert drain["finalization"] == "VERIFIED" and drain["last_error"] is None
