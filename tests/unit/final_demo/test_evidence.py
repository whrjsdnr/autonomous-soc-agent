"""Public final-demo evidence integrity; tampering uses memory/private screenshot copies."""

import copy
import json
import shutil
from pathlib import Path

import pytest
from tests.final_demo_support import file_sha, verify_manifest

from soc_agent.security_ai.research.models import digest

DIRECTORY = Path(__file__).resolve().parents[3] / "docs/linux-soc-v1/final-demo"


@pytest.fixture
def evidence():
    return json.loads((DIRECTORY / "evidence-manifest.json").read_text())


def reseal(value):
    value["manifest_digest"] = digest({k: v for k, v in value.items() if k != "manifest_digest"})
    return value


def test_actual_committed_manifest_and_screenshot_bytes(evidence):
    verified = verify_manifest(evidence, DIRECTORY)
    assert len(verified.invocations) == 6
    assert len(verified.screenshots) >= 18
    assert verified.authentication["database_unchanged"]


def test_manifest_change_rejected_without_reseal(evidence):
    evidence["invocations"][0]["score"] = 0.314159
    with pytest.raises(ValueError, match="MANIFEST_DIGEST"):
        verify_manifest(evidence, DIRECTORY)


@pytest.mark.parametrize(
    "field,value",
    [
        ("input_origin", "NATIVE_AF_PACKET"),
        ("artifact_sha256", "0" * 64),
        ("feature_contract_digest", "0" * 64),
        ("operational_gate", "READY"),
        ("action_policy", "WRITE_ALLOWED"),
        ("status", "OPERATIONAL"),
        ("model_identity", "untrusted-model"),
        ("score", -0.1),
        ("prediction", "ATTACK_CONFIRMED"),
        ("provider_calls", 1),
        ("checkpoint_restored", False),
    ],
)
def test_resealed_semantic_forgery_rejected(evidence, field, value):
    evidence["invocations"][0][field] = value
    with pytest.raises(ValueError):
        verify_manifest(reseal(evidence), DIRECTORY)


def test_missing_invocation_input_is_rejected(evidence):
    del evidence["invocations"][0]["input_digest"]
    with pytest.raises(ValueError):
        verify_manifest(reseal(evidence), DIRECTORY)


def test_duplicate_inference_or_incident_is_rejected(evidence):
    evidence["invocations"][1] = copy.deepcopy(evidence["invocations"][0])
    with pytest.raises(ValueError, match="DUPLICATE_OR_MERGED"):
        verify_manifest(reseal(evidence), DIRECTORY)


@pytest.mark.parametrize(
    "field,value",
    [
        ("worker_running", True),
        ("new_inferences_after_cached_replay", 1),
        ("demo_state", "RUNNING"),
        ("same_audit_head", False),
    ],
)
def test_recovery_cannot_claim_a_new_inference_as_retained(evidence, field, value):
    evidence["recovery"][field] = value
    with pytest.raises(ValueError, match="READ_ONLY_OR_RECOVERY"):
        verify_manifest(reseal(evidence), DIRECTORY)


def test_retained_auth_database_mutation_is_rejected(evidence):
    first = next(iter(evidence["authentication"]["database_sha256_after"]))
    evidence["authentication"]["database_sha256_after"][first] = "0" * 64
    with pytest.raises(ValueError, match="READ_ONLY_OR_RECOVERY"):
        verify_manifest(reseal(evidence), DIRECTORY)


def test_authentication_cannot_be_merged_into_a_research_incident(evidence):
    evidence["authentication"]["findings"][0]["incident_id"] = evidence["invocations"][0][
        "incident_id"
    ]
    with pytest.raises(ValueError, match="CROSS_DOMAIN"):
        verify_manifest(reseal(evidence), DIRECTORY)


@pytest.mark.parametrize(
    "field,value", [("password", "private"), ("path", "/home/private-person/model")]
)
def test_private_environment_is_not_publishable(evidence, field, value):
    evidence["environment"][field] = value
    with pytest.raises(ValueError, match="PRIVATE_EVIDENCE"):
        verify_manifest(reseal(evidence), DIRECTORY)


def test_missing_required_screenshot_is_rejected(evidence):
    evidence["screenshots"] = [
        s for s in evidence["screenshots"] if s["filename"] != "screenshots/audit-1366.png"
    ]
    with pytest.raises(ValueError, match="SCREENSHOT_COVERAGE"):
        verify_manifest(reseal(evidence), DIRECTORY)


def test_screenshot_digest_and_symlink_are_rejected(evidence, tmp_path):
    shutil.copytree(DIRECTORY / "screenshots", tmp_path / "screenshots")
    path = tmp_path / evidence["screenshots"][0]["filename"]
    original = path.read_bytes()
    path.write_bytes(original + b"changed")
    with pytest.raises(ValueError, match="SCREENSHOT_DIGEST"):
        verify_manifest(evidence, tmp_path)
    path.unlink()
    path.symlink_to(DIRECTORY / evidence["screenshots"][0]["filename"])
    with pytest.raises(ValueError, match="UNSAFE_SCREENSHOT_PATH"):
        verify_manifest(evidence, tmp_path)


def test_screenshot_dimension_and_traversal_are_rejected(evidence):
    evidence["screenshots"][0]["width"] += 1
    with pytest.raises(ValueError, match="SCREENSHOT_DIGEST_OR_DIMENSION"):
        verify_manifest(reseal(evidence), DIRECTORY)
    evidence["screenshots"][0]["filename"] = "screenshots/../../outside.png"
    with pytest.raises(ValueError):
        verify_manifest(reseal(evidence), DIRECTORY)


def test_screenshot_directory_symlink_is_rejected(evidence, tmp_path):
    (tmp_path / "screenshots").symlink_to(DIRECTORY / "screenshots", target_is_directory=True)
    with pytest.raises(ValueError, match="UNSAFE_SCREENSHOT_ROOT"):
        verify_manifest(evidence, tmp_path)


def test_original_collection_manifest_is_preserved(evidence):
    path = DIRECTORY / "history/evidence-manifest-collected.json"
    assert file_sha(path) == "d8546713be92a468aa716cd01c5f0070fe71e02fe02d53c69dd3ed3c43ec7963"
    original = json.loads(path.read_text())
    verify_manifest(original, DIRECTORY)
    assert original["manifest_digest"] == (
        "a31dc1dc67399ce4548c2a724cee58899330b1a8037168288705e8255a138a3b"
    )
    assert {
        k: v for k, v in evidence.items() if k not in {"known_limitations", "manifest_digest"}
    } == {k: v for k, v in original.items() if k != "manifest_digest"}
    assert evidence["known_limitations"]


def test_recovery_verification_does_not_merge_runs(evidence):
    recovery = json.loads((DIRECTORY / "recovery-verification.json").read_text())
    assert recovery["run_id"] != evidence["run_id"]
    assert recovery["collection_run_id"] == evidence["run_id"]
    assert recovery["collection_validation_timestamp"] == evidence["validation_date"]
    assert recovery["final_manifest_sha256"] == file_sha(DIRECTORY / "evidence-manifest.json")
    assert recovery["collected_manifest_sha256"] == file_sha(
        DIRECTORY / recovery["collected_manifest_file"]
    )
    assert recovery["artifact_references"] == evidence["environment"]["artifacts"]


def test_missing_primary_evidence_and_sigill_are_not_reported_as_resolved():
    recovery = json.loads((DIRECTORY / "recovery-verification.json").read_text())
    assert recovery["validation_result"] == "PARTIAL"
    for field in (
        "raw_receipt_files",
        "research_audit_database",
        "investigation_checkpoints",
        "authentication_databases",
        "original_test_logs",
        "original_sigill_log",
    ):
        assert recovery[field] == "MISSING"
    assert recovery["new_native_inferences"] == recovery["new_os_captures"] == 0
    assert recovery["new_os_security_writes"] == recovery["new_journal_collections"] == 0
    assert recovery["sigill"]["root_cause"] == "ROOT_CAUSE_UNKNOWN"
    assert recovery["sigill"]["recurrence"] == "RECURRENCE_NOT_EXCLUDED"
    assert recovery["operational_gate"] == "BLOCKED"
