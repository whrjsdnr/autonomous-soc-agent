"""Real runtime replay and negative authority gates in private isolated databases."""

import asyncio
from copy import deepcopy

import pytest

from soc_agent.approval import ApprovalManager
from soc_agent.llm.openai_compatible import OpenAICompatibleClient
from soc_agent.security_ai.packaging import ModelPackage
from tests.decision_pipeline_contract import DecisionExport, compare, correctness, projection
from tests.diagnose_decision_pipeline import export, save_reports


@pytest.fixture(scope="module")
def traces(tmp_path_factory):
    root = tmp_path_factory.mktemp("decision-equivalence")
    calls = []
    original = ModelPackage.predict
    from unittest.mock import patch

    def predict(package, features):
        calls.append(package.manifest.model_kind)
        return original(package, features)

    def forbidden(*args, **kwargs):
        raise AssertionError("Provider or approval issuance forbidden")

    with (
        patch.object(ModelPackage, "predict", predict),
        patch.object(OpenAICompatibleClient, "_post", forbidden),
        patch.object(ApprovalManager, "approve", forbidden),
    ):
        a = asyncio.run(export(root / "first"))
        b = asyncio.run(export(root / "second"))
    assert len(calls) == 26  # 13 real model calls each run, none on duplicate replay
    return a, b, root


def test_same_fixed_events_replay_same_actual_domain_trace(traces):
    a, b, _ = traces
    assert a["metadata"] != b["metadata"]
    assert (
        a["sequences"][0]["events"][0]["checkpoint"]["run_id"]
        != b["sequences"][0]["events"][0]["checkpoint"]["run_id"]
    )
    result = compare(a, b)
    assert result["correctness"] == "PASS"
    assert result["decision_equivalence"] == "PASS"
    assert result["cross_platform_execution"] == "INCONCLUSIVE"
    assert result["status"] == "INCONCLUSIVE"
    assert "accepted operational human authorization" in result["not_validated"]


@pytest.mark.parametrize(
    "field",
    [
        "fixture_sha256",
        "policy_sha256",
        "model_files",
        "threat",
        "severity",
        "policy",
        "approval_requirement",
        "action_id",
        "evidence",
        "missing_trace",
        "metadata",
        "guard_wrong_allow",
        "source_time",
        "read_surface",
        "audit",
        "both_missing_audit",
    ],
)
def test_comparison_detects_security_changes_and_preserves_metadata_rule(traces, field):
    a, b, _ = traces
    other = deepcopy(b)
    event = other["sequences"][0]["events"][0]
    guards = {g["case_id"]: g for g in other["guards"]}
    if field in ("fixture_sha256", "policy_sha256"):
        other[field] = "0" * 64
    elif field == "model_files":
        other[field]["network_classifier"]["model/model.json"] = "0" * 64
    elif field == "threat":
        event["checkpoint"]["artifacts"]["assessment"]["threat_assessment"]["summary"] = (
            "Changed advisory"
        )
    elif field == "severity":
        event["checkpoint"]["artifacts"]["assessment"]["threat_assessment"]["severity"] = "critical"
    elif field == "policy":
        event["policy_calls"][0]["result"]["decision"] = "deny"
    elif field == "approval_requirement":
        guards["write_without_approval"]["approval_required"] = False
    elif field == "action_id":
        guards["stable_action_id_mismatch"]["action_id"] = "00000000-0000-0000-0000-000000000001"
    elif field == "evidence":
        event["state"]["evidence"][0]["raw_data"] = "Tampered evidence"
    elif field == "missing_trace":
        del event["trace"]
    elif field == "metadata":
        other["metadata"] = {
            "captured_at": "different runtime time",
            "output_directory": "C:\\synthetic-path",
        }
    elif field == "source_time":
        event["receipt"]["event"]["occurred_at"] = "2026-01-02T00:00:00Z"
    elif field == "read_surface":
        event["progress"][-1]["waiting_for_human"] = False
    elif field == "audit":
        other["sequences"][0]["audit"][0]["actor_id"] = "unexpected-synthetic-actor"
    elif field == "both_missing_audit":
        other["sequences"][0]["audit"] = []
        a = deepcopy(a)
        a["sequences"][0]["audit"] = []
    else:
        guards["write_without_approval"] |= {
            "permitted": True,
            "blocked": False,
            "error_type": None,
        }
        a = deepcopy(a)
        a["guards"] = [deepcopy(g) for g in other["guards"]]
    result = compare(a, other)
    if field == "metadata":
        assert result["decision_equivalence"] == "PASS"
    elif field == "missing_trace":
        assert result["status"] == "INCONCLUSIVE"
    else:
        assert result["status"] == "FAIL"


def test_invalid_approval_and_policy_cases_are_actually_blocked(traces):
    a, _, _ = traces
    guards = {g["case_id"]: g for g in a["guards"]}
    for name in (
        "write_without_approval",
        "pending_write",
        "forged_approval_id",
        "stable_action_id_mismatch",
        "approval_target_mismatch",
        "expired_principal",
        "expired_confirmation",
        "insufficient_role",
        "invalid_confirmation_format",
        "stored_evidence_tamper",
        "missing_evidence",
    ):
        assert guards[name]["blocked"] is True
        assert guards[name]["error_type"]
        assert guards[name].get("write_calls", 0) == 0
        assert guards[name].get("verification_records", 0) == 0
    assert guards["read_allowed"]["permitted"] is True
    assert guards["advisory_info"]["decision"] == "insufficient_basis"
    assert guards["advisory_low"]["decision"] == "suspicion_for_review"
    assert all(
        s["write_calls"] == s["approval_rows"] == s["execution_rows"] == 0 for s in a["sequences"]
    )


def test_duplicate_and_reordered_batch_are_not_silently_sorted_away(traces):
    a, _, _ = traces
    sequences = {s["case_id"]: s for s in projection(DecisionExport.model_validate(a))["sequences"]}
    assert [e["event"]["event_id"] for e in sequences["mixed_batch"]["events"]] == list(
        reversed([e["event"]["event_id"] for e in sequences["reversed_batch"]["events"]])
    )
    duplicate = sequences["duplicate_event"]["events"]
    assert duplicate[0]["duplicate"] is False and duplicate[1]["duplicate"] is True
    assert duplicate[1]["policy_calls"] == []


def test_contract_mismatch_and_existing_output_rejected(traces):
    a, b, root = traces
    bad = deepcopy(b)
    bad["contract"] = "future-contract"
    assert compare(a, bad)["status"] == "FAIL"
    with pytest.raises(FileExistsError):
        asyncio.run(export(root / "first"))
    assert correctness(DecisionExport.model_validate(a)) == []
    save_reports(root / "comparison", compare(a, b))
    markdown = (root / "comparison/report.md").read_text(encoding="utf-8")
    assert "SOC Decision Pipeline" in markdown and "actual SOC domain" in markdown
    with pytest.raises(FileExistsError):
        save_reports(root / "comparison", compare(a, b))
