"""Current startup claims are bound to reviewed source and offline-only evidence."""

import json
from pathlib import Path

from soc_agent.security_ai.research.models import digest, parse_receipt

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads((ROOT / "docs/linux-soc-v1/zeek-one-command-evidence.json").read_text())


def test_current_bundle_source_and_unmodified_security_scope():
    v = evidence()
    # Immutable evidence of commit 7dd0f66, not authority for later bundles.
    assert v["bundle_digest"] == digest(v["bundle"])
    assert v["launcher_sha256"] == v["bundle"]["live_process.py"]
    assert v["approval_contract"] == "soc-zeek-native-plan:v4"
    assert v["source_parent_head"] == "604e26508f80f2413fa4645325d528538a8ad818"
    assert not v["preservation"]["errors"]
    assert v["preservation"]["user_files_checked"] == 132
    assert v["preservation"]["protected_files_checked"] == 245
    assert not v["native_capture_executed"] and not v["privileged_commands_executed"]
    assert not v["test_traffic_generated"] and not v["sudoers_modified"]
    assert v["native_ai"] == v["dns9"] == v["operational_gate"] == "BLOCKED"
    assert v["verdict"] == "PARTIAL"


def test_actual_offline_models_and_audit_do_not_promote_native():
    v = evidence()
    for group in ("main_runs", "final_affected_runs"):
        assert all(run["exit_code"] == 0 for run in v["independent_export"][group].values())
    run = v["model_run"]
    assert run["input_origin"] == "ZEEK_OFFLINE_PCAP" and not run["native_capture"]
    assert run["queue_final"] == run["inference_queue_final"] == run["restored_new_inferences"] == 0
    assert run["audit_digest"] == run["recovered_audit_digest"]
    assert v["model_stream_plan"]["bundle_digest"] == v["bundle_digest"]
    assert {r["profile"] for r in v["research_records"]} == {"quality", "edge"}
    for row in v["research_records"]:
        receipt = parse_receipt(row["receipt"])
        assert str(receipt.capture_session) == run["session_id"]
        assert receipt.origin == "ZEEK_OFFLINE_PCAP" and receipt.write_policy == "WRITE_DENIED"
        assert receipt.status == "RESEARCH_ONLY"
        assert row["investigation"]["status"] == "ASSESSED_READ_ONLY"
        assert row["investigation"]["checkpoint_restored"]


def test_history_uncertainty_and_performance_scope():
    v = evidence()
    assert v["historical"]["audit_integrity"] == "VERIFIED"
    assert v["historical"]["audit_kinds"]["COLLECTOR_STARTED"] == 1
    assert v["historical"]["specific_interruption_cause"] == "UNKNOWN"
    assert not v["historical"]["exit"]["closed_observed"]
    assert not v["historical"]["exit"]["cleanup_verified"]
    assert v["performance"]["samples_per_side"] == 3
    assert v["performance"]["native_authentication_overhead"] == "UNKNOWN_NOT_EXECUTED"
    for side in ("before", "after"):
        assert v["performance"][side]["idle_child_processes"] == 0
        assert v["performance"][side]["remaining_child_processes"] == 0
    text = (ROOT / "docs/linux-soc-v1/zeek-one-command-startup.md").read_text()
    assert v["launcher_sha256"] in text and v["bundle_digest"] in text
