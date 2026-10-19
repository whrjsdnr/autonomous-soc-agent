"""Bind lifecycle claims to final source, screenshots and offline-only receipts."""

import json
from pathlib import Path

from soc_agent.security_ai.collectors.live_contract import bundle
from soc_agent.security_ai.collectors.offline import file_digest
from soc_agent.security_ai.research.models import digest, parse_receipt

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads((ROOT / "docs/linux-soc-v1/zeek-live-controller-evidence.json").read_text())


def test_final_identity_and_historical_uncertainty():
    value = evidence()
    assert value["bundle"] == bundle()
    assert value["bundle_digest"] == digest(bundle())
    assert value["launcher_sha256"] == file_digest(
        ROOT / "src/soc_agent/security_ai/collectors/live_process.py"
    )
    for name, sha in value["source_sha256"].items():
        assert file_digest(ROOT / name) == sha
    assert value["approval_contract"] == "soc-zeek-native-plan:v2"
    assert value["historical"]["controller_exit_cause"] == "UNKNOWN"
    assert value["historical"]["stop_request_origin"] == "UNKNOWN"
    assert value["historical"]["audit_integrity"] == "VERIFIED"
    assert not value["preservation"]["errors"]
    assert all(
        run["exit_code"] == 0
        for group in ("main_runs", "final_affected_runs")
        for run in value["independent_export"][group].values()
    )


def test_real_model_receipts_keep_offline_origin_and_no_replay():
    value = evidence()
    assert value["verdict"] == "PARTIAL"
    assert not value["native_capture_executed"]
    assert not value["privileged_commands_executed"]
    assert not value["test_traffic_generated"]
    assert value["native_inference"] == value["dns9"] == value["operational_promotion"] == "BLOCKED"
    run = value["model_run"]
    assert value["model_stream_plan"]["bundle_digest"] == value["bundle_digest"]
    assert run["audit_digest"] == run["recovered_audit_digest"]
    assert run["queue_final"] == run["inference_queue_final"] == run["restored_new_inferences"] == 0
    assert {record["profile"] for record in value["research_records"]} == {"quality", "edge"}
    for record in value["research_records"]:
        receipt = parse_receipt(record["receipt"])
        assert digest(record["receipt"]) == record["receipt_digest"]
        assert str(receipt.capture_session) == run["session_id"]
        assert receipt.origin == "ZEEK_OFFLINE_PCAP"
        assert receipt.status == "RESEARCH_ONLY" and receipt.write_policy == "WRITE_DENIED"
        assert record["investigation"]["status"] == "ASSESSED_READ_ONLY"
        assert record["investigation"]["checkpoint_restored"]


def test_wslg_scope_dimensions_and_review_hashes():
    value = evidence()
    assert len(value["screenshots"]) == 8
    for shot in value["screenshots"]:
        path = ROOT / "docs/linux-soc-v1" / shot["filename"]
        raw = path.read_bytes()
        assert file_digest(path) == shot["sha256"]
        assert raw[:8] == b"\x89PNG\r\n\x1a\n"
        assert (int.from_bytes(raw[16:20], "big"), int.from_bytes(raw[20:24], "big")) == (
            shot["width"],
            shot["height"],
        )
        assert (shot["width"], shot["height"]) in {(1920, 1080), (1366, 768)}
        assert shot["scope"] == "PREPARATION_MOCK_ENVIRONMENT_NO_AUTHENTICATION_NO_CAPTURE"
    doc = (ROOT / "docs/linux-soc-v1/zeek-live-controller-lifecycle.md").read_text()
    assert value["launcher_sha256"] in doc and value["bundle_digest"] in doc
    assert value["performance"]["samples_per_side"] == 3
