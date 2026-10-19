"""Public claims refer to actual offline receipts and tested source, never Native success."""

import json
from pathlib import Path

from soc_agent.security_ai.collectors.finalization import Closed
from soc_agent.security_ai.collectors.live_contract import bundle
from soc_agent.security_ai.collectors.offline import file_digest
from soc_agent.security_ai.research.models import digest, parse_receipt

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads(
        (ROOT / "docs/linux-soc-v1/zeek-native-finalization-evidence.json").read_text()
    )


def test_current_bundle_and_preservation():
    v = evidence()
    assert v["bundle"] == bundle() and v["bundle_digest"] == digest(bundle())
    assert v["launcher_sha256"] == file_digest(
        ROOT / "src/soc_agent/security_ai/collectors/live_process.py"
    )
    for name, sha in v["source_sha256"].items():
        assert file_digest(ROOT / name) == sha
    assert v["approval_contract"] == "soc-zeek-native-plan:v3"
    assert not v["preservation"]["errors"]
    for group in ("main_runs", "final_affected_runs"):
        assert all(run["exit_code"] == 0 for run in v["independent_export"][group].values())
    assert v["historical"]["counts"] == dict(ready=1, packet=4096, network=106)
    assert v["historical"]["specific_native_fatal_cause"] == "UNKNOWN_STDERR_NOT_RETAINED"
    assert v["historical"]["audit_integrity"] == "VERIFIED"


def test_real_offline_certificates_and_models_not_native_promotion():
    v = evidence()
    assert v["verdict"] == "PARTIAL"
    assert not v["native_capture_executed"] and not v["privileged_commands_executed"]
    assert not v["test_traffic_generated"]
    assert v["native_inference"] == v["dns9"] == v["operational_promotion"] == "BLOCKED"
    assert len(v["final_packet_proofs"]) == 3
    for proof in v["final_packet_proofs"]:
        result = proof["exit"]
        assert result["closed_observed"] and result["container_absent"]
        assert result["cleanup_verified"] and result["protocol_finalized"]
        assert result["exit_code"] == 0 and not result["native_capture"]
        assert result["capture_integrity"] == "UNVERIFIED"
        end = Closed.model_validate(result["closed_detail"])
        end.verify(
            sequence=result["sequence"],
            packets=end.packet_records,
            network=end.network_events,
            dns=end.dns_events,
        )
    assert {row["profile"] for row in v["research_records"]} == {"quality", "edge"}
    for row in v["research_records"]:
        receipt = parse_receipt(row["receipt"])
        assert str(receipt.capture_session) == v["model_run"]["session_id"]
        assert receipt.origin == "ZEEK_OFFLINE_PCAP" and receipt.status == "RESEARCH_ONLY"
        assert row["receipt_digest"] == digest(row["receipt"])
        assert row["investigation"]["status"] == "ASSESSED_READ_ONLY"
        assert row["investigation"]["checkpoint_restored"]
    assert v["model_run"]["audit_digest"] == v["model_run"]["recovered_audit_digest"]
    assert v["model_run"]["restored_new_inferences"] == 0
    assert v["model_stream_plan"]["bundle_digest"] == v["bundle_digest"]


def test_screenshots_and_performance_scope():
    v = evidence()
    assert len(v["screenshots"]) == 2 and v["performance"]["samples_per_side"] == 3
    for shot in v["screenshots"]:
        path = ROOT / "docs/linux-soc-v1" / shot["filename"]
        assert file_digest(path) == shot["sha256"]
        raw = path.read_bytes()
        assert (int.from_bytes(raw[16:20], "big"), int.from_bytes(raw[20:24], "big")) == (
            shot["width"],
            shot["height"],
        )
        assert shot["scope"] == "ACTUAL_WSLG_OFFLINE_PCAP_PACKET_LIMIT_NO_NATIVE_NO_INFERENCE"
    text = (ROOT / "docs/linux-soc-v1/zeek-native-finalization.md").read_text()
    assert v["launcher_sha256"] in text and v["bundle_digest"] in text
    assert v["terminal_authentication"]["sudoers_modified"] is False
