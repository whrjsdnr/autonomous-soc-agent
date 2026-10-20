"""Current claims are source-bound and keep Native and offline scopes separate."""

import hashlib
import json
from pathlib import Path

from soc_agent.security_ai.research.models import digest, parse_receipt

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads(
        (ROOT / "docs/linux-soc-v1/zeek-realtime-preprocessing-evidence.json").read_text()
    )


def test_source_bundle_preservation_and_security_boundaries():
    v = evidence()
    # Immutable evidence of commit 9d48db5, not authority for a subsequent Bundle.
    assert v["bundle_digest"] == digest(v["bundle"])
    assert v["bundle_digest"] == "953f34ec2f9fa0172968ebc8c3d44022931640bc266753f9fe3920d6f45d98e4"
    assert v["launcher_sha256"] == v["bundle"]["live_process.py"]
    assert v["preservation"]["errors"] == []
    assert v["preservation"]["user_files_checked"] == 132
    assert v["native_ai"] == v["dns9"] == v["operational_gate"] == "BLOCKED"
    assert not v["native_capture_executed"] and not v["privileged_commands_executed"]
    assert not v["test_traffic_generated"] and not v["model_artifacts_modified"]


def test_native_projection_remains_incomplete_and_dns_unknown():
    v = evidence()
    n = v["native_projection"]
    assert n["progress"]["normalized_packets"] == 4096 and n["stream_sequence"] == 4215
    assert n["progress"]["finalization_reasons"] == {"PACKET_LIMIT": 51}
    assert n["eligible_windows"] == 0 and n["feature_metadata_verified"] == 51
    assert n["port53_metadata"] == 68 and n["progress"]["dns"]["records"] == 0
    assert n["progress"]["capture_integrity"] == "UNVERIFIED"
    assert n["native_model_invocations"] == 0
    assert n["dns_reason"] == "UNKNOWN_PORT53_METADATA_WITHOUT_DNS_EVENT"


def test_actual_offline_models_and_independent_recovery():
    v = evidence()
    m = v["offline_models"]
    assert m["input_origin"] == "ZEEK_OFFLINE_PCAP" and not m["native_capture"]
    assert m["stream_plan"]["bundle_digest"] == v["bundle_digest"]
    assert m["queue_final"] == m["inference_queue_final"] == m["restored_new_inferences"] == 0
    assert m["audit_digest"] == m["recovered_audit_digest"]
    assert m["preprocessing"]["feature_decisions"]["ELIGIBLE"] == 1
    assert m["preprocessing"]["completed_flows"] == m["preprocessing"]["incomplete_flows"] == 1
    assert {row["profile"] for row in m["records"]} == {"quality", "edge"}
    for row in m["records"]:
        receipt = parse_receipt(row["receipt"])
        assert receipt.origin == "ZEEK_OFFLINE_PCAP" and receipt.status == "RESEARCH_ONLY"
        assert receipt.write_policy == "WRITE_DENIED"
        assert row["investigation"]["status"] == "ASSESSED_READ_ONLY"
        assert row["investigation"]["checkpoint_restored"]
    assert all(run["exit_code"] == 0 for run in v["verified_runs"].values())
    assert v["harness_incidents"]["long_unix_path"]["product_defect"] is False
    assert (
        v["performance"]["before"]["golden_flow_values"]
        == v["performance"]["after"]["golden_flow_values"]
    )
    for shot in v["screenshots"]:
        assert hashlib.sha256((ROOT / shot["file"]).read_bytes()).hexdigest() == shot["sha256"]
        assert shot["scope"] == "NATIVE_PROTOCOL_FIXTURE_NOT_CAPTURE"
