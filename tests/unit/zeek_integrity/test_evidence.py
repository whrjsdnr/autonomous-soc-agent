"""Published claims distinguish Native evidence from offline model verification."""

import hashlib
import json
from pathlib import Path

from soc_agent.security_ai.collectors.live_contract import bundle
from soc_agent.security_ai.research.models import digest, parse_receipt

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads(
        (ROOT / "docs/linux-soc-v1/zeek-native-capture-integrity-evidence.json").read_text()
    )


def test_reviewed_sources_bundle_and_preservation():
    v = evidence()
    assert v["bundle"] == bundle()
    assert v["bundle_digest"] == digest(bundle())
    assert v["launcher_sha256"] == bundle()["live_process.py"]
    for name, sha in v["source_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha
    assert not v["preservation"]["errors"]
    assert v["preservation"]["user_files_checked"] == 132
    assert v["preservation"]["protected_files_checked"] == 267
    assert not any(
        v[k]
        for k in (
            "native_capture_executed",
            "privileged_commands_executed",
            "test_traffic_generated",
            "model_artifacts_modified",
        )
    )
    assert v["native_ai"] == v["dns9"] == v["operational_gate"] == "BLOCKED"


def test_native_counter_and_incomplete_flow_evidence_never_promotes_ai():
    v = evidence()
    h, s = v["historical"], v["historical"]["summary"]["session"]
    assert s["packet_records"] == 4096 and h["stream_sequence"] == 4215
    assert s["network_events"] == 117 and s["dns_events"] == 0
    assert s["process"] == s["stream"] == "VERIFIED"
    assert s["counter"]["reported_drops"] == 0
    assert s["counter"]["query_status"] == "UNKNOWN"
    assert s["counter"]["kernel_drops_verified"] is None
    assert s["capture"] == "UNVERIFIED" and s["gaps"] is None
    assert h["metadata_arithmetic_matched"] == 51
    assert h["summary"]["flow_reasons"] == {"PACKET_LIMIT": 51}
    assert h["summary"]["timeout_complete_flows"] == 0
    assert s["port53_metadata_packets"] == 68
    assert s["dns_visibility"] == "UNKNOWN_PORT53_METADATA_WITHOUT_DNS_EVENT"
    assert h["native_model_receipts"] == h["native_investigations"] == 0
    assert h["audit_integrity"] == h["source_event_audit_binding"] == "VERIFIED"


def test_actual_offline_receipts_recovery_and_retained_failures():
    v = evidence()
    m = v["offline_models"]
    assert m["input_origin"] == "ZEEK_OFFLINE_PCAP" and not m["native_capture"]
    assert m["stream_plan"]["bundle_digest"] == v["bundle_digest"]
    assert m["queue_final"] == m["inference_queue_final"] == m["restored_new_inferences"] == 0
    assert m["audit_digest"] == m["recovered_audit_digest"]
    assert {r["profile"] for r in m["records"]} == {"quality", "edge"}
    for row in m["records"]:
        receipt = parse_receipt(row["receipt"])
        assert receipt.origin == "ZEEK_OFFLINE_PCAP"
        assert receipt.status == "RESEARCH_ONLY" and receipt.write_policy == "WRITE_DENIED"
        assert str(receipt.capture_session) == m["session_id"]
        assert row["investigation"]["status"] == "ASSESSED_READ_ONLY"
        assert row["investigation"]["checkpoint_restored"]
        assert row["investigation"]["provider_calls"] == 0
    assert all(r["exit_code"] == 0 for r in v["verified_runs"].values())
    assert v["known_failures"]["resource"]["automatic_retry"] is False
    assert v["known_failures"]["resource"]["failure"] == "ZEEK_MODEL_HEADROOM_REQUIRED"
    assert v["known_failures"]["exit_sidecar_race"]["regression_added"]
    assert v["performance"]["samples_per_side"] == 3
    for shot in v["screenshots"]:
        assert hashlib.sha256((ROOT / shot["file"]).read_bytes()).hexdigest() == shot["sha256"]
        assert shot["origin"] == "NATIVE_PROTOCOL_FIXTURE_NOT_CAPTURE"
    text = (ROOT / "docs/linux-soc-v1/zeek-native-capture-integrity.md").read_text()
    assert v["launcher_sha256"] in text and v["bundle_digest"] in text
