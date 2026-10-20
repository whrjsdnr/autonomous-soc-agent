"""Published evidence binds current code without upgrading fixture proof to Native."""

import hashlib
import json
from pathlib import Path

from soc_agent.security_ai.collectors.live_contract import bundle
from soc_agent.security_ai.research.models import digest, parse_receipt

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads(
        (
            ROOT / "docs/linux-soc-v1/zeek-native-attestation-dns-visibility-evidence.json"
        ).read_text()
    )


def test_current_bundle_and_native_boundaries():
    v = evidence()
    assert v["bundle"] == bundle() and v["bundle_digest"] == digest(bundle())
    for name, sha in v["source_sha256"].items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == sha
    assert v["verdict"] == "PARTIAL"
    assert v["same_handle_native_proof"] == "BLOCKED_NO_REVIEWED_NATIVE_PROVIDER"
    assert v["native_counter_retrieval"] == "UNKNOWN"
    assert v["native_ai"] == v["dns9"] == v["operational_gate"] == "BLOCKED"
    assert not any(
        v[k]
        for k in (
            "native_capture_executed",
            "privileged_commands_executed",
            "test_traffic_generated",
            "model_artifacts_modified",
        )
    )
    assert v["preservation"]["errors"] == []


def test_offline_proof_does_not_attest_historical_capture():
    v = evidence()
    probe = v["offline_counter_probe"]
    assert probe["retrieval"] == "UNSUPPORTED" and probe["dropped"] is None
    assert probe["scope"] == "OWNED_OFFLINE_HANDLE_NOT_ZEEK_NATIVE_HANDLE"
    n = v["native_projection"]
    assert n["eligible_windows"] == 0 and n["port53_metadata"] == 68
    assert n["progress"]["finalization_reasons"] == {"PACKET_LIMIT": 51}
    assert v["dns_historical_cause"] == "DNS_VISIBILITY_UNKNOWN"
    m = v["offline_models"]
    assert m["stream_plan"]["bundle_digest"] == v["bundle_digest"]
    assert m["audit_digest"] == m["recovered_audit_digest"]
    assert m["queue_final"] == m["inference_queue_final"] == m["restored_new_inferences"] == 0
    for row in m["records"]:
        receipt = parse_receipt(row["receipt"])
        assert receipt.origin == "ZEEK_OFFLINE_PCAP" and receipt.write_policy == "WRITE_DENIED"
        assert row["investigation"]["status"] == "ASSESSED_READ_ONLY"
    assert all(run["exit_code"] == 0 for run in v["verified_runs"].values())
    for shot in v["screenshots"]:
        assert hashlib.sha256((ROOT / shot["file"]).read_bytes()).hexdigest() == shot["sha256"]
