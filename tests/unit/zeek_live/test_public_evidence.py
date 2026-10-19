"""Public claims are bound to source files, real receipts and WSLg image bytes."""

import json
from pathlib import Path

from soc_agent.security_ai.collectors.offline import IMAGE, file_digest
from soc_agent.security_ai.research.models import digest, parse_receipt

ROOT = Path(__file__).resolve().parents[3]


def evidence():
    return json.loads((ROOT / "docs/linux-soc-v1/zeek-native-live-evidence.json").read_text())


def test_public_run_and_model_identity_not_native_promotion():
    value = evidence()
    # Immutable evidence from commit 4f1c9cf, not an approval of current launcher code.
    assert (
        value["bundle_digest"] == "fd190b1d44f0a5027d110d1395bc4fadaee3c8a32c172f59c9f66d3435ab5144"
    )
    assert value["bundle_digest"] == digest(value["bundle"])
    assert value["image"] == IMAGE and value["verdict"] == "PARTIAL"
    assert not value["native_capture_executed"] and not value["privileged_commands_executed"]
    assert value["native_inference"] == value["dns9"] == "BLOCKED"
    session = value["model_run"]["session_id"]
    assert value["model_stream_process_proof"]["bundle_digest"] == value["bundle_digest"]
    records = value["research_records"]
    assert {r["profile"] for r in records} == {"quality", "edge"}
    for record in records:
        receipt = parse_receipt(record["receipt"])
        assert record["receipt_digest"] == digest(record["receipt"])
        assert str(receipt.capture_session) == session
        assert receipt.origin == "ZEEK_OFFLINE_PCAP" and receipt.status == "RESEARCH_ONLY"
        assert receipt.operational_inference == "BLOCKED" and receipt.write_policy == "WRITE_DENIED"
        assert record["investigation"]["status"] == "ASSESSED_READ_ONLY"
    assert value["model_run"]["restored_new_inferences"] == 0
    assert value["independent_export"]["product_distinct_passes"] == 728
    assert all(r["exit_code"] == 0 for r in value["independent_export"]["main_runs"].values())


def test_public_wslg_images_scope_and_digest():
    value = evidence()
    assert len(value["screenshots"]) == 8
    for image in value["screenshots"]:
        path = ROOT / "docs/linux-soc-v1" / image["filename"]
        assert path.suffix == ".png" and file_digest(path) == image["sha256"]
        raw = path.read_bytes()
        assert raw[:8] == b"\x89PNG\r\n\x1a\n"
        w = int.from_bytes(raw[16:20], "big")
        h = int.from_bytes(raw[20:24], "big")
        assert (w, h) in {(1920, 1080), (1366, 768)}
        assert image["scope"] == "PREPARATION_MOCK_ENVIRONMENT_NO_AUTHENTICATION_NO_CAPTURE"
    text = (ROOT / "docs/linux-soc-v1/zeek-native-live-integration.md").read_text()
    assert value["launcher_sha256"] in text and value["bundle_digest"] in text
