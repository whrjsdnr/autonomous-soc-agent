import json
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest
from tests.total_monitoring_support import dns_packet

from soc_agent.security_ai.operational.network_capture import total_session
from soc_agent.security_ai.operational.network_capture.stream_session import StreamPolicy
from soc_agent.security_ai.research.models import SPECS, digest
from soc_agent.security_ai.research.total_dns import DNSDiagnostics


def test_console_entry_and_actual_fixture_export_evidence():
    root = Path(__file__).resolve().parents[3]
    assert tomllib.loads((root / "pyproject.toml").read_text())["project"]["scripts"] == {
        "soc-agent": "soc_agent.cli:main"
    }
    data = json.loads(
        (root / "docs/linux-soc-v1/unified-total-monitoring-fixture-evidence.json").read_text()
    )
    result = data["result"]
    assert data["document_digest"] == digest(result)
    assert result["research_status"] == "RESEARCH_ONLY"
    assert result["input_origin"] == "FIXTURE"
    assert data["network_socket_attempts_blocked"] == 0
    assert result["dns"]["dns9_inference"] == "BLOCKED"
    assert len(result["records"]) == 4
    assert "192.0.2." not in json.dumps(result)
    for record in result["records"]:
        receipt = record["model_receipt"]
        assert receipt["artifact_digest"] == SPECS[receipt["profile"]]["sha256"]
        assert (
            receipt["feature_contract_digest"]
            == "84ba0916f0ce4e9e12bb70712db2cd1eaea84ba4173acd57b647faf38efb1c6e"
        )
        assert receipt["worker_peak_rss_bytes"] > 0
        assert receipt["inference_latency_ms"] >= 0
        assert record["investigation_summary"]["status"] == "ASSESSED_READ_ONLY"


@pytest.mark.parametrize("tcp", [True, False])
def test_dns_binary_query_response_and_privacy(tmp_path, tcp):
    session = total_session.prepare(tmp_path / "new", StreamPolicy())
    owner = SimpleNamespace(session=session)
    dns = DNSDiagnostics(session.session_id)
    query = dns.observe(dns_packet(owner, 0, tcp=tcp), 1)
    response = dns.observe(dns_packet(owner, 0.5, tcp=tcp, response=True), 2)
    assert query[0]["status"] == "QUERY"
    assert response[0]["status"] == "MATCHED_RESPONSE"
    assert response[0]["latency_seconds"] == 0.5
    assert dns.snapshot()["dns9_inference"] == "BLOCKED"
    assert "example" not in json.dumps(dns.snapshot())
    assert total_session.load(tmp_path / "new") == session


def test_dns_duplicate_missing_and_abort(tmp_path):
    session = total_session.prepare(tmp_path / "new", StreamPolicy())
    owner = SimpleNamespace(session=session)
    dns = DNSDiagnostics(session.session_id)
    dns.observe(dns_packet(owner, 0), 1)
    assert dns.observe(dns_packet(owner, 1), 2)[0]["status"] == "AMBIGUOUS_QUERY"
    assert dns.observe(dns_packet(owner, 2, response=True), 3)[0]["status"] == "AMBIGUOUS_RESPONSE"
    assert dns.observe(dns_packet(owner, 8, malformed=True), 4)[0]["status"] == "PARSE_FAILURE"
    dns.observe(dns_packet(owner, 9), 5)
    assert dns.finish(aborted=True)[0]["status"] == "UNVERIFIED_ABORT"
    assert not dns.pending


def test_total_scope_is_separate_and_tampering_fails(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="EXACT_REVIEWED_POLICY"):
        total_session.prepare(tmp_path / "bad", StreamPolicy(seconds=301))
    directory = tmp_path / "new"
    session = total_session.prepare(directory, StreamPolicy())
    assert "total_helper" in total_session.instructions(directory, session)["command"]
    data = json.loads((directory / "session.json").read_text())
    data["code_sha256"]["total_helper.py"] = "f" * 64
    (directory / "session.json").write_text(json.dumps(data))
    with pytest.raises(ValueError, match="IDENTITY"):
        total_session.load(directory)
    monkeypatch.setattr(total_session, "code_hashes", lambda: {})
    with pytest.raises(ValueError, match="BUNDLE_MISMATCH"):
        total_session.verify_bundle()
