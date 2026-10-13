"""Read-only Gate B diagnostics preserve existing strict contract boundaries."""

import json

import pytest
from pydantic import TypeAdapter, ValidationError
from tests.diagnose_gate_b_packages import sha256_file, write_new_report

from soc_agent.ingestion.models import Event
from soc_agent.security_ai.fusion.compatibility import CLASS_DIRECTIONS
from soc_agent.security_ai.network.schema import NetworkFlowInput
from soc_agent.security_ai.packaging.package import Kind


def test_report_utf8_and_no_overwrite(tmp_path):
    path = tmp_path / "결과.json"
    report = {"scope": "합성 입력 · standalone only"}
    write_new_report(path, report)
    assert json.loads(path.read_text(encoding="utf-8")) == report
    before = sha256_file(path)
    with pytest.raises(FileExistsError):
        write_new_report(path, {"scope": "different"})
    assert sha256_file(path) == before


def test_nonfinite_report_rejected_before_file_creation(tmp_path):
    path = tmp_path / "report.json"
    with pytest.raises(ValueError):
        write_new_report(path, {"score": float("nan")})
    assert not path.exists()


@pytest.mark.parametrize("kind", ["dns_classifier", "network_quality", "network_edge"])
def test_external_kinds_cannot_impersonate_existing_package_contract(kind):
    with pytest.raises(ValidationError):
        TypeAdapter(Kind).validate_python(kind)


def test_dns_cannot_be_coerced_into_authentication_or_network_event():
    with pytest.raises(ValidationError, match="union_tag_invalid"):
        TypeAdapter(Event).validate_python({"event_type": "dns"})


def test_external_features_cannot_bypass_existing_flow_validation():
    with pytest.raises(ValidationError):
        NetworkFlowInput.model_validate({"FQDN_count": 1.0, "Flow Duration": 1.0})
    assert tuple(label for label, _ in CLASS_DIRECTIONS) == (
        "BENIGN",
        "BruteForce",
        "DoS",
        "PortScan",
    )
