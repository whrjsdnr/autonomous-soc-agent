"""DNS Native contract and pre-deserialization integrity boundaries, no model loading."""

import shutil
from pathlib import Path
from uuid import uuid4

import pytest
from tests.research_adapter_support import research_paths

from soc_agent.security_ai.research.dns import PIN, catalogue, verify
from soc_agent.security_ai.research.environment import Paths
from soc_agent.security_ai.research.models import AdvisoryContext, DNSReceipt, Request, digest


def receipt():
    d = catalogue()
    item = d["fixtures"][0]
    return DNSReceipt(
        profile="dns",
        request_digest="0" * 64,
        invocation_id=uuid4(),
        flow_index=0,
        fixture_id=item["id"],
        input_digest=item["input_digest"],
        feature_names=d["feature_names"],
        score=0.55859375,
        prediction="CLASS_1",
        inferred_at="2026-10-15T00:00:00Z",
        inference_latency_ms=1,
        worker_limits={
            "address_space_bytes": 3221225472,
            "cpu_seconds": 15,
            "result_file_bytes": 131072,
            "network": "DENIED",
        },
        provenance_digest=digest(
            {
                "catalogue": PIN,
                "input_digest": item["input_digest"],
                "model": d["model"]["artifacts"],
                "source": item["source"],
            }
        ),
    ).model_dump(mode="json")


@pytest.mark.parametrize(
    "field,value",
    [
        ("origin", "NATIVE_AF_PACKET"),
        ("status", "OPERATIONAL_READY"),
        ("artifact_digest", "0" * 64),
        ("scaler_digest", "0" * 64),
        ("feature_contract_digest", "0" * 64),
        ("input_digest", "0" * 64),
        ("feature_names", list(reversed(catalogue()["feature_names"]))),
        ("model_id", "forged"),
        ("producer_parity", "VERIFIED"),
        ("operational_inference", "READY"),
        ("write_policy", "ALLOW"),
        ("provenance_digest", "0" * 64),
        ("score", float("nan")),
        ("threshold", 0.7),
        ("prediction", "CLASS_0"),
    ],
)
def test_dns_exact_receipt(field, value):
    d = receipt()
    d[field] = value
    with pytest.raises(ValueError):
        DNSReceipt.model_validate(d)


def test_context_does_not_alias_network_or_authentication():
    p = DNSReceipt.model_validate(receipt())
    with pytest.raises(ValueError):
        AdvisoryContext(
            incident_id=uuid4(), receipt_digest=digest(p.model_dump(mode="json")), result=p
        )
    context = AdvisoryContext(
        contract="soc-dns-research-advisory:v1",
        incident_id=uuid4(),
        receipt_digest=digest(p.model_dump(mode="json")),
        result=p,
    )
    assert context.role == "UNTRUSTED_MODEL_INFERENCE_NOT_EVIDENCE"
    with pytest.raises(ValueError):
        Request(
            research_mode=True,
            profile="dns",
            flow_index=0,
            invocation_id=uuid4(),
            origin="FIXTURE",
            raw_fqdn="example.invalid",
        )


def clone(tmp_path):
    original = research_paths()
    ml = tmp_path / "ML"
    pkg = catalogue()["package_sha256"]
    for rel in pkg:
        p = ml / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2((original.producer_source or original.ml) / rel, p)
    python = tmp_path / "autonomous-soc-agent/.security-ai-demo/inference/bin/python"
    python.parent.mkdir(parents=True)
    python.symlink_to(original.python.resolve())
    rel = "lib/python3.12/site-packages/ai_edge_litert-2.3.0.dist-info/METADATA"
    dst = python.parent.parent / rel
    dst.parent.mkdir(parents=True)
    shutil.copy2(original.python.parent.parent / rel, dst)
    for entry in catalogue()["model"]["artifacts"].values():
        rel = "autonomous-soc-agent/.security-ai-demo/artifacts/dns/" + entry["filename"]
        dst = tmp_path / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original.ml.parent / rel, dst)
    return Paths(ml, python, original.soc_source)


@pytest.mark.parametrize("change", ["model", "scaler", "schema", "package", "link"])
def test_trusted_files_checked_before_deserialization(tmp_path, change):
    paths = clone(tmp_path)
    assert verify(paths)["status"] == "READY"
    root = paths.ml.parent / "autonomous-soc-agent/.security-ai-demo/artifacts/dns"
    if change in ("model", "scaler", "link"):
        rel = "model/dnn_int8.tflite" if change != "scaler" else "preprocessor/scaler.joblib"
        p = root / rel
        if change == "link":
            p.unlink()
            p.symlink_to(Path("/dev/null"))
        else:
            p.write_bytes(b"untrusted never deserialize")
    else:
        p = (
            paths.ml
            / "packages/dns-security-ai/src/dns_security_ai"
            / ("feature_contract.json" if change == "schema" else "predictor.py")
        )
        p.write_text("{}")
    with pytest.raises(ValueError):
        verify(paths)


def test_fixed_fixture_inputs_no_raw_dns_conversion():
    d = catalogue()
    assert len(d["fixtures"]) == 2 and len(d["feature_names"]) == 9
    for item in d["fixtures"]:
        payload = dict(zip(d["feature_names"], item["values"], strict=True))
        assert digest(payload) == item["input_digest"]
