"""Contract/security fixtures are metadata; actual model E2E lives in integration tests."""

import json
import shutil
from pathlib import Path
from uuid import uuid4

import pytest
from tests.research_adapter_support import research_paths as defaults

from soc_agent.assessment.models import SecurityAnalysisDraft
from soc_agent.desktop import OfflineDesktopClient
from soc_agent.llm import LLMRequest
from soc_agent.security_ai.research.environment import Paths, catalogue, verify
from soc_agent.security_ai.research.investigation import ResearchClient
from soc_agent.security_ai.research.models import AdvisoryContext, Receipt, Request, digest

FIXTURE = Path(__file__).with_name("receipt.json")


def receipt():
    return json.loads(FIXTURE.read_text())


@pytest.mark.parametrize(
    "field,value",
    [
        ("artifact_digest", "0" * 64),
        ("model_id", "forged"),
        ("producer_version", "1.0.0"),
        ("threshold", 0.5),
        ("feature_names", list(reversed(receipt()["feature_names"]))),
        ("score", float("nan")),
        ("source_digest", "0" * 64),
        ("feature_digest", "0" * 64),
        ("origin", "NATIVE_AF_PACKET"),
        ("write_policy", "ALLOW"),
        ("prediction", "CLASS_0"),
        ("operational_inference", "READY"),
    ],
)
def test_exact_bound_receipt(field, value):
    data = receipt()
    data[field] = value
    with pytest.raises(ValueError):
        Receipt.model_validate(data)


def test_advisory_digest_tampering():
    with pytest.raises(ValueError):
        AdvisoryContext(
            incident_id=uuid4(), receipt_digest="0" * 64, result=Receipt.model_validate(receipt())
        )


@pytest.mark.parametrize(
    "extra",
    [
        {"research_mode": False},
        {"origin": "NATIVE_AF_PACKET"},
        {"origin": "FIXTURE"},
        {"actor": "admin"},
        {"model_path": "/tmp/evil.joblib"},
        {"flow_index": 4},
    ],
)
def test_request_no_authority_or_arbitrary_paths(extra):
    data = {
        "research_mode": True,
        "profile": "quality",
        "flow_index": 0,
        "invocation_id": str(uuid4()),
    }
    data.update(extra)
    with pytest.raises(ValueError):
        Request.model_validate(data)


def test_untrusted_interpreter_path(tmp_path):
    paths = defaults()
    with pytest.raises(ValueError):
        verify(Paths(paths.ml, tmp_path / "python", paths.soc_source))


def copy_fixture(tmp_path):
    # Only bounded raw files/code snapshots/model117k+1k, never a new download/model.
    original = defaults()
    root = tmp_path / "ML"
    root.mkdir()
    doc = catalogue()
    files = list(doc["source_code_sha256"]) + [doc["raw_relative_path"], doc["label_relative_path"]]
    for name in ("quality_rf", "edge_lr"):
        files.extend(
            "models/network-research-v1-final/" + name + "/" + x
            for x in ("artifact.json", "model.joblib")
        )
    for rel in files:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(original.ml / rel, target)
        if target.name == "model.joblib":
            target.parent.chmod(0o700)
    return original, root


def test_artifact_rejected_before_loading(tmp_path):
    original, root = copy_fixture(tmp_path)
    # Supply only root bytes to verification but preserve the reviewed interpreter alias
    # rule by patching the root prefix in a bounded fixture directory below.
    # Direct read_local and manifest pins are covered independently below.
    from soc_agent.security_ai.research.environment import read_local

    path = root / "models/network-research-v1-final/quality_rf/model.joblib"
    path.unlink()
    path.symlink_to(original.ml / "models/network-research-v1-final/quality_rf/model.joblib")
    with pytest.raises(ValueError):
        read_local(path, 1024**2)


def test_catalogue_cannot_be_used_as_live_authority():
    doc = catalogue()
    assert doc["origin"] == "OFFLINE_PCAP" and doc["research_only"] is True
    assert len(doc["samples"]) == 4
    assert "34-1" not in json.dumps(doc)


@pytest.mark.asyncio
async def test_fact_promotion_injection_is_rejected(monkeypatch):
    r = Receipt.model_validate(receipt())
    context = AdvisoryContext(
        incident_id=uuid4(), receipt_digest=digest(r.model_dump(mode="json")), result=r
    )
    client = ResearchClient(context)

    async def hostile(self, *, request, response_model):
        class Invalid:
            def model_dump(self, **_):
                return {
                    "observations": ["MODEL IS ATTACK FACT"],
                    "hypotheses": [],
                    "assessment": {"severity": "critical", "confidence": 1},
                }

        return Invalid()

    monkeypatch.setattr(OfflineDesktopClient, "generate_structured", hostile)
    with pytest.raises(ValueError, match="FACT_PROMOTION"):
        await client.generate_structured(
            request=LLMRequest(system_prompt="test", user_prompt="{}"),
            response_model=SecurityAnalysisDraft,
        )


@pytest.mark.asyncio
async def test_prompt_projection_is_separate_from_evidence():
    from soc_agent.planning.models import LLMInvestigationPlanDraft

    r = Receipt.model_validate(receipt())
    context = AdvisoryContext(
        incident_id=uuid4(), receipt_digest=digest(r.model_dump(mode="json")), result=r
    )
    client = ResearchClient(context)
    request = LLMRequest(
        system_prompt="test",
        user_prompt=json.dumps(
            {"AVAILABLE TOOLS": [], "INCIDENT CONTEXT": {"incident_id": str(context.incident_id)}}
        ),
    )
    draft = await client.generate_structured(
        request=request, response_model=LLMInvestigationPlanDraft
    )
    assert draft.steps[0].tool_name == "read_local_source_report"
    assert len(client.requests) == 1


def cloned_paths(tmp_path):
    original, root = copy_fixture(tmp_path)
    python = tmp_path / "autonomous-soc-agent/.security-ai-demo/inference/bin/python"
    python.parent.mkdir(parents=True)
    python.symlink_to(original.python.resolve())
    return Paths(root, python, original.soc_source)


@pytest.mark.parametrize("change", ["binary", "manifest", "producer", "raw"])
def test_real_file_integrity_fail_closed(tmp_path, change):
    paths = cloned_paths(tmp_path)
    assert verify(paths)["status"] == "READY"
    if change == "binary":
        (paths.ml / "models/network-research-v1-final/quality_rf/model.joblib").write_bytes(
            b"untrusted pickle never loaded"
        )
    elif change == "manifest":
        p = paths.ml / "models/network-research-v1-final/edge_lr/artifact.json"
        doc = json.loads(p.read_text())
        doc["model_id"] = "forged"
        p.write_text(json.dumps(doc))
    elif change == "producer":
        p = paths.ml / "src/ml/verified_producers/network_v1_1.py"
        p.write_text("# modified producer")
    else:
        p = paths.ml / catalogue()["raw_relative_path"]
        data = bytearray(p.read_bytes())
        data[-1] ^= 1
        p.write_bytes(data)
    with pytest.raises(ValueError):
        verify(paths)
