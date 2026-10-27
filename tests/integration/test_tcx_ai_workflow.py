"""Synthetic TCX evidence + actual RF/LR, or explicit Mock transport for Native gates."""

import hashlib
import json
from datetime import timedelta
from uuid import UUID

import pytest

from soc_agent.approval import ApprovalManager
from soc_agent.cli import main
from soc_agent.security_ai.ebpf_tc.capture_evidence import assess_capture
from soc_agent.security_ai.offline_workflow import OfflineWorkflow, verify_result
from soc_agent.security_ai.research.adapter import ResearchAdapter
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.tcx_analysis import METADATA, analysis_action
from soc_agent.security_ai.tcx_input import candidates
from soc_agent.security_ai.workflow_models import TCXAnalysisJob
from soc_agent.state.evidence import utc_now
from tests.research_adapter_support import research_paths
from tests.unit.ebpf_tc.test_batch2_window import complete

SESSION = UUID("4dcc8938-d102-4bd8-8031-e57a13d27279")
NS = "net:[4026532232]"


def job(native=False):
    p, _, w, clock, c, a = complete()
    p["plan"].update(session_id=str(SESSION), net_namespace=NS, interface="lo", hook="INGRESS")
    capture = assess_capture(
        c,
        a,
        p,
        closed=True,
        error=None,
        source=1 if native else 2,
        scope=dict(program_sha256="a" * 64, approval_digest="b" * 64),
        cpu_windows=w,
        clock_samples=clock,
    )
    transport = dict(
        processing=p,
        source="KERNEL_TCX_NATIVE" if native else "ORDINARY_UID_PACKET_FIXTURE",
        capture_evidence=capture,
        counter_evidence=c,
        delivery_accounting=a,
        cpu_windows=w,
        clock_samples=clock,
        terminal_closed_observed=True,
        drain_state="VERIFIED",
        error=None,
        cleanup_error=None,
    )
    return TCXAnalysisJob(
        kind="tcx_analysis",
        origin="REAL_NATIVE" if native else "FIXTURE",
        session=SESSION,
        namespace=NS,
        release_manifest="f" * 64,
        result=dict(tcx=dict(release_manifest_digest="f" * 64, data_plane=transport)),
    )


@pytest.mark.asyncio
async def test_fixture_tcx_actual_models_and_existing_investigation(tmp_path):
    j = job()
    _, _, rs = candidates(j)
    assert [r["input_state"] for r in rs] == ["ELIGIBLE", "INCOMPLETE"]
    w = OfflineWorkflow(tmp_path / "attempt", paths=research_paths())
    r = await w.run(j)
    assert r.eligibility == "ELIGIBLE" and len(r.inference) == 2
    assert all(x.receipt["origin"] == "FIXTURE" for x in r.inference)
    assert {x.model_id for x in r.inference} == {
        "linux-network14-research-v1-quality_rf",
        "linux-network14-research-v1-edge_lr",
    }
    assert r.external_provider_calls == 0 and r.native_execution is False
    assert r.evidence[0].namespace == NS and r.evidence[0].session == str(SESSION)
    assert r.inference[0].feature_fingerprint == rs[0]["feature_fingerprint"]
    assert verify_result(w.directory) == r


@pytest.mark.asyncio
async def test_unapproved_native_eligible_vector_never_calls_adapter(tmp_path, monkeypatch):
    calls = []

    async def forbidden(*a, **kw):
        calls.append(1)
        raise AssertionError("Unauthorized model execution")

    monkeypatch.setattr(ResearchAdapter, "infer", forbidden)
    w = OfflineWorkflow(tmp_path / "run", paths=research_paths())
    r = await w.run(job(native=True))
    assert r.eligibility == "ELIGIBLE" and not r.inference and calls == []
    assert "TCX_MODEL_ACTION_APPROVAL_REQUIRED" in r.reasons
    assert r.classification == "MODEL_ERROR" and r.investigation is None
    pending = json.loads((w.directory / "tcx-model-approval-pending.json").read_bytes())
    assert pending["status"] == "pending" and pending["decision"] is None
    assert r.evidence[0].integrity == "DECLARED_UNATTESTED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        "window",
        "counter",
        "epoch",
        "clock",
        "namespace",
        "session",
        "release",
        "fingerprint",
        "schema",
        "flow_stop",
        "unknown",
        "drain",
    ],
)
async def test_invalid_or_incomplete_never_calls_inference(tmp_path, monkeypatch, fault):
    j = job()
    raw = j.model_dump(mode="json")
    t = raw["result"]["tcx"]["data_plane"]
    s = t["processing"]
    if fault == "window":
        t["cpu_windows"] = []
    elif fault == "counter":
        t["counter_evidence"]["totals"]["emitted"] += 1
    elif fault == "epoch":
        s["plan"]["generation"] = 99
    elif fault == "clock":
        t["clock_samples"] = []
    elif fault == "namespace":
        raw["namespace"] = "net:[4026531833]"
    elif fault == "session":
        raw["session"] = "cba8d0cb-9db6-4f8e-b1ce-6a8376997582"
    elif fault == "release":
        raw["release_manifest"] = "e" * 64
    elif fault == "fingerprint":
        s["feature_tail"][0]["values_digest"] = "0" * 64
    elif fault == "schema":
        s["feature_tail"][0]["feature_names"].reverse()
    elif fault == "flow_stop":
        s["feature_tail"][0]["close_reason"] = "CAPTURE_STOP"
    elif fault == "unknown":
        s["feature_tail"][0].pop("values")
    elif fault == "drain":
        t["drain_state"] = "UNVERIFIED"

    async def forbidden(*a, **kw):
        raise AssertionError("Bad input reached model")

    monkeypatch.setattr(ResearchAdapter, "infer", forbidden)
    r = await OfflineWorkflow(tmp_path / "run", paths=research_paths()).run(
        TCXAnalysisJob.model_validate(raw)
    )
    assert not r.inference and r.eligibility in ("INVALID", "INCOMPLETE")
    assert r.external_provider_calls == 0


@pytest.mark.asyncio
async def test_fixture_cannot_relabel_native_source(tmp_path, monkeypatch):
    raw = job(native=True).model_dump(mode="json")
    raw["origin"] = "FIXTURE"
    r = await OfflineWorkflow(tmp_path / "run", paths=research_paths()).run(
        TCXAnalysisJob.model_validate(raw)
    )
    assert r.eligibility == "INVALID" and not r.inference


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault", ["wrong_action", "expired", "pending", "unbound", "other_namespace"]
)
async def test_existing_approval_contract_fails_closed(tmp_path, monkeypatch, fault):
    j = job(native=True)
    out = tmp_path / "run"
    a = analysis_action(j, out)
    m = ApprovalManager()
    req = m.create(
        incident_id=a.incident_id,
        metadata=METADATA,
        reason="SYNTHETIC TEST ONLY",
        action_id=a.action_id,
        action_input_json=a.tool_input,
        expires_at=utc_now() + timedelta(minutes=3),
    )
    approval = m.approve(req.approval_id, actor="TEST_ONLY")
    values = approval.model_dump(mode="json")
    if fault == "wrong_action":
        values["action_id"] = "43906e8e-bdc1-4c7d-a4af-87bc7cf29ead"
    elif fault == "expired":
        values["created_at"] = (utc_now() - timedelta(hours=2)).isoformat()
        values["expires_at"] = (utc_now() - timedelta(hours=1)).isoformat()
        values["decision"]["decided_at"] = (utc_now() - timedelta(minutes=90)).isoformat()
    elif fault == "pending":
        values.update(status="pending", decision=None)
    elif fault == "unbound":
        values.update(action_id=None, action_input_json=None)
    else:
        body = json.loads(values["action_input_json"])
        body["namespace"] = "net:[4026531833]"
        values["action_input_json"] = json.dumps(body)
    from soc_agent.approval import ApprovalRequest

    async def forbidden(*a, **kw):
        raise AssertionError("Unapproved inference")

    monkeypatch.setattr(ResearchAdapter, "infer", forbidden)
    r = await OfflineWorkflow(
        out, paths=research_paths(), tcx_approval=ApprovalRequest.model_validate(values)
    ).run(j)
    assert not r.inference and r.classification == "MODEL_ERROR"


def test_supervisor_cli_pinned_normalization(tmp_path, capsys):
    j = job()
    p = tmp_path / "supervisor.json"
    p.write_text(json.dumps(j.result))
    out = tmp_path / "run"
    args = [
        "analyze-offline",
        "--input",
        str(p),
        "--input-sha256",
        hashlib.sha256(p.read_bytes()).hexdigest(),
        "--output",
        str(out),
        "--tcx-namespace",
        NS,
        "--tcx-session",
        str(SESSION),
        "--tcx-release-manifest",
        j.release_manifest,
        "--research-ml-root",
        str(research_paths().ml),
    ]
    assert main(args) == 0
    r = verify_result(out)
    assert len(r.inference) == 2 and r.evidence[0].origin == "FIXTURE"
    assert main(["analyze-offline", "--verify", "--output", str(out)]) == 0
    assert main(args) == 2


def test_source_mutation_changes_exact_action_input(tmp_path):
    j = job()
    a = analysis_action(j, tmp_path / "run")
    changed = j.model_copy(update={"profiles": ("edge",)})
    assert analysis_action(changed, tmp_path / "run").action_id != a.action_id
    assert analysis_action(j, tmp_path / "other").action_id != a.action_id


@pytest.mark.asyncio
async def test_exact_existing_governance_native_path_uses_mock_models_only(tmp_path, monkeypatch):
    """MOCK receipts and synthetic Native-shaped evidence, not real Native validation."""
    from soc_agent.security_ai.research.models import SPECS
    from soc_agent.security_ai.tcx_analysis import incident_id
    from soc_agent.security_ai.tcx_input import VectorReceipt, vector

    j = job(native=True)
    directory = tmp_path / "mock-native"
    action = analysis_action(j, directory)
    m = ApprovalManager()
    pending = m.create(
        incident_id=incident_id(j),
        metadata=METADATA,
        reason="SYNTHETIC MOCK TEST ONLY NO HUMAN AUTHORITY",
        action_id=action.action_id,
        action_input_json=action.tool_input,
        expires_at=utc_now() + timedelta(minutes=2),
    )
    approval = m.approve(pending.approval_id, actor="TEST_ONLY_NOT_AN_OPERATOR")
    seen = []

    async def mocked(self, request):
        assert self.authorize_tcx is not None
        self.authorize_tcx(request)
        seen.append(request.profile)
        row, _ = vector(request.job, request.flow_id, request.input_receipt_digest)
        spec = SPECS[request.profile]
        r = VectorReceipt(
            origin="REAL_NATIVE",
            profile=request.profile,
            request_digest=digest(request.model_dump(mode="json")),
            invocation_id=request.invocation_id,
            source_digest=digest(j.model_dump(mode="json")),
            session=j.session,
            namespace=j.namespace,
            release_manifest=j.release_manifest,
            flow_id=request.flow_id,
            input_receipt_digest=request.input_receipt_digest,
            feature_fingerprint=row["values_digest"],
            feature_names=row["feature_names"],
            feature_values=row["values"],
            model_id=spec["model_id"],
            artifact_digest=spec["sha256"],
            model_manifest_digest=spec["manifest"],
            score=0.99,
            threshold=spec["threshold"],
            prediction="CLASS_1",
            inferred_at=utc_now(),
            inference_latency_ms=0,
            worker_limits=dict(
                address_space_bytes=3221225472,
                cpu_seconds=15,
                result_file_bytes=131072,
                network="DENIED",
            ),
        )
        return dict(status="SUCCESS", receipt=r.model_dump(mode="json"))

    monkeypatch.setattr(ResearchAdapter, "infer", mocked)
    w = OfflineWorkflow(directory, paths=research_paths(), tcx_approval=approval)
    r = await w.run(j)
    assert seen == ["quality", "edge"] and len(r.inference) == 2
    assert r.fusion["agreement_state"] == "consistent" and r.fusion["confidence_state"] == "unknown"
    assert r.investigation["status"] == "COMPLETED_READ_ONLY" and r.llm_mode == "SCRIPTED"
    assert r.native_execution is False and r.external_provider_calls == 0
    assert verify_result(directory) == r


@pytest.mark.asyncio
async def test_native_metadata_dns_admission_never_fakes_raw_or_dns9(tmp_path):
    raw = job().model_dump(mode="json")
    raw["result"]["tcx"]["zeek_summary"] = {"dns_transactions": {"records": 2, "accepted": 2}}
    w = OfflineWorkflow(tmp_path / "run", paths=research_paths())
    r = await w.run(TCXAnalysisJob.model_validate(raw))
    d = json.loads((w.directory / "tcx-dns-admission.json").read_bytes())
    assert d["transaction_metadata"]["records"] == 2
    assert d["feature_status"] == "INCOMPLETE" and d["model_inference_executed"] is False
    assert d["raw_dns_status"] == "NOT_RETAINED_IN_SUPERVISOR_RESULT"
    assert all(x.receipt["profile"] in ("quality", "edge") for x in r.inference)
    d["feature_status"] = "ELIGIBLE"
    (w.directory / "tcx-dns-admission.json").write_text(json.dumps(d))
    with pytest.raises(ValueError, match="DNS_ADMISSION"):
        verify_result(w.directory)


def test_drain_failure_preserves_invalid_feature_state():
    raw = job().model_dump(mode="json")
    t = raw["result"]["tcx"]["data_plane"]
    t["processing"]["feature_tail"][0]["values_digest"] = "0" * 64
    t["drain_state"] = "UNVERIFIED"
    assert candidates(TCXAnalysisJob.model_validate(raw))[2][0]["input_state"] == "INVALID"
