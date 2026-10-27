"""Actual XGBoost/numeric forests on synthetic records; no capture or provider calls."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from soc_agent.cli import main
from soc_agent.llm import MockLLMClient
from soc_agent.security_ai.features import SecurityRecord, SourceReference
from soc_agent.security_ai.offline_workflow import OfflineWorkflow, verify_result
from soc_agent.security_ai.packaging.files import sha256
from soc_agent.security_ai.workflow_models import (
    CollectorFailureJob,
    NativeCheckpointJob,
    PackageInput,
    RecordsJob,
    ReplayJob,
    StoredDNSJob,
)
from tests.authentication_support import record as auth_record

ROOT = Path(__file__).parents[1] / "fixtures/security_ai_packages"
PINS = dict(
    network_classifier="afbc5a77bd858cfb9bb04652af8bcb9985125b6368bd4ce440f423758cbe7773",
    network_anomaly="14429a0323f6d622dc65f217761698ae37566dd32eca421d51fbf1eab1f489d7",
    authentication_anomaly="aabeb76277534d9300f70699dfddb84214720add607ef1d17b4c0e34e084b5f6",
)


def packages(*names):
    return tuple(
        PackageInput(directory=str((ROOT / n).absolute()), manifest_sha256=PINS[n]) for n in names
    )


def network(mode="normal"):
    fields = dict(
        duration_us=1000000.0, fwd_packets=30, bwd_packets=25, fwd_bytes=3000, bwd_bytes=2500
    )
    if mode == "attack":
        fields = dict(
            duration_us=500000.0, fwd_packets=100, bwd_packets=10, fwd_bytes=5000, bwd_bytes=500
        )
    if mode == "anomaly":
        fields["fwd_packets"] = 300
    if mode == "invalid":
        fields.pop("bwd_bytes")
    if mode == "overflow":
        fields["duration_us"] = 1e300
    return SecurityRecord(
        record_type="network_flow",
        record_schema_version="1.0.0",
        source="synthetic-flow",
        source_reference=SourceReference(
            source_type="stream", source_name="synthetic-flow", record_id="f1"
        ),
        fields=fields,
        observed_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def job(mode="normal"):
    return RecordsJob(
        kind="stored_records",
        origin="FIXTURE",
        records=(network(mode),),
        packages=packages("network_classifier", "network_anomaly"),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode,expected",
    [("normal", "NORMAL"), ("attack", "KNOWN_THREAT"), ("anomaly", "UNKNOWN_ANOMALY")],
)
async def test_actual_models_through_response_and_audit(tmp_path, mode, expected):
    w = OfflineWorkflow(tmp_path / "run")
    r = await w.run(job(mode))
    assert r.classification == expected and r.eligibility == "ELIGIBLE"
    assert len(r.inference) == 2 and r.fusion["confidence_state"] == "unknown"
    assert r.response["postcondition"] == "SOURCE_CONTINUITY_VERIFIED"
    assert r.response["host_remediation"] is False and r.external_provider_calls == 0
    assert all(x.model_manifest_digest in PINS.values() for x in r.inference)
    assert all(
        x.feature_fingerprint and x.evidence_references and x.latency_ms >= 0 for x in r.inference
    )
    assert verify_result(w.directory) == r
    assert bool(r.investigation) == (mode == "anomaly")
    if r.investigation:
        assert r.investigation["status"] == "COMPLETED_READ_ONLY"
        assert len(r.investigation["prompt_digests"]) == 2
        assert r.investigation["assessment"]["incident_state"]["hypotheses"] == []


@pytest.mark.asyncio
async def test_authentication_real_iforest_and_cross_domain_fusion(tmp_path):
    events = tuple(
        auth_record(
            event_id=str(i),
            account="synthetic",
            seconds=i,
            result="failure" if i < 40 else "success",
            kind="stream",
        )
        for i in range(42)
    )
    j = RecordsJob(
        kind="stored_records",
        origin="FIXTURE",
        records=(network("attack"), *events),
        packages=packages(*PINS),
    )
    r = await OfflineWorkflow(tmp_path / "run").run(j)
    assert len(r.inference) == 3
    assert r.inference[-1].prediction == "anomaly"
    assert len(r.fusion["correlation_groups"]) == 2
    assert r.fusion["summary"]["cross_domain_state"] == "unverified"
    assert set(
        r.inference[-1].receipt["features"]["feature_schema"]["features"][i]["name"]
        for i in range(5)
    ) == {
        "failed_login_count",
        "successful_login_count",
        "total_login_count",
        "failure_rate",
        "login_attempt_rate",
    }


@pytest.mark.asyncio
async def test_authentication_anomaly_has_bounded_complete_investigation(tmp_path):
    events = tuple(
        auth_record(
            event_id=str(i), seconds=i, result="failure" if i < 40 else "success", kind="stream"
        )
        for i in range(42)
    )
    j = RecordsJob(
        kind="stored_records",
        origin="FIXTURE",
        records=events,
        packages=packages("authentication_anomaly"),
    )
    r = await OfflineWorkflow(tmp_path / "run").run(j)
    assert (
        r.classification == "UNKNOWN_ANOMALY" and r.investigation["status"] == "COMPLETED_READ_ONLY"
    )
    assert len(r.inference[0].evidence_references) == 42


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["invalid", "overflow"])
async def test_bad_features_block_every_predict(tmp_path, monkeypatch, mode):
    from soc_agent.security_ai.base import SecurityAI

    async def forbidden(*args, **kwargs):
        raise AssertionError("Inference occurred")

    monkeypatch.setattr(SecurityAI, "predict", forbidden)
    r = await OfflineWorkflow(tmp_path / "run").run(job(mode))
    assert r.classification == "DATA_QUALITY_FAILURE" and r.eligibility == "INVALID"
    assert not r.inference and not r.investigation


@pytest.mark.asyncio
async def test_package_pin_failure_is_not_benign_and_routes_to_planner(tmp_path):
    j = job().model_copy(
        update={
            "packages": (
                PackageInput(directory=str(ROOT / "network_classifier"), manifest_sha256="a" * 64),
            )
        }
    )
    r = await OfflineWorkflow(tmp_path / "run").run(j)
    assert r.classification == "MODEL_ERROR" and not r.inference
    assert r.investigation["status"] == "COMPLETED_READ_ONLY"


@pytest.mark.asyncio
async def test_native_evidence_never_runs_models(tmp_path, monkeypatch):
    from soc_agent.security_ai.workflow_inputs import ResearchAdapter

    async def forbidden(*args, **kwargs):
        raise AssertionError("Native inference")

    monkeypatch.setattr(ResearchAdapter, "infer", forbidden)
    r = await OfflineWorkflow(tmp_path / "run").run(
        NativeCheckpointJob(kind="native_checkpoint", summary={}, transport={})
    )
    assert r.classification == "DATA_QUALITY_FAILURE" and r.eligibility == "INCOMPLETE"
    assert r.reasons == ("NATIVE_AI_POLICY_BLOCKED",) and not r.inference


@pytest.mark.asyncio
async def test_known_error_revalidates_once_without_repair_claim(tmp_path):
    w = OfflineWorkflow(tmp_path / "run")
    j = CollectorFailureJob(
        kind="collector_error", code="FEATURE_EXTRACTION_INTERRUPTED", record=network()
    )
    r = await w.run(j)
    assert r.classification == "COLLECTOR_ERROR" and not r.inference
    assert r.response["result"]["output"]["status"] == "INPUT_REVALIDATED_NO_COLLECTOR_REPAIR"
    assert r.response["automatic_attempts"] == 1 and not r.response["host_remediation"]
    with pytest.raises(ValueError, match="ALREADY_CLAIMED"):
        await w.run(j)
    with pytest.raises(FileExistsError):
        OfflineWorkflow(w.directory)


@pytest.mark.asyncio
async def test_failed_revalidation_stops_and_preserves_original(tmp_path):
    r = await OfflineWorkflow(tmp_path / "run").run(
        CollectorFailureJob(
            kind="collector_error", code="FEATURE_EXTRACTION_INTERRUPTED", record=network("invalid")
        )
    )
    assert r.response["status"] == "FAILED_STOP_NO_RETRY"
    assert not r.inference and r.classification == "COLLECTOR_ERROR"


@pytest.mark.asyncio
async def test_unclassified_error_uses_scripted_llm_no_external_calls(tmp_path):
    r = await OfflineWorkflow(tmp_path / "run").run(
        CollectorFailureJob(kind="collector_error", code="UNCLASSIFIED")
    )
    assert r.investigation["status"] == "COMPLETED_READ_ONLY" and r.llm_mode == "SCRIPTED"
    assert r.investigation["human_approval_for_host_response"]


@pytest.mark.asyncio
async def test_llm_cannot_select_shell_or_invent_evidence(tmp_path):
    client = MockLLMClient(
        [
            dict(
                goal="malicious",
                steps=[dict(tool_name="arbitrary_shell", tool_input={}, purpose="deny")],
            )
        ]
    )
    r = await OfflineWorkflow(tmp_path / "run", llm_client=client).run(
        CollectorFailureJob(kind="collector_error", code="UNCLASSIFIED")
    )
    assert r.investigation["status"] == "FAILED_STOP_NO_RETRY" and client.call_count == 1
    assert not r.inference and r.llm_mode == "INJECTED_CLIENT"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["input.json", "result.json", "inference-0.json"])
async def test_restoration_rejects_tampering(tmp_path, name):
    d = tmp_path / "run"
    await OfflineWorkflow(d).run(job())
    p = d / name
    doc = json.loads(p.read_bytes())
    doc["tampered"] = True
    p.write_text(json.dumps(doc))
    with pytest.raises(ValueError):
        verify_result(d)


@pytest.mark.asyncio
async def test_duplicate_records_rejected_before_inference(tmp_path):
    j = job()
    j = j.model_copy(update={"records": (j.records[0], j.records[0])})
    r = await OfflineWorkflow(tmp_path / "run").run(j)
    assert r.classification == "DATA_QUALITY_FAILURE" and not r.inference


def test_operational_cli_exact_pin_and_read_only_reopen(tmp_path, capsys):
    p = tmp_path / "job.json"
    p.write_text(job().model_dump_json())
    pin = sha256(p.read_bytes())
    assert (
        main(
            [
                "analyze-offline",
                "--input",
                str(p),
                "--input-sha256",
                "a" * 64,
                "--output",
                str(tmp_path / "wrong"),
            ]
        )
        == 2
    )
    assert not (tmp_path / "wrong").exists()
    out = tmp_path / "run"
    assert (
        main(["analyze-offline", "--input", str(p), "--input-sha256", pin, "--output", str(out)])
        == 0
    )
    assert main(["analyze-offline", "--verify", "--output", str(out)]) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[-1])["inferences"] == 2


@pytest.mark.asyncio
async def test_schema14_is_not_silently_fed_to_schema5(tmp_path):
    fields = {"feature" + str(i): float(i) for i in range(14)}
    n = network().model_copy(update={"fields": json.dumps(fields)})
    r = await OfflineWorkflow(tmp_path / "run").run(job().model_copy(update={"records": (n,)}))
    assert not r.inference and r.classification == "DATA_QUALITY_FAILURE"


@pytest.mark.asyncio
async def test_empty_replay_profiles_rejected_without_worker(tmp_path):
    r = await OfflineWorkflow(tmp_path / "run").run(
        ReplayJob(kind="network14_replay", flow_index=0, profiles=())
    )
    assert not r.inference and r.eligibility == "INVALID"


@pytest.mark.asyncio
async def test_stored_dns_is_not_silently_substituted_with_fixture(tmp_path, monkeypatch):
    from soc_agent.security_ai.research.adapter import ResearchAdapter
    from tests.unit.operational_features.test_raw_sources import dns

    async def forbidden(*args, **kwargs):
        raise AssertionError("DNS fixture substitution")

    monkeypatch.setattr(ResearchAdapter, "infer", forbidden)
    r = await OfflineWorkflow(tmp_path / "run").run(
        StoredDNSJob(kind="stored_dns", sources=(dns(),))
    )
    assert r.eligibility == "INCOMPLETE" and not r.inference
    assert r.evidence[0].source_digest == dns().content_digest
    assert "DNS9_PRODUCER_PARITY_UNVERIFIED" in r.reasons


@pytest.mark.asyncio
async def test_partial_inference_preserved_when_next_model_fails(tmp_path, monkeypatch):
    from soc_agent.security_ai.base import SecurityAI
    from soc_agent.security_ai.errors import SecurityAIInferenceError

    original = SecurityAI.predict
    calls = []

    async def fail_second(self, request):
        calls.append(self.metadata.name)
        if len(calls) == 2:
            raise SecurityAIInferenceError("injected failure")
        return await original(self, request)

    monkeypatch.setattr(SecurityAI, "predict", fail_second)
    r = await OfflineWorkflow(tmp_path / "run").run(job())
    assert r.classification == "MODEL_ERROR" and len(r.inference) == 1
    assert verify_result(tmp_path / "run") == r


@pytest.mark.asyncio
async def test_validated_local_llm_hypothesis_is_separate_from_observation(tmp_path):
    from soc_agent.desktop import OfflineDesktopClient

    class LocalDraft:
        async def generate_structured(self, *, request, response_model):
            body = json.loads(request.user_prompt)
            if "AVAILABLE TOOLS" in body:
                return await OfflineDesktopClient().generate_structured(
                    request=request, response_model=response_model
                )
            refs = [e["evidence_id"] for e in body["EVIDENCE (UNTRUSTED DATA)"]]
            return response_model.model_validate(
                dict(
                    observations=[],
                    hypotheses=[
                        dict(
                            ref="H1",
                            statement="Distribution shift may explain the anomaly; unverified",
                            supporting_evidence_ids=refs,
                            confidence=0.1,
                        )
                    ],
                    assessment=dict(
                        severity="info",
                        confidence=0.1,
                        summary="Local test hypothesis only",
                        supporting_evidence_ids=refs,
                        supporting_hypothesis_refs=["H1"],
                    ),
                )
            )

    r = await OfflineWorkflow(tmp_path / "run", llm_client=LocalDraft()).run(job("anomaly"))
    assert r.investigation["status"] == "COMPLETED_READ_ONLY"
    assert len(r.investigation["hypothesis_verification"]) == 1
    assert r.investigation["assessment"]["incident_state"]["observations"] == []
    assert r.investigation["hypothesis_verification"][0]["read_only_tools"] == [
        "read_local_source_report"
    ]


def test_cli_submitted_bytes_are_audited(tmp_path):
    p = tmp_path / "source.json"
    p.write_text(job().model_dump_json(indent=2))
    out = tmp_path / "run"
    assert (
        main(
            [
                "analyze-offline",
                "--input",
                str(p),
                "--input-sha256",
                sha256(p.read_bytes()),
                "--output",
                str(out),
            ]
        )
        == 0
    )
    p = out / "submitted-input.json"
    doc = json.loads(p.read_bytes())
    doc["utf8"] += " "
    p.write_text(json.dumps(doc))
    with pytest.raises(ValueError, match="SUBMITTED_INPUT_CHANGED"):
        verify_result(out)


def test_offline_cli_never_requests_root_or_network(tmp_path, monkeypatch):
    import socket
    import subprocess

    import soc_agent.cli as cli

    def forbidden(*args, **kwargs):
        raise AssertionError("Privileged/network path entered")

    original_socket = socket.socket

    def local_only(family=socket.AF_INET, *args, **kwargs):
        if family != socket.AF_UNIX:
            raise AssertionError("Network path entered")
        return original_socket(family, *args, **kwargs)

    monkeypatch.setattr(cli, "terminal_authenticate", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "socket", local_only)
    p = tmp_path / "job.json"
    p.write_text(job().model_dump_json())
    assert (
        main(
            [
                "analyze-offline",
                "--input",
                str(p),
                "--input-sha256",
                sha256(p.read_bytes()),
                "--output",
                str(tmp_path / "run"),
            ]
        )
        == 0
    )


@pytest.mark.asyncio
async def test_model_context_cannot_become_llm_observed_fact(tmp_path):
    from soc_agent.desktop import OfflineDesktopClient

    class InventedFact:
        async def generate_structured(self, *, request, response_model):
            body = json.loads(request.user_prompt)
            if "AVAILABLE TOOLS" in body:
                return await OfflineDesktopClient().generate_structured(
                    request=request, response_model=response_model
                )
            refs = [e["evidence_id"] for e in body["EVIDENCE (UNTRUSTED DATA)"]]
            return response_model.model_validate(
                dict(
                    observations=[
                        dict(
                            ref="O1",
                            statement="Model output proves a compromise",
                            supporting_evidence_ids=refs,
                        )
                    ],
                    hypotheses=[],
                    assessment=dict(
                        severity="high",
                        confidence=1.0,
                        summary="forged fact",
                        supporting_evidence_ids=refs,
                    ),
                )
            )

    r = await OfflineWorkflow(tmp_path / "run", llm_client=InventedFact()).run(job("anomaly"))
    assert r.investigation["status"] == "FAILED_STOP_NO_RETRY"
    assert r.investigation["error_type"] == "LLMResponseValidationError"
