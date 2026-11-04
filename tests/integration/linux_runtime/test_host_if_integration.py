"""Saved journal at the Host command boundary; IF/API are explicitly mocked."""

import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest
from tests.integration.linux_runtime.test_managed_authentication_lifecycle import (
    approve_fixture,
    mock_journal_child,
    prepare,
)

from soc_agent.approval import ApprovalManager
from soc_agent.continuous.authentication_lifecycle import AuthenticationLifecycle
from soc_agent.continuous.host_authentication import package_contract, sealed_jobs, validate_job
from soc_agent.security_ai.authentication_action import METADATA, analysis_action
from soc_agent.security_ai.offline_workflow import OfflineWorkflow, verify_result
from soc_agent.security_ai.research.models import digest
from soc_agent.security_ai.workflow_models import PackageInput
from soc_agent.state.evidence import utc_now


def packages():
    directory = Path(__file__).parents[2] / "fixtures/security_ai_packages/authentication_anomaly"
    return (
        PackageInput(
            directory=str(directory),
            manifest_sha256=hashlib.sha256((directory / "manifest.json").read_bytes()).hexdigest(),
        ),
    )


async def retained(tmp_path, monkeypatch, *, seconds=(1, 2, 3, 361)):
    store = prepare(tmp_path, packages=packages())
    approve_fixture(store)
    mock_journal_child(monkeypatch, seconds=seconds)
    child = AuthenticationLifecycle(store)
    try:
        await child.start()
    finally:
        await child.close()
    return store


def grant(job, directory, *, approve=True, expires=None):
    action = analysis_action(job, directory)
    manager = ApprovalManager()
    request = manager.create(
        incident_id=action.incident_id,
        metadata=METADATA,
        reason="TEST ONLY exact saved journal model boundary",
        action_id=action.action_id,
        action_input_json=action.tool_input,
        expires_at=expires or utc_now() + timedelta(minutes=5),
    )
    return (manager.approve if approve else manager.reject)(request.approval_id, actor="FIXTURE")


@pytest.mark.asyncio
async def test_host_parser_seal_parity_privacy_and_tamper(tmp_path, monkeypatch):
    store = await retained(tmp_path, monkeypatch)
    jobs = sealed_jobs(store)
    assert len(jobs) == 1 and len(jobs[0].records) == 3
    job = jobs[0]
    contract = validate_job(job)
    assert len(contract["feature_names"]) == 5
    assert contract["threshold"] == 0.95
    assert contract["deployment_assurance"] == "RESEARCH_MODEL_HOST_DISTRIBUTION_UNVERIFIED"
    assert job.host_binding.session == store.database.store_id
    assert job.origin == "DECLARED_HOST_JOURNAL"
    assert "fixture-user" not in job.model_dump_json()
    assert "192.0.2.5" not in job.model_dump_json()
    assert digest(sealed_jobs(store)[0].model_dump(mode="json")) == digest(
        job.model_dump(mode="json")
    )
    changed = job.model_copy(update={"source_sha256": "0" * 64})
    with pytest.raises(ValueError, match="SEALED_JOB_CHANGED"):
        validate_job(changed)
    changed = job.model_copy(
        update={"host_binding": job.host_binding.model_copy(update={"namespace": "net:[0]"})}
    )
    with pytest.raises(ValueError, match="SEALED_JOB_CHANGED"):
        validate_job(changed)
    receipt = store.config.managed_authentication.approval_file
    receipt.write_text("{}")
    with pytest.raises(ValueError):
        validate_job(job)
    proof = json.loads((store.directory / "authentication-cleanup.json").read_text())
    assert proof["cleanup"] == "VERIFIED" and proof["stop_ack"]


@pytest.mark.asyncio
async def test_incomplete_host_window_never_becomes_model_job(tmp_path, monkeypatch):
    store = await retained(tmp_path, monkeypatch, seconds=(1, 2, 3))
    assert sealed_jobs(store) == ()
    assert (
        package_contract(packages())["source_assurance"]
        == "DECLARED_UNATTESTED_NOT_KERNEL_ATTESTED"
    )


@pytest.mark.asyncio
async def test_exact_if_action_mock_prediction_and_existing_orchestration(tmp_path, monkeypatch):
    store = await retained(tmp_path, monkeypatch)
    (job,) = sealed_jobs(store)
    from soc_agent.security_ai.anomaly_common import AnomalyPrediction
    from soc_agent.security_ai.packaging.package import ModelPackage

    calls = []

    def predict(self, feature):
        calls.append(feature.input_fingerprint)
        reference = self.profile.normalization
        raw = 0.9
        normalized = reference.normalize(raw)
        return AnomalyPrediction(
            raw_score=-raw,
            raw_decision_score=-raw - reference.sklearn_offset,
            raw_anomaly_measure=raw,
            anomaly_score=normalized,
            threshold=reference.threshold,
            is_anomaly=normalized >= reference.threshold,
        )

    # Real adapter/structured result/fusion; replace ONLY numeric model scoring.
    monkeypatch.setattr(ModelPackage, "predict", predict)
    pending = await OfflineWorkflow(tmp_path / "pending", defer_investigation=True).run(job)
    assert not calls and not pending.inference
    directory = tmp_path / "approved"
    approval = grant(job, directory)
    outcome = await OfflineWorkflow(
        directory, authentication_approval=approval, defer_investigation=True
    ).run(job)
    assert len(calls) == 1 and len(outcome.inference) == 1
    assert outcome.evidence[0].session == str(store.database.store_id)
    verify_result(directory)
    from tests.integration.test_continuous_orchestration import Recorded, drained

    from soc_agent.continuous.investigation import from_analysis
    from soc_agent.continuous.investigation_store import InvestigationTasks

    source = from_analysis(
        directory, scope=store.config.input_sha256, namespace=store.config.namespace
    )
    assert source.role == "AUTHENTICATION"
    tasks = InvestigationTasks(store)
    first = tasks.submit(source)
    assert tasks.submit(source) == first
    client = Recorded()
    await drained(tasks, client)
    assert client.calls and len(tasks.tasks()) >= 1
    from soc_agent.gui.analysis_service import project_result

    projection = project_result(outcome)
    assert projection["inference_count"] == 1
    with pytest.raises(FileExistsError):
        await OfflineWorkflow(directory, authentication_approval=approval).run(job)
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_gui_exact_if_review_does_not_authorize_future_windows(tmp_path, monkeypatch):
    from soc_agent import agent_review

    store = await retained(tmp_path, monkeypatch)
    (job,) = sealed_jobs(store)
    pin = digest(job.model_dump(mode="json"))
    path = store.directory / "inputs" / (pin + ".json")
    path.write_text(job.model_dump_json())
    path.chmod(0o600)
    store.config.native_model_approvals.mkdir(mode=0o700)
    request = dict(
        runtime_session=str(store.database.store_id),
        authentication_model_action_review=dict(max_model_invocations=1),
        model_action_review=dict(max_model_invocations=16),
        expires_at=(utc_now() + timedelta(minutes=10)).isoformat(),
    )
    monkeypatch.setattr(
        agent_review, "_context", lambda _: (request, store.config, store.directory)
    )
    review = tmp_path / "review"
    review.mkdir()
    (review / "approval-request-final-v2.json").write_text(json.dumps(request))
    batch = agent_review.pending_models(review)
    assert len(batch.jobs) == 1 and batch.jobs[0].family == "AUTHENTICATION_IF"
    assert batch.jobs[0].calls == 1 and batch.authentication_maximum_invocations == 1
    assert batch.jobs[0].model_details["threshold"] == 0.95
    with pytest.raises(ValueError, match="EXPLICIT_HUMAN"):
        agent_review.approve_models(
            review, digest(batch.model_dump(mode="json")), actor="FIXTURE", confirmed=False
        )
    assert not list(store.config.native_model_approvals.iterdir())
    result = agent_review.approve_models(
        review, digest(batch.model_dump(mode="json")), actor="FIXTURE", confirmed=True
    )
    assert result["jobs"] == 1 and not result["capture_started"]
    assert not agent_review.pending_models(review).jobs
    receipt = store.config.native_model_approvals / (pin + ".json")
    original = receipt.read_bytes()
    with pytest.raises(ValueError, match="BATCH_CHANGED"):
        agent_review.approve_models(
            review, digest(batch.model_dump(mode="json")), actor="FIXTURE", confirmed=True
        )
    assert receipt.read_bytes() == original


@pytest.mark.parametrize("decision", ["rejected", "expired", "changed_input"])
@pytest.mark.asyncio
async def test_invalid_model_grants_never_reach_numeric_scoring(tmp_path, monkeypatch, decision):
    store = await retained(tmp_path, monkeypatch)
    (job,) = sealed_jobs(store)
    directory = tmp_path / "attempt"
    approval = grant(job, directory, approve=decision != "rejected")
    if decision == "expired":
        approval = approval.model_copy(update={"expires_at": utc_now() - timedelta(seconds=1)})
    if decision == "changed_input":
        approval = approval.model_copy(update={"action_input_json": "{}"})
    from soc_agent.security_ai.packaging.package import ModelPackage

    monkeypatch.setattr(
        ModelPackage, "predict", lambda *_: pytest.fail("unapproved numeric scoring")
    )
    outcome = await OfflineWorkflow(
        directory, authentication_approval=approval, defer_investigation=True
    ).run(job)
    assert outcome.classification == "MODEL_ERROR" and not outcome.inference
    assert not list(directory.glob("inference-*.json"))


@pytest.mark.asyncio
async def test_main_runtime_handoffs_once_and_stop_preserves_unapproved_job(tmp_path, monkeypatch):
    import asyncio

    from soc_agent.continuous.service import ContinuousRuntime

    store = prepare(tmp_path, packages=packages())
    approve_fixture(store)
    mock_journal_child(monkeypatch, seconds=(1, 2, 3, 361))
    runtime = ContinuousRuntime(store.directory)

    class IdleSource:
        async def events(self):
            await runtime.stop.wait()
            if False:
                yield {}

        async def close(self):
            return None

    runtime.source = IdleSource()
    task = asyncio.create_task(runtime.run())
    try:
        for _ in range(200):
            if runtime.worker_state == "WAITING_EXACT_MODEL_ACTION_APPROVAL" or task.done():
                break
            await asyncio.sleep(0.05)
        assert not task.done(), task.exception() if task.done() else None
        assert runtime.worker_state == "WAITING_EXACT_MODEL_ACTION_APPROVAL"
        assert runtime.analysis.process is None
        assert runtime.metrics["auth_windows"] == 1
        snapshot = await runtime.observed_snapshot()
        assert snapshot["authentication"]["if_admission"]["predictions"] == 0
        assert (
            snapshot["authentication"]["if_admission"]["state"]
            == "WAITING_EXACT_IF_ACTION_APPROVAL"
        )
        assert len(list((store.directory / "inputs").glob("*.json"))) == 1
    finally:
        runtime.stop.set()
        await asyncio.wait_for(task, 20)
    assert runtime.auth_lifecycle.evidence["cleanup"] == "VERIFIED"
    assert len(list((store.directory / "inputs").glob("*.json"))) == 1
    assert runtime.metrics["predictions"] == 0
