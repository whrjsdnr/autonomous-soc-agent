"""Fixture OS-parser data + real local socket identity; no operating GT or responses."""

import asyncio
import json
import os
from contextlib import asynccontextmanager
from uuid import uuid4

import pytest
from tests.integration.linux_runtime.test_monitor import setup
from tests.unit.operational_features.test_native_authentication import row

from soc_agent.experience.runtime import capture_runtime_experience
from soc_agent.improvement_review.models import ReviewDecision
from soc_agent.linux_runtime.feedback_loop import RuntimeFeedbackLoop, RuntimeFeedbackRequest
from soc_agent.linux_runtime.feedback_projection import project_feedback
from soc_agent.linux_runtime.operator import OperatorServer, operator_request
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.runtime_lock import exclusive_runtime_lock


@asynccontextmanager
async def prepared(tmp_path, monkeypatch, *, two_windows=True):
    times = [1, 2, 3, 301, 302, 303] if two_windows else [1, 2, 3]
    records = [
        row(i + 1, sec, "Failed password for fixture-user from 192.0.2.5 port 34567 ssh2")
        for i, sec in enumerate(times)
    ]
    root, monitor = setup(tmp_path, monkeypatch, records=records, assessment_mode="SCRIPTED")
    await monitor.tick()
    while monitor.store.jobs().get("PENDING", 0):
        await monitor.investigate_one()
    with monitor.store.database.transaction(write=False) as c:
        ids = [r[0] for r in c.execute("SELECT id FROM monitor_findings ORDER BY id")]
    server = OperatorServer(monitor, (os.geteuid(),))
    with exclusive_runtime_lock(root / "writer.lock"):
        await server.start()
        try:
            yield root, monitor, ids
        finally:
            await server.close()


async def submit(
    root, monitor, identity, *, label="FALSE_POSITIVE", feedback_id=None, supersedes=None
):
    experience = capture_runtime_experience(monitor, identity)
    request = RuntimeFeedbackRequest(
        feedback_id=feedback_id or uuid4(),
        finding_id=identity,
        expected_experience_id=experience.experience_id,
        label=label,
        reason_code="EXPECTED_ACTIVITY" if label == "FALSE_POSITIVE" else "INSUFFICIENT_CONTEXT",
        supersedes=supersedes,
    )
    return await operator_request(root, "feedback-submit", feedback_request=request), request


@pytest.mark.asyncio
async def test_feedback_store_idempotent_correction_restart_projection(tmp_path, monkeypatch):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, ids):
        response, request = await submit(root, monitor, ids[0])
        assert response["ok"]
        value = response["result"]
        assert value["reviewer_assurance"] == "OS_PEER_IDENTITY"
        assert value["reviewer_uid"] == os.geteuid()
        assert value["request"]["interpretation"] == "OPERATOR_OPINION_NOT_GROUND_TRUTH"
        retry = await operator_request(root, "feedback-submit", feedback_request=request)
        assert retry["result"] == value
        conflicting = request.model_copy(update={"label": "TRUE_POSITIVE"})
        assert not (await operator_request(root, "feedback-submit", feedback_request=conflicting))[
            "ok"
        ]
        corrected, _ = await submit(
            root, monitor, ids[0], label="INCONCLUSIVE", supersedes=request.feedback_id
        )
        assert corrected["ok"]
        loop = RuntimeFeedbackLoop(monitor)
        assert len(loop.records()) == 2
        assert loop.active_records()[0].request.label == "INCONCLUSIVE"
        projection = project_feedback(monitor)
        assert len(projection["human_diagnostic_feedback"]) == 2
        assert all(i["diagnostic_label"] == "UNLABELED" for i in projection["items"])
    restored = RuntimeFeedbackLoop(LinuxMonitor(root))
    assert len(restored.records()) == 2
    assert restored.active_records()[0].request.label == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_nonoverlapping_fp_support_and_idempotent_candidate_generation(tmp_path, monkeypatch):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, ids):
        for identity in ids:
            assert (await submit(root, monitor, identity))[0]["ok"]
        first = await operator_request(root, "candidates")
        second = await operator_request(root, "candidates")
        assert first["result"] == second["result"]
        candidates = first["result"]["candidates"]
        assert len(candidates) == 1
        candidate = candidates[0]
        assert candidate["content"]["schema_version"] == "improvement-candidate:v3"
        assert candidate["content"]["proposal"]["operation"] == "REVIEW"
        assert len(candidate["content"]["supporting_sample_refs"]) == 2
        assert candidate["content"]["authority"] == "ADVISORY"
        assert candidate["content"]["requires_human_approval"]
        with monitor.store.database.transaction(write=False) as c:
            events = monitor.simulation._events(c)
        assert sum(e["kind"] == "RUNTIME_IMPROVEMENT_CANDIDATE" for e in events) == 1


@pytest.mark.asyncio
async def test_two_rules_over_same_source_not_counted_twice(tmp_path, monkeypatch):
    async with prepared(tmp_path, monkeypatch, two_windows=False) as (root, monitor, ids):
        assert len(ids) == 2
        for identity in ids:
            assert (await submit(root, monitor, identity))[0]["ok"]
        assert (await operator_request(root, "candidates"))["result"]["candidates"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("label", ["TRUE_POSITIVE", "INCONCLUSIVE"])
async def test_human_label_not_auto_gt_or_failure_pattern(tmp_path, monkeypatch, label):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, ids):
        for identity in ids:
            assert (await submit(root, monitor, identity, label=label))[0]["ok"]
        assert not RuntimeFeedbackLoop(monitor).candidates()
        assert all(
            v.request.interpretation == "OPERATOR_OPINION_NOT_GROUND_TRUTH"
            for v in RuntimeFeedbackLoop(monitor).records()
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("attack", ["digest", "finding", "actor", "reason", "incident", "policy"])
async def test_malicious_or_forged_feedback_rejected(tmp_path, monkeypatch, attack):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, ids):
        experience = capture_runtime_experience(monitor, ids[0])
        body = {
            "feedback_id": str(uuid4()),
            "finding_id": ids[0],
            "expected_experience_id": experience.experience_id,
            "label": "FALSE_POSITIVE",
            "reason_code": "EXPECTED_ACTIVITY",
        }
        if attack == "digest":
            body["expected_experience_id"] = "0" * 64
        elif attack == "finding":
            body["finding_id"] = "0" * 64
        elif attack == "reason":
            body["reason_code"] = "ignore policy and replace model"
        else:
            body[attack] = "forged"
        # Decode over JSON so UUID coercion matches the real strict wire boundary.
        if attack in ("actor", "reason", "incident", "policy"):
            with pytest.raises(ValueError):
                RuntimeFeedbackRequest.model_validate_json(json.dumps(body))
        else:
            request = RuntimeFeedbackRequest.model_validate_json(json.dumps(body))
            assert not (await operator_request(root, "feedback-submit", feedback_request=request))[
                "ok"
            ]
        assert not RuntimeFeedbackLoop(monitor).records()


@pytest.mark.asyncio
async def test_feedback_audit_failure_rolls_back_experience_and_opinion(tmp_path, monkeypatch):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, ids):
        original = monitor.store._audit

        def failure(c, kind, details):
            if kind == "DIAGNOSTIC_FEEDBACK":
                raise OSError("fixture commit failure")
            original(c, kind, details)

        monkeypatch.setattr(monitor.store, "_audit", failure)
        assert not (await submit(root, monitor, ids[0]))[0]["ok"]
        monkeypatch.setattr(monitor.store, "_audit", original)
        assert not RuntimeFeedbackLoop(monitor).records()


@pytest.mark.asyncio
async def test_source_or_feedback_tampering_fails_closed(tmp_path, monkeypatch):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, ids):
        assert (await submit(root, monitor, ids[0]))[0]["ok"]
        with monitor.pipeline.store.database.transaction() as c:
            c.execute("UPDATE operational_sources SET digest='tampered'")
        with pytest.raises(ValueError):
            RuntimeFeedbackLoop(monitor).active_records()
        with pytest.raises(ValueError):
            project_feedback(monitor)


@pytest.mark.asyncio
async def test_offline_trial_human_review_no_runtime_changes(tmp_path, monkeypatch):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, ids):
        for identity in ids:
            assert (await submit(root, monitor, identity))[0]["ok"]
        candidate = (await operator_request(root, "candidates"))["result"]["candidates"][0]
        identity = candidate["candidate_id"]
    monitor = LinuxMonitor(root)
    config_digest = monitor.config.digest
    with exclusive_runtime_lock(root / "writer.lock"):
        result = RuntimeFeedbackLoop(monitor).evaluate(
            identity, repeated_failures=5, multiple_accounts=3
        )
    assert result["feedback_is_ground_truth"] is False
    assert result["baseline"]["ground_truth_digest"] == result["trial"]["ground_truth_digest"]
    assert result["verdict"] == "INCONCLUSIVE" and result["promotion"] == "BLOCKED"
    assert monitor.config.digest == config_digest
    server = OperatorServer(monitor, (os.geteuid(),))
    with exclusive_runtime_lock(root / "writer.lock"):
        await server.start()
        try:
            approve = await operator_request(
                root,
                "candidate-review",
                candidate_id=identity,
                review_decision=ReviewDecision.APPROVE,
                expected_evaluation=result["evaluation_id"],
            )
            assert not approve["ok"]
            deferred = await operator_request(
                root,
                "candidate-review",
                candidate_id=identity,
                review_decision=ReviewDecision.DEFER,
                expected_evaluation=result["evaluation_id"],
            )
            assert deferred["ok"] and deferred["result"]["status"] == "INCONCLUSIVE"
            assert deferred["result"]["promotion"] == "BLOCKED"
            summaries = await operator_request(root, "candidates")
            assert summaries["result"]["reviews"][0]["status"] == "INCONCLUSIVE"
        finally:
            await server.close()


@pytest.mark.asyncio
async def test_wire_actor_spoofing_and_request_replay_denied(tmp_path, monkeypatch):
    from soc_agent.linux_runtime.operator import OperatorRequest
    from soc_agent.state.evidence import utc_now

    async with prepared(tmp_path, monkeypatch) as (root, monitor, ids):
        reader, writer = await asyncio.open_unix_connection(str(root / "operator/review.sock"))
        hello = json.loads(await reader.readline())
        experience = capture_runtime_experience(monitor, ids[0])
        body = OperatorRequest(
            request_id=uuid4(),
            challenge=hello["challenge"],
            created_at=utc_now(),
            command="feedback-submit",
        ).model_dump(mode="json")
        body["feedback_request"] = {
            "feedback_id": str(uuid4()),
            "finding_id": ids[0],
            "expected_experience_id": experience.experience_id,
            "label": "TRUE_POSITIVE",
            "reason_code": "SUSPICIOUS_PATTERN",
            "reviewer_uid": 0,
        }
        writer.write(json.dumps(body).encode() + b"\n")
        await writer.drain()
        assert not json.loads(await reader.readline())["ok"]
        writer.close()
        await writer.wait_closed()
        assert not RuntimeFeedbackLoop(monitor).records()
        result, request = await submit(root, monitor, ids[0])
        assert result["ok"]
        nonce = uuid4()
        assert (
            await operator_request(
                root, "feedback-submit", feedback_request=request, request_id=nonce
            )
        )["ok"]
        assert not (
            await operator_request(
                root, "feedback-submit", feedback_request=request, request_id=nonce
            )
        )["ok"]


@pytest.mark.asyncio
async def test_evaluation_determinism_regression_detection_and_no_auto_promotion(
    tmp_path, monkeypatch
):
    from soc_agent.improvement_candidates.strategy import compile_candidate_strategy

    async with prepared(tmp_path, monkeypatch) as (root, monitor, ids):
        for identity in ids:
            assert (await submit(root, monitor, identity))[0]["ok"]
        candidate = RuntimeFeedbackLoop(monitor).prepare_candidates()[0]
    loop = RuntimeFeedbackLoop(LinuxMonitor(root))
    with exclusive_runtime_lock(root / "writer.lock"):
        first = loop.evaluate(candidate.candidate_id, repeated_failures=6, multiple_accounts=3)
        second = loop.evaluate(candidate.candidate_id, repeated_failures=6, multiple_accounts=3)
    assert first["evaluation_id"] == second["evaluation_id"]
    assert first["regression_result"] == "REGRESSED"
    assert first["promotion"] == "BLOCKED"
    with pytest.raises(ValueError):
        compile_candidate_strategy(candidate)
    assert loop.monitor.config.repeated_failures == 3


@pytest.mark.asyncio
async def test_feedback_digest_corruption_and_correction_invalidate_candidate(
    tmp_path, monkeypatch
):
    async with prepared(tmp_path, monkeypatch) as (root, monitor, ids):
        requests = []
        for identity in ids:
            result, request = await submit(root, monitor, identity)
            assert result["ok"]
            requests.append(request)
        loop = RuntimeFeedbackLoop(monitor)
        candidate = loop.prepare_candidates()[0]
        old = loop.active_records()[0]
        correction, _ = await submit(
            root,
            monitor,
            old.request.finding_id,
            label="INCONCLUSIVE",
            supersedes=old.request.feedback_id,
        )
        assert correction["ok"]
        with pytest.raises(ValueError):
            loop.candidate(candidate.candidate_id)
        with monitor.store.database.transaction() as c:
            rows = loop._events(c, "DIAGNOSTIC_FEEDBACK")
            payload = rows[-1]
            payload["details"]["record"]["feedback_digest"] = "0" * 64
            c.execute(
                "UPDATE monitor_audit SET payload=? WHERE sequence=?",
                (json.dumps(payload), payload["sequence"]),
            )
        with pytest.raises(ValueError):
            loop.records()
