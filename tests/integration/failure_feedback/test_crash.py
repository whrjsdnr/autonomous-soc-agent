"""Four commit boundaries in harness-owned child processes and temporary stores."""

import asyncio
import json
import multiprocessing
import os
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from tests.authentication_crash_harness import kill_owned_checkpoint, security_check
from tests.integration.failure_feedback.test_loop import prepared
from tests.unit.holdout.test_contract import contracts

from soc_agent.experience.failure import capture_failure
from soc_agent.linux_runtime.failure_feedback import FailureFeedbackLoop, FailureFeedbackRequest
from soc_agent.linux_runtime.holdout_evaluation import HoldoutEvaluation
from soc_agent.linux_runtime.operator import operator_request
from soc_agent.linux_runtime.service import LinuxMonitor
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.operational.authentication_investigation import read_authentication_view
from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector


def child(root, point, candidate_id, sender, nonce):
    LinuxAuthenticationCollector.poll = lambda *args: []
    monitor = LinuxMonitor(Path(root))
    commit = monitor.store.database._commit
    kind = "HOLDOUT_CLAIM" if "HOLDOUT" in point else "FAILURE_FEEDBACK"

    def pause():
        sender.send((os.getpid(), nonce, point))
        sender.recv()

    def committed(connection):
        row = connection.execute(
            "SELECT payload FROM monitor_audit ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        hit = row and json.loads(row[0])["kind"] == kind
        if hit and point.startswith("BEFORE"):
            pause()
        commit(connection)
        if hit and point.startswith("AFTER"):
            pause()

    monitor.store.database._commit = committed
    if candidate_id:
        with exclusive_runtime_lock(Path(root) / "writer.lock"):
            dataset, contract = contracts()
            HoldoutEvaluation(monitor).run(
                candidate_id, contract, dataset, repeated_failures=4, multiple_accounts=3
            )
    else:
        asyncio.run(monitor.run(duration_seconds=20, operator_uids=(os.geteuid(),)))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "point",
    [
        "BEFORE_FAILURE_COMMIT",
        "AFTER_FAILURE_COMMIT",
        "BEFORE_HOLDOUT_COMMIT",
        "AFTER_HOLDOUT_COMMIT",
    ],
)
async def test_owned_crash_append_commit_and_holdout_claim(tmp_path, monkeypatch, point):
    candidate_id = None
    async with prepared(tmp_path, monkeypatch) as (root, monitor, query):
        request = FailureFeedbackRequest(
            feedback_id=uuid4(),
            query=query,
            expected_experience_id=capture_failure(monitor, query)["experience_id"],
            reason_code="EXPECTED_RULE_MISSING",
        )
        if "HOLDOUT" in point:
            assert (await operator_request(root, "failure-submit", failure_feedback=request))["ok"]
            candidate_id = (await operator_request(root, "candidates"))["result"]["candidates"][0][
                "candidate_id"
            ]
    source_digest = read_authentication_view(monitor.pipeline).evidence_digest
    context = multiprocessing.get_context("spawn")
    parent, sender = context.Pipe()
    nonce = str(uuid4())
    process = context.Process(target=child, args=(str(root), point, candidate_id, sender, nonce))
    process.start()
    sender.close()
    client = None
    try:
        if candidate_id is None:
            path = tmp_path / "feedback.json"
            path.write_text(request.model_dump_json())
            path.chmod(0o600)
            for _ in range(500):
                if (root / "operator/review.sock").exists():
                    break
                await asyncio.sleep(0.01)
            client = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                "soc_agent.linux_runtime",
                "--directory",
                str(root),
                "operator",
                "failure-submit",
                "--input",
                str(path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        kill_owned_checkpoint(process, parent, nonce, point, root / "writer.lock")
        if client:
            await client.communicate()
            assert client.returncode != 0
        restored = LinuxMonitor(root)
        restored.store.verify_audit()
        assert read_authentication_view(restored.pipeline).evidence_digest == source_digest
        assert restored.pipeline.queue.counts() == {"DONE": 1}
        if candidate_id:
            dataset, contract = contracts()
            with exclusive_runtime_lock(root / "writer.lock"):
                if point.startswith("AFTER"):
                    with pytest.raises(ValueError, match="HOLDOUT_REUSE"):
                        HoldoutEvaluation(restored).run(
                            candidate_id,
                            contract,
                            dataset,
                            repeated_failures=4,
                            multiple_accounts=3,
                        )
                else:
                    assert (
                        HoldoutEvaluation(restored).run(
                            candidate_id,
                            contract,
                            dataset,
                            repeated_failures=4,
                            multiple_accounts=3,
                        )["promotion"]
                        == "BLOCKED"
                    )
        else:
            assert len(FailureFeedbackLoop(restored).records()) == (
                1 if point.startswith("AFTER") else 0
            )
        assert (await security_check(restored.pipeline))["write_spy_calls"] == 0
    finally:
        if process.is_alive():
            process.kill()
            process.join(5)  # Only this harness-created child.
        if client and client.returncode is None:
            await client.communicate()
        parent.close()
