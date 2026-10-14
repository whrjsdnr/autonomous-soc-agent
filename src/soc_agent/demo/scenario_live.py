"""Bounded WSL native read probe; never replays fixtures or enables response actions."""

import json
import tempfile
from pathlib import Path
from uuid import uuid4

from soc_agent.approval import ApprovalManager
from soc_agent.demo.scenario_analysis import analyze
from soc_agent.demo.scenario_models import AssessmentMode, ScenarioResult, Stage
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ExecutionDeniedError
from soc_agent.policy import PolicyEngine
from soc_agent.realtime.collectors import CollectorUnavailable
from soc_agent.realtime.queue import EventQueue
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.authentication_investigation import (
    authentication_read_registry,
    read_authentication_view,
)
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector
from soc_agent.security_ai.operational.source_store import OperationalSourceStore


async def run_live(
    *,
    assessment_mode: AssessmentMode = "SCRIPTED",
    env_file: Path | None = None,
    limit: int = 16,
    batches: int = 1,
) -> ScenarioResult:
    if not 1 <= limit <= 16 or not 1 <= batches <= 8:
        raise ValueError("LIVE_PROBE_LIMIT_REJECTED")
    directory = Path(tempfile.mkdtemp(prefix="soc-live-read-")).resolve()
    incident, run_id = uuid4(), uuid4()
    stages = {}
    collected = verified = 0
    exchanges = ()
    with exclusive_runtime_lock(directory / "writer.lock"):
        collector = LinuxAuthenticationCollector(include_pam_failures=True)
        pipeline = AuthenticationPipeline(
            EventQueue.create(directory / "queue.sqlite"),
            OperationalSourceStore.create(
                directory / "sources.sqlite", allowed_lateness_seconds=60, max_future_skew_seconds=5
            ),
            incident,
            collector_identity=collector.identity,
        )
        try:
            for _ in range(batches):
                count = pipeline.collect(collector, limit=limit)
                collected += count
                if count < limit:
                    break
            stages["collector"] = Stage(
                status="PASS", outcome=f"NATIVE_JOURNAL_RECORDS={collected}"
            )
        except CollectorUnavailable as error:
            stages["collector"] = Stage(status="BLOCKED", outcome=type(error).__name__)
        for _ in range(collected):
            pipeline.step()
        view = read_authentication_view(pipeline)
        verified = view.authentication_events_verified
        stages["queue"] = Stage(status="PASS", outcome=f"PERSISTED={view.queue_records_persisted}")
        stages["evidence"] = Stage(
            status="PASS" if verified else "BLOCKED",
            outcome=f"VERIFIED_AUTH={verified};UNSUPPORTED={view.authentication_events_unsupported}",
        )
        if verified:
            _, _, analysis, exchanges = await analyze(pipeline, assessment_mode, env_file=env_file)
            stages.update(analysis)
        else:
            blocked = Stage(status="BLOCKED", outcome="NO_VERIFIED_NATIVE_AUTHENTICATION_EVENT")
            stages.update(investigation=blocked, threat_assessment=blocked)
        guarded = GovernedExecutor(
            registry=authentication_read_registry(pipeline),
            policy=PolicyEngine(),
            approvals=ApprovalManager(),
        )
        action = ActionProposal(
            incident_id=incident,
            tool_name="disable_demo_account",
            tool_input={"account_id": "demo-alice"},
        )
        try:
            await guarded.execute(action)
        except ExecutionDeniedError:
            stages["read_only_boundary"] = Stage(status="PASS", outcome="WRITE_DENIED")
        else:
            raise ValueError("LIVE_READ_ONLY_BYPASS")
        for name in ("approval", "response_simulation"):
            stages[name] = Stage(status="SKIPPED", outcome="LIVE_RESPONSE_DISABLED")
        stages["inference_gate"] = Stage(status="PASS", outcome="NOT_INFERABLE")
        payload = {
            "contract_version": "soc-live-read-probe:v1",
            "input_mode": "LIVE_LINUX",
            "input_origin": "NATIVE_OS",
            "assessment_mode": assessment_mode,
            "incident_id": str(incident),
            "run_id": str(run_id),
            "evidence_digest": view.evidence_digest,
            "provenance_references": list(view.provenance_reference),
            "stages": {k: v.model_dump(mode="json") for k, v in stages.items()},
            "llm_exchanges": list(exchanges),
            "real_os_handler_calls": 0,
        }
        digest = content_digest_payload(payload)
        with pipeline.queue.database.transaction() as c:
            c.execute("CREATE TABLE live_probe_receipt(payload TEXT NOT NULL,digest TEXT NOT NULL)")
            c.execute("INSERT INTO live_probe_receipt VALUES(?,?)", (json.dumps(payload), digest))
        with pipeline.queue.database.transaction(write=False) as c:
            row = c.execute("SELECT * FROM live_probe_receipt").fetchone()
            if content_digest_payload(json.loads(row["payload"])) != row["digest"]:
                raise ValueError("LIVE_PROBE_AUDIT_INTEGRITY_REJECTED")
        stages["audit"] = Stage(status="PASS", outcome="NATIVE_READ_RECEIPT_VERIFIED")
    return ScenarioResult(
        scenario_id="LIVE_LINUX_PROBE",
        scenario_version="1.0.0",
        input_mode="LIVE_LINUX",
        input_origin="NATIVE_OS",
        assessment_mode=assessment_mode,
        llm_request_count=len(exchanges),
        fixture_identity="NOT_APPLICABLE",
        replay_run_id=run_id,
        response_mode="DISABLED",
        stages=stages,
        detections=(),
        verified_events=verified,
        duplicate_events=0,
        simulated_handler_calls=0,
        audit_receipt=digest,
        audit_path=str(directory / "queue.sqlite"),
        overall_status="BLOCKED" if any(v.status == "BLOCKED" for v in stages.values()) else "PASS",
    )
