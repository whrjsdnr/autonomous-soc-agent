"""Explicit Linux fixture replay. No live collector, LLM, model or OS response execution."""

import argparse
import asyncio
import json
import tempfile
from pathlib import Path
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from soc_agent.approval import ApprovalManager
from soc_agent.demo.scenario_analysis import analyze
from soc_agent.demo.scenario_models import (
    AssessmentMode,
    ResponseMode,
    ScenarioResult,
    Stage,
    scenarios,
)
from soc_agent.demo.scenario_pipeline import (
    fixture_event,
    open_pipeline,
    verify_network_dns_gate,
)
from soc_agent.demo.scenario_response import response_simulation
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ExecutionDeniedError, ExecutionError
from soc_agent.policy import PolicyEngine
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.runtime_lock import exclusive_runtime_lock
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.authentication_detection import DetectionConfig, detect
from soc_agent.security_ai.operational.authentication_investigation import (
    authentication_read_registry,
    read_authentication_view,
)
from soc_agent.security_ai.operational.native_authentication import SCENARIO_IDENTITY
from soc_agent.tools import ToolError


def verify_audit(directory: Path, incident: UUID) -> str:
    pipeline = open_pipeline(directory, incident, create=False)
    with pipeline.queue.database.transaction(write=False) as c:
        rows = c.execute("SELECT * FROM scenario_audit ORDER BY sequence").fetchall()
    previous = "0" * 64
    for expected, row in enumerate(rows, 1):
        payload = json.loads(row["payload"])
        if (
            row["sequence"] != expected
            or payload["previous"] != previous
            or payload["incident_id"] != str(incident)
            or content_digest_payload(payload) != row["digest"]
        ):
            raise ValueError("SCENARIO_AUDIT_INTEGRITY_REJECTED")
        previous = row["digest"]
    if not rows:
        raise ValueError("SCENARIO_AUDIT_MISSING")
    return previous


async def run_scenario(
    scenario_id: str,
    *,
    response_mode: ResponseMode = "DISABLED",
    assessment_mode: AssessmentMode = "SCRIPTED",
    env_file: Path | None = None,
    root: Path | None = None,
    replay_run_id: UUID | None = None,
    config: DetectionConfig | None = None,
) -> ScenarioResult:
    if response_mode not in ("DISABLED", "RESPONSE_SIMULATION"):
        raise ValueError("SCENARIO_RESPONSE_MODE_REJECTED")
    selected = next((s for s in scenarios() if s.scenario_id == scenario_id), None)
    if selected is None:
        raise ValueError("UNKNOWN_SCENARIO")
    # Every run gets a fresh private directory; no API for adopting a user/operating DB.
    directory = Path(tempfile.mkdtemp(prefix="soc-scenario-", dir=root)).resolve()
    create_private_directory(directory)
    run_id = replay_run_id or uuid4()
    incident = uuid5(NAMESPACE_URL, f"scenario:{selected.fixture_identity}:{run_id}")
    stages = {"collector": Stage(status="PASS", outcome="FIXTURE_REPLAY_NO_NATIVE_COLLECTION")}
    with exclusive_runtime_lock(directory / "writer.lock"):
        pipeline = open_pipeline(directory, incident, create=True)
        with pipeline.queue.database.transaction() as c:
            c.execute(
                "CREATE TABLE scenario_audit(sequence INTEGER PRIMARY KEY,"
                "payload TEXT NOT NULL,digest TEXT NOT NULL)"
            )
        start_payload = {
            "previous": "0" * 64,
            "incident_id": str(incident),
            "input_origin": "FIXTURE",
            "replay_run_id": str(run_id),
            "fixture_identity": selected.fixture_identity,
            "status": "STARTED",
        }
        start_digest = content_digest_payload(start_payload)
        with pipeline.queue.database.transaction() as c:
            c.execute(
                "INSERT INTO scenario_audit VALUES(1,?,?)",
                (json.dumps(start_payload), start_digest),
            )
        events = [fixture_event(selected, i, run_id) for i in range(len(selected.messages))]
        for event in events:
            pipeline.queue.enqueue(event, cursor_source=SCENARIO_IDENTITY)
        duplicate_count = 0
        if scenario_id == "S11":
            pipeline.queue.claim()  # Leave a durable unacknowledged claim for recovery.
            pipeline = open_pipeline(directory, incident, create=False)
            pipeline.queue.recover()  # Exclusive lock held; no concurrent worker.
            duplicate_count = sum(not pipeline.queue.enqueue(e) for e in events)
        for _ in events:
            pipeline.step()
        view = read_authentication_view(pipeline)
        detected = detect(pipeline, config or DetectionConfig())
        stages["queue"] = Stage(
            status="PASS" if view.queue_records_persisted == len(events) else "FAIL",
            outcome=f"PERSISTED={view.queue_records_persisted};DUPLICATES={duplicate_count}",
        )
        stages["evidence"] = Stage(
            status="PASS" if view.authentication_events_verified == len(events) else "FAIL",
            outcome="FIXTURE_SOURCE_WINDOW_PROVENANCE_VALIDATED",
        )
        stages["detection"] = Stage(
            status="PASS" if detected == tuple(sorted(selected.expected_detection)) else "FAIL",
            outcome=",".join(detected) or "NO_SIGNAL",
        )
        investigation, assessment, analysis_stages, exchanges = await analyze(
            pipeline,
            assessment_mode,
            env_file=env_file,
        )
        stages.update(analysis_stages)
        # Exercise the real read-only boundary with an unregistered WRITE proposal.
        write = ActionProposal(
            incident_id=incident,
            tool_name="disable_demo_account",
            tool_input={"account_id": "demo-alice"},
        )
        guarded = GovernedExecutor(
            registry=authentication_read_registry(pipeline),
            policy=PolicyEngine(),
            approvals=ApprovalManager(),
        )
        try:
            await guarded.execute(write)
        except ExecutionDeniedError:
            stages["read_only_boundary"] = Stage(status="PASS", outcome="WRITE_DENIED")
        else:
            raise ValueError("SCENARIO_READ_ONLY_BYPASS")
        from soc_agent.demo.tools import demo_response_tool

        policy = PolicyEngine().evaluate(demo_response_tool().metadata)
        stages["policy"] = Stage(
            status="PASS" if policy.decision.value == "require_approval" else "FAIL",
            outcome=policy.decision.value.upper(),
        )
        calls = 0
        audit_events = ("WRITE_DENIED",)
        if (
            scenario_id in {"S07", "S08", "S09", "S10"}
            and response_mode == "RESPONSE_SIMULATION"
            and all(stage.status == "PASS" for stage in analysis_stages.values())
        ):
            try:
                approval, execution, calls, response_events = await response_simulation(
                    scenario_id, incident
                )
            except (ExecutionError, ToolError, ValueError):
                # The existing tool boundary sanitizes handler failures. Preserve a failure
                # receipt; an unknown invocation count must never be reported as zero.
                approval = execution = "SIMULATION_FAILED"
                calls = None
                response_events = ("SIMULATION_FAILED_NO_OS_HANDLER",)
            audit_events += response_events
            status = "NOT_IMPLEMENTED" if approval == "NOT_IMPLEMENTED" else "PASS"
            stages["approval"] = Stage(
                status=status if approval == selected.expected_approval_outcome else "FAIL",
                outcome=approval,
            )
            stages["response_simulation"] = Stage(
                status=status if execution == selected.expected_execution_outcome else "FAIL",
                outcome=execution,
            )
        else:
            stages["approval"] = Stage(
                status="SKIPPED",
                outcome="SIMULATION_DISABLED"
                if scenario_id in {"S07", "S08", "S09", "S10"}
                else "NOT_REQUESTED",
            )
            stages["response_simulation"] = Stage(status="SKIPPED", outcome="DISABLED")
        gate_receipts = ()
        if scenario_id == "S12":
            gate_receipts = verify_network_dns_gate(directory, incident, run_id)
        stages["inference_gate"] = Stage(
            status="PASS",
            outcome="NETWORK_DNS_NOT_INFERABLE" if gate_receipts else view.inference_status,
        )
        # Actual durable reopen and read verification, not a regenerated summary.
        restored = read_authentication_view(open_pipeline(directory, incident, create=False))
        stages["restart"] = Stage(
            status="PASS" if restored == view else "FAIL",
            outcome="SQLITE_REOPEN_SOURCE_WINDOW_PROVENANCE_EQUAL",
        )
        payload = {
            "previous": start_digest,
            "incident_id": str(incident),
            "scenario_id": selected.scenario_id,
            "fixture_identity": selected.fixture_identity,
            "input_origin": "FIXTURE",
            "replay_run_id": str(run_id),
            "evidence_digest": view.evidence_digest,
            "provenance_references": list(view.provenance_reference),
            "model_gate_receipts": list(gate_receipts),
            "assessment_digest": content_digest_payload(assessment.model_dump(mode="json"))
            if assessment
            else None,
            "assessment_mode": assessment_mode,
            "llm_exchanges": list(exchanges),
            "events": list(audit_events),
            "investigation_audit_digest": content_digest_payload(
                {
                    "state": investigation.incident_state.model_dump(mode="json")
                    if investigation
                    else None
                }
            ),
            "stages": {k: v.model_dump(mode="json") for k, v in stages.items()},
            "simulated_handler_calls": calls,
            "real_os_handler_calls": 0,
        }
        digest = content_digest_payload(payload)
        with pipeline.queue.database.transaction() as c:
            c.execute(
                "INSERT INTO scenario_audit VALUES(2,?,?)",
                (json.dumps(payload, sort_keys=True), digest),
            )
        if verify_audit(directory, incident) != digest:
            raise ValueError("SCENARIO_AUDIT_VERIFY_FAILED")
        stages["audit"] = Stage(status="PASS", outcome="DURABLE_RECEIPT_VERIFIED")
    overall = (
        "FAIL"
        if any(s.status == "FAIL" for s in stages.values())
        else "BLOCKED"
        if any(s.status == "BLOCKED" for s in stages.values())
        else "PASS"
    )
    # Explicitly report incomplete scenario features instead of treating them as passed.
    if (
        overall == "PASS"
        and scenario_id in {"S07", "S08", "S09", "S10"}
        and response_mode == "DISABLED"
    ):
        overall = "SKIPPED"
    return ScenarioResult(
        scenario_id=selected.scenario_id,
        scenario_version=selected.scenario_version,
        fixture_identity=selected.fixture_identity,
        replay_run_id=run_id,
        response_mode=response_mode,
        assessment_mode=assessment_mode,
        llm_request_count=len(exchanges),
        stages=stages,
        detections=detected,
        verified_events=view.authentication_events_verified,
        duplicate_events=duplicate_count,
        simulated_handler_calls=calls,
        audit_receipt=digest,
        audit_path=str(directory / "queue.sqlite"),
        overall_status=overall,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    live = sub.add_parser("run-live")
    live.add_argument("--assessment-mode", choices=("SCRIPTED", "REAL_LLM"), default="SCRIPTED")
    live.add_argument("--env-file", type=Path)
    live.add_argument("--limit", type=int, default=16)
    live.add_argument("--batches", type=int, default=1)
    for name in ("run", "run-all"):
        command = sub.add_parser(name)
        if name == "run":
            command.add_argument("scenario_id", choices=[s.scenario_id for s in scenarios()])
        command.add_argument(
            "--input-mode",
            choices=("LIVE_LINUX", "SCENARIO"),
            default="SCENARIO",
            help="run command is explicit fixture opt-in; LIVE_LINUX is not replay",
        )
        command.add_argument(
            "--assessment-mode", choices=("SCRIPTED", "REAL_LLM"), default="SCRIPTED"
        )
        command.add_argument(
            "--env-file", type=Path, help="Explicit LLM environment file; never auto-loaded"
        )
        command.add_argument(
            "--response-mode", choices=("DISABLED", "RESPONSE_SIMULATION"), default="DISABLED"
        )
    args = parser.parse_args()
    if args.command == "list":
        print(
            json.dumps(
                [
                    s.model_dump(mode="json") | {"fixture_identity": s.fixture_identity}
                    for s in scenarios()
                ],
                indent=2,
            )
        )
        return 0
    if args.command == "run-live":
        from soc_agent.demo.scenario_live import run_live

        result = asyncio.run(
            run_live(
                assessment_mode=args.assessment_mode,
                env_file=args.env_file,
                limit=args.limit,
                batches=args.batches,
            )
        )
        print(result.model_dump_json(indent=2))
        return 1 if result.overall_status in ("FAIL", "BLOCKED") else 0
    if args.input_mode != "SCENARIO":
        parser.error(
            "LIVE_LINUX requires the existing native collector; this runner never starts it"
        )
    results = [
        asyncio.run(
            run_scenario(
                s.scenario_id,
                response_mode=args.response_mode,
                assessment_mode=args.assessment_mode,
                env_file=args.env_file,
            )
        )
        for s in scenarios()
        if args.command == "run-all" or s.scenario_id == args.scenario_id
    ]
    print(json.dumps([r.model_dump(mode="json") for r in results], indent=2))
    return 1 if any(r.overall_status in ("FAIL", "BLOCKED") for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
