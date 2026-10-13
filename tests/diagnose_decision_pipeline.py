"""Isolated actual SOC runtime/domain replay, with existing scripted LLM and no WRITE dispatch."""

import argparse
import ast
import asyncio
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import NAMESPACE_URL, uuid5

from pydantic import TypeAdapter

from soc_agent.api.models import StepRequest
from soc_agent.application import compose_application, open_application_store
from soc_agent.approval import ApprovalManager
from soc_agent.approval.errors import ApprovalError
from soc_agent.assessment import ThreatAssessor
from soc_agent.assessment.errors import AssessmentError
from soc_agent.decision import IncidentDecisionEngine
from soc_agent.demo.composition import DemoLLM
from soc_agent.demo.tools import (
    DemoIdentityInput,
    DemoIdentityOutput,
    demo_network_tool,
    demo_read_tool,
    demo_response_tool,
)
from soc_agent.deployment import DeploymentDescriptor, DeploymentProfile
from soc_agent.execution import ActionProposal, GovernedExecutor
from soc_agent.execution.errors import ExecutionError
from soc_agent.ingestion import EventIngestor, migrate_ingestion
from soc_agent.ingestion.models import Event
from soc_agent.policy import PolicyDecision, PolicyEngine
from soc_agent.review.authentication import (
    AuthenticatedPrincipal,
    HumanActionContext,
    HumanConfirmation,
    ProviderHumanAuthority,
)
from soc_agent.review.authority import HumanAction
from soc_agent.review.authorization import HumanRole, RBACPermissionVerifier
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.persistence.secure_storage import create_private_directory
from soc_agent.security_ai.model_analysis import PackagedAnalysis
from soc_agent.security_ai.packaging import load_package
from soc_agent.security_ai.packaging.files import read_package
from soc_agent.tools import Tool, ToolRegistry, ToolRiskLevel
from soc_agent.tools.errors import ToolError
from tests.decision_pipeline_contract import (
    CONTRACT,
    FIXTURE_PIN,
    DecisionExport,
    PolicyCall,
    RuntimeEvent,
    SequenceTrace,
    compare,
    correctness,
)
from tests.diagnose_native_inference import (
    ROOT,
    encoded,
    environment,
    read_document,
    read_json,
    sha,
    write_new,
)
from tests.scenarios.test_security_ai_fusion import PINS

FIXTURE = ROOT / "tests/fixtures/decision_pipeline_events_v1.json"
NOW = datetime(2026, 1, 1, tzinfo=UTC)
POLICY_SOURCES = (
    "policy/engine.py",
    "approval/models.py",
    "approval/manager.py",
    "execution/executor.py",
    "execution/binding.py",
    "review/authentication.py",
    "review/authorization.py",
    "review/validation.py",
    "decision/rules.py",
    "investigation/runtime/service.py",
    "application.py",
    "demo/composition.py",
    "demo/tools.py",
    "security_ai/model_analysis.py",
)


class WriteSentinel:
    def __init__(self):
        self.calls = 0

    async def __call__(self, value):
        self.calls += 1
        raise AssertionError("Offline validation must never dispatch WRITE")


def registry(ingestion):
    tools = ToolRegistry()
    tools.register(demo_read_tool(ingestion))
    tools.register(demo_network_tool(ingestion))
    sentinel = WriteSentinel()
    tools.register(
        Tool(demo_response_tool().metadata, DemoIdentityInput, DemoIdentityOutput, sentinel)
    )
    return tools, sentinel


def policy_configuration():
    sources = {}
    for name in POLICY_SOURCES:
        text = (ROOT / "src/soc_agent" / name).read_text(encoding="utf-8-sig")
        sources[name] = sha(ast.dump(ast.parse(text), include_attributes=False).encode("utf-8"))
    # AST hash permits CRLF/comments only, not semantic code/config changes.
    return {
        "source_ast_sha256": sources,
        "runtime_round_limit": 2,
        "authority": "default deny; no injected operational human provider",
        "write_metadata": demo_response_tool().metadata.model_dump(mode="json"),
        "provider_test_maximum_age_seconds": 300,
        "diagnostic_adapter_ast_sha256": sha(
            ast.dump(
                ast.parse(Path(__file__).read_text(encoding="utf-8")), include_attributes=False
            ).encode("utf-8")
        ),
        "adapter": "existing DemoLLM; source-scripted offline response; real domain validation",
    }


async def replay_sequence(directory: Path, definition: dict, fixture: dict, packages):
    create_private_directory(directory, exist_ok=False)
    store = open_application_store(directory / "store.db", create=True)
    migrate_ingestion(store)
    ingestion = EventIngestor(store)
    tools, sentinel = registry(ingestion)
    service = compose_application(
        store,
        deployment=DeploymentDescriptor(profile=DeploymentProfile.DEMO),
        registry=tools,
        llm_client=DemoLLM(ingestion),
        ingestion=ingestion,
        model_analysis=PackagedAnalysis(ingestion, packages),
    ).service
    events = []
    approval_calls = []
    original_create = ApprovalManager.create

    def observe_approval(manager, *args, **kwargs):
        request = original_create(manager, *args, **kwargs)
        approval_calls.append(request)
        return request

    for name in definition["events"]:
        event = TypeAdapter(Event).validate_python(fixture["events"][name])
        loaded = service.ingest(event)
        identity = loaded.incident_id
        initial = service.incident(identity).state
        calls = []
        actual = PolicyEngine.evaluate

        def observe(policy, metadata, original=actual, observed=calls):
            result = original(policy, metadata)
            observed.append(PolicyCall(metadata=metadata, result=result))
            return result

        if loaded.duplicate:
            workflow = service.workflow(identity)
        else:
            workflow = service.start(identity)
        progress = [workflow]
        with (
            patch.object(PolicyEngine, "evaluate", observe),
            patch.object(ApprovalManager, "create", observe_approval),
        ):
            for _ in range(fixture["limits"]["steps_per_event"]):
                if workflow.waiting_for_human or workflow.terminal or workflow.failure is not None:
                    break
                workflow = await service.step(
                    identity,
                    StepRequest(
                        run_id=workflow.workflow_id, expected_revision=workflow.checkpoint_revision
                    ),
                )
                progress.append(workflow)
            else:
                raise ValueError("Existing runtime did not reach its bounded stop")
        value = RuntimeEvent(
            receipt=ingestion.load(identity),
            duplicate=loaded.duplicate,
            initial_state=initial,
            state=service.incident(identity).state,
            checkpoint=service.checkpoint(identity),
            trace=service.trace(identity),
            progress=progress,
            policy_calls=calls,
        )
        value.verify()
        events.append(value)
    with store.database.transaction(write=False) as connection:
        executions = connection.execute("SELECT count(*) FROM execution_records").fetchone()[0]
    return SequenceTrace(
        case_id=definition["id"],
        events=events,
        audit=list(store.events()),
        write_calls=sentinel.calls,
        approval_rows=len(approval_calls),
        execution_rows=executions,
    ), service


class AssessmentInput:
    """Explicit test response adapter; actual ThreatAssessor/reference/decision rules run."""

    def __init__(self, severity="info", foreign=False):
        self.severity, self.foreign = severity, foreign

    async def generate_structured(self, *, request, response_model):
        data = json.loads(request.user_prompt)
        refs = (
            [str(uuid5(NAMESPACE_URL, "offline-foreign-evidence"))]
            if self.foreign
            else [e["evidence_id"] for e in data["EVIDENCE (UNTRUSTED DATA)"]]
        )
        return response_model.model_validate(
            {
                "observations": [],
                "hypotheses": [],
                "assessment": {
                    "severity": self.severity,
                    "confidence": 0.0,
                    "summary": "Synthetic advisory boundary input",
                    "supporting_evidence_ids": refs,
                },
            }
        )


class InvalidPolicy:
    def evaluate(self, metadata):
        return object()  # explicitly faulty injected dependency, not a new PolicyDecision


class RejectedProvider:
    """Synthetic invalid claims only. No real credential, issuance or authorization."""

    def __init__(self, case, principal, confirmation):
        self.case, self.principal, self.confirmation = case, principal, confirmation

    def authenticate(self, credential):
        if self.case == "invalid_credential":
            raise HumanAuthorizationDenied("Synthetic invalid identity rejected")
        return self.principal

    def confirm(self, credential, principal, context):
        return {} if self.case == "invalid_confirmation_format" else self.confirmation


class TestRoles:
    def __init__(self, case):
        self.case = case

    def roles_for(self, principal, context):
        return (HumanRole.ANALYST,) if self.case == "insufficient_role" else (HumanRole.APPROVER,)


def identity_guard(case):
    context = HumanActionContext(
        incident_id=uuid5(NAMESPACE_URL, "offline-guard-incident"),
        action=HumanAction.APPROVE_PROMOTED_TOOL,
        decision_id="d" * 64,
        binding_digest="b" * 64,
    )
    principal = AuthenticatedPrincipal(
        subject_id="synthetic-human-claim",
        provider_id="offline-rejected-provider",
        session_id="synthetic-session",
        subject_kind="human",
        authentication_context=("test-only",),
        authenticated_at=NOW,
        expires_at=NOW + timedelta(minutes=4),
        scopes=(),
    )
    confirmation = HumanConfirmation(
        confirmation_id="synthetic-rejected-confirmation",
        subject_id=principal.subject_id,
        provider_id=principal.provider_id,
        session_id=principal.session_id,
        action=context.action,
        binding_digest=context.binding_digest,
        confirmed_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )
    if case == "expired_principal":
        principal = principal.model_copy(update={"expires_at": NOW - timedelta(seconds=1)})
    if case == "expired_confirmation":
        confirmation = confirmation.model_copy(update={"expires_at": NOW - timedelta(seconds=1)})
    if case == "confirmation_wrong_session":
        confirmation = confirmation.model_copy(update={"session_id": "different-session"})
    if case == "confirmation_wrong_digest":
        confirmation = confirmation.model_copy(update={"binding_digest": "c" * 64})
    authority = ProviderHumanAuthority(
        provider=RejectedProvider(case, principal, confirmation),
        provider_id=principal.provider_id,
        permissions=RBACPermissionVerifier(roles=TestRoles(case)),
        resolve_context=lambda a, b: context,
        clock=lambda: NOW,
    )
    try:
        authority.verify(
            credential="offline-invalid-input-not-a-token",
            action=context.action,
            binding_digest=context.binding_digest,
        )
        result = {"blocked": False, "permitted": True, "error_type": None}
    except (ValueError, TypeError) as error:
        result = {"blocked": True, "permitted": False, "error_type": type(error).__name__}
    return result | {
        "verification_records": len(authority.verification_records()),
        "adapter": "rejected synthetic provider claims; actual ProviderHumanAuthority and RBAC",
        "clock": NOW.isoformat(),
        "write_calls": 0,
    }


async def guard(case, service):
    identity = service.ingest(
        TypeAdapter(Event).validate_python(read_json(FIXTURE)["events"]["auth_success"])
    ).incident_id
    state = service.incident(identity).state
    if case in ("missing_evidence", "foreign_evidence_reference", "advisory_info", "advisory_low"):
        try:
            source = (
                state.model_copy(update={"evidence": ()}) if case == "missing_evidence" else state
            )
            result = await ThreatAssessor(
                llm_client=AssessmentInput(
                    "low" if case == "advisory_low" else "info",
                    case == "foreign_evidence_reference",
                )
            ).assess(source)
            decision = IncidentDecisionEngine().decide(
                result.incident_state, result.threat_assessment
            )
            return {
                "case_id": case,
                "blocked": False,
                "decision": decision.outcome.value,
                "severity": result.threat_assessment.severity.value,
                "write_calls": 0,
            }
        except (AssessmentError, ValueError) as error:
            return {
                "case_id": case,
                "blocked": True,
                "error_type": type(error).__name__,
                "write_calls": 0,
            }
    if case == "event_identity_conflict":
        event = service.ingestion.load(identity).event.model_copy(
            update={"severity_hint": "critical"}
        )
        try:
            service.ingest(event)
            return {"case_id": case, "blocked": False, "error_type": None}
        except ValueError as error:
            return {"case_id": case, "blocked": True, "error_type": type(error).__name__}
    if case == "stored_evidence_tamper":
        # Fault injection on isolated SQLite only; retain old fingerprint to exercise rejection.
        with service.store.database.transaction() as connection:
            row = connection.execute(
                "SELECT payload FROM incidents WHERE incident_id=?", (str(identity),)
            ).fetchone()
            payload = json.loads(row["payload"])
            payload["evidence"][0]["raw_data"] = "synthetic-tamper"
            connection.execute(
                "UPDATE incidents SET payload=? WHERE incident_id=?",
                (json.dumps(payload), str(identity)),
            )
        try:
            service.store.load(identity)
            return {"case_id": case, "blocked": False, "error_type": None}
        except ValueError as error:
            return {"case_id": case, "blocked": True, "error_type": type(error).__name__}
    if case in (
        "expired_principal",
        "expired_confirmation",
        "confirmation_wrong_session",
        "confirmation_wrong_digest",
        "insufficient_role",
        "invalid_confirmation_format",
        "invalid_credential",
    ):
        return {"case_id": case} | identity_guard(case)
    tools, sentinel = registry(service.ingestion)
    approvals = ApprovalManager()
    policy = PolicyEngine()
    engine = GovernedExecutor(
        registry=tools,
        policy=None
        if case == "missing_policy"
        else InvalidPolicy()
        if case == "non_policy_result"
        else policy,
        approvals=approvals,
    )
    action = ActionProposal(
        action_id=uuid5(NAMESPACE_URL, "offline-stable-action"),
        incident_id=identity,
        tool_name="read_demo_authentication"
        if case == "read_allowed"
        else "absent_tool"
        if case == "unknown_tool"
        else "disable_demo_account",
        tool_input={"incident_id": str(identity)}
        if case == "read_allowed"
        else {"account_id": "demo-alice"},
        created_at=NOW,
    )
    if case == "destructive":
        meta = demo_response_tool().metadata.model_copy(
            update={"name": "diagnostic_destructive", "risk_level": ToolRiskLevel.DESTRUCTIVE}
        )
        tools.register(Tool(meta, DemoIdentityInput, DemoIdentityOutput, sentinel))
        action = action.model_copy(update={"tool_name": meta.name})
    if case == "invalid_policy_metadata":
        result = policy.evaluate(None)
        return {
            "case_id": case,
            "blocked": result.decision == PolicyDecision.DENY,
            "policy": result.model_dump(mode="json"),
            "error_type": None,
            "rejection_reason": result.reason,
            "write_calls": 0,
        }
    approval_id = None
    if case in ("pending_write", "stable_action_id_mismatch", "approval_target_mismatch"):
        request = engine.request_approval(
            action, reason="Synthetic pending request; never approved"
        )
        approval_id = request.approval_id
        if case == "stable_action_id_mismatch":
            action = action.model_copy(
                update={"action_id": uuid5(NAMESPACE_URL, "offline-wrong-action")}
            )
        if case == "approval_target_mismatch":
            action = ActionProposal.model_validate(
                action.model_dump() | {"tool_input": {"account_id": "demo-bob"}}
            )
    if case == "forged_approval_id":
        approval_id = uuid5(NAMESPACE_URL, "offline-forged-approved-id-not-in-ledger")
    try:
        metadata = engine.preflight(action, approval_id=approval_id)
        result = {
            "blocked": False,
            "permitted": True,
            "error_type": None,
            "metadata": metadata.model_dump(mode="json"),
        }
    except (
        ExecutionError,
        ApprovalError,
        ToolError,
        ValueError,
        KeyError,
        AttributeError,
    ) as error:
        result = {"blocked": True, "permitted": False, "error_type": type(error).__name__}
    result |= {
        "case_id": case,
        "action_id": str(action.action_id),
        "tool_name": action.tool_name,
        "tool_input": action.tool_input,
        "approval_statuses": [r.status.value for r in approvals.list()],
        "write_calls": sentinel.calls,
    }
    if case not in ("missing_policy", "non_policy_result", "unknown_tool"):
        result["policy"] = policy.evaluate(tools.get(action.tool_name).metadata).model_dump(
            mode="json"
        )
        result["approval_required"] = result["policy"]["decision"] == "require_approval"
    return result


async def export(output: Path):
    if output.exists():
        raise FileExistsError("Existing decision output must not be overwritten")
    fixture, raw = read_document(FIXTURE)
    if sha(raw) != FIXTURE_PIN:
        raise ValueError("Decision fixture integrity mismatch")
    create_private_directory(output, exist_ok=False)
    packages = tuple(
        load_package(
            ROOT / "tests/fixtures/security_ai_packages" / kind, expected_manifest_digest=pin
        )
        for kind, pin, _ in PINS
    )
    model_files = {
        kind: {
            name: sha(raw)
            for name, raw in read_package(
                ROOT / "tests/fixtures/security_ai_packages" / kind
            ).items()
        }
        for kind, _, _ in PINS
    }
    sequences = []
    guard_service = None
    for sequence in fixture["sequences"]:
        result, service = await replay_sequence(
            output / sequence["id"], sequence, fixture, packages
        )
        sequences.append(result)
        if sequence["id"] == "auth_success":
            guard_service = service
    guards = []
    # Tamper last so no later guard depends on the intentionally damaged test DB.
    for name in [n for n in fixture["guard_cases"] if n != "stored_evidence_tamper"] + [
        "stored_evidence_tamper"
    ]:
        guards.append(await guard(name, guard_service))
    guards.sort(key=lambda g: fixture["guard_cases"].index(g["case_id"]))
    host, versions = environment()
    config = policy_configuration()
    value = DecisionExport(
        contract=CONTRACT,
        fixture_sha256=sha(raw),
        fixture=fixture,
        policy_sha256=sha(encoded(config)),
        policy_configuration=config,
        model_files=model_files,
        environment=host | versions,
        adapter=config["adapter"],
        sequences=sequences,
        guards=guards,
        metadata={"captured_at": datetime.now(UTC).isoformat(), "output_directory": str(output)},
    )
    errors = correctness(value)
    write_new(output / "trace.json", encoded(value.model_dump(mode="json")))
    write_new(
        output / "correctness.json",
        encoded({"status": "FAIL" if errors else "PASS", "errors": errors}),
    )
    if errors:
        raise ValueError("Decision fixture security oracle failed")
    return value.model_dump(mode="json")


def save_reports(output: Path, result: dict):
    create_private_directory(output, exist_ok=False)
    write_new(output / "report.json", encoded(result))
    text = (
        "# Offline SOC Decision Pipeline Equivalence\n\n"
        f"Status: **{result['status']}**\n\n"
        "Scope: fixed synthetic events, existing scripted LLM, actual SOC domain and guard "
        "logic. Operational human authorization and privileged execution are not exercised.\n\n"
        "```json\n" + encoded(result).decode("utf-8") + "```\n"
    )
    write_new(output / "report.md", text.encode("utf-8"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("export")
    run.add_argument("--output", type=Path, required=True)
    cmp = sub.add_parser("compare")
    cmp.add_argument("--left", type=Path, required=True)
    cmp.add_argument("--right", type=Path, required=True)
    cmp.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "export":
            asyncio.run(export(args.output))
        else:
            value = compare(read_json(args.left), read_json(args.right))
            save_reports(args.output, value)
            return 1 if value["status"] == "FAIL" else 0
    except (ValueError, TypeError, KeyError, AttributeError, OSError) as error:
        print(json.dumps({"status": "FAIL", "error_type": type(error).__name__}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
