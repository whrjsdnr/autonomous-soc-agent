"""Explicit LLM opt-in; missing configuration never falls back to scripted success."""

from pathlib import Path

from pydantic import BaseModel, ValidationError

from soc_agent._json import canonical_json_object
from soc_agent.approval import ApprovalManager
from soc_agent.assessment import ThreatAssessor
from soc_agent.assessment.errors import AssessmentError
from soc_agent.assessment.models import AssessmentResult
from soc_agent.demo.scenario_models import AssessmentMode, Stage
from soc_agent.execution import GovernedExecutor
from soc_agent.investigation import InvestigationOrchestrator, InvestigationResult
from soc_agent.llm import LLMClient, MockLLMClient
from soc_agent.llm.errors import LLMError
from soc_agent.llm.openai_compatible import OpenAICompatibleClient, OpenAICompatibleSettings
from soc_agent.planning import InvestigationPlanner
from soc_agent.planning.errors import PlanningError
from soc_agent.policy import PolicyEngine
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.authentication_investigation import (
    authentication_read_registry,
    investigate_authentication,
    read_authentication_view,
)
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.state import Evidence, IncidentState


class RecordedLLM:
    """Retain hashes and failure categories, never credentials or raw provider replies."""

    def __init__(self, client: LLMClient):
        self.client = client
        self.exchanges: list[dict[str, str]] = []

    async def generate_structured[T: BaseModel](self, *, request, response_model: type[T]) -> T:
        record = {
            "request_digest": content_digest_payload(request.model_dump(mode="json")),
            "status": "ATTEMPTED",
        }
        self.exchanges.append(record)
        try:
            response = await self.client.generate_structured(
                request=request, response_model=response_model
            )
        except LLMError as error:
            record["status"] = type(error).__name__
            raise
        record["response_digest"] = content_digest_payload(response.model_dump(mode="json"))
        record["status"] = "RECEIVED_UNTRUSTED"
        return response


async def analyze(
    pipeline: AuthenticationPipeline,
    mode: AssessmentMode,
    *,
    client: LLMClient | None = None,
    env_file: Path | None = None,
    finding_context: dict | None = None,
) -> tuple[
    InvestigationResult | None,
    AssessmentResult | None,
    dict[str, Stage],
    tuple[dict[str, str], ...],
]:
    if mode not in ("REAL_LLM", "SCRIPTED"):
        raise ValueError("ASSESSMENT_MODE_REJECTED")
    recorded = None
    if mode == "REAL_LLM":
        if client is None:
            try:
                client = OpenAICompatibleClient(OpenAICompatibleSettings(_env_file=env_file))
            except ValidationError:
                blocked = Stage(status="BLOCKED", outcome="REAL_LLM_CONFIGURATION_UNAVAILABLE")
                return None, None, {"investigation": blocked, "threat_assessment": blocked}, ()
        recorded = RecordedLLM(client)
    try:
        if recorded is None:
            investigation = await investigate_authentication(pipeline)
        else:
            view = read_authentication_view(pipeline)
            state = IncidentState(incident_id=pipeline.incident_id).add_evidence(
                Evidence(
                    incident_id=pipeline.incident_id,
                    source="SCENARIO_FIXTURE"
                    if pipeline.binding["collector"].startswith("scenario:")
                    else "NATIVE_OS_DECLARED_SOURCE",
                    summary="Read-only authentication staging context; not proof of an attack",
                    raw_data=view.model_dump_json(),
                    observed_at=view.authentication_window[0].started_at,
                )
            )
            if finding_context is not None:
                state = state.add_evidence(
                    Evidence(
                        incident_id=pipeline.incident_id,
                        source="DETERMINISTIC_FINDING_ADVISORY",
                        summary="Rule correlation candidate; not an attack fact or authority",
                        raw_data=canonical_json_object(finding_context),
                        observed_at=view.authentication_window[0].started_at,
                    )
                )
            registry = authentication_read_registry(pipeline)
            planner = InvestigationPlanner(llm_client=recorded, registry=registry)
            plan = await planner.create_plan(state)
            investigation = await InvestigationOrchestrator(
                executor=GovernedExecutor(
                    registry=registry,
                    policy=PolicyEngine(),
                    approvals=ApprovalManager(),
                )
            ).execute_plan(incident_state=state, plan=plan, require_read_only=True)
        if not all(s.status.value == "completed" for s in investigation.plan.steps):
            blocked = Stage(status="BLOCKED", outcome="READ_ONLY_INVESTIGATION_INCOMPLETE")
            return (
                investigation,
                None,
                {"investigation": blocked, "threat_assessment": blocked},
                tuple(recorded.exchanges) if recorded else (),
            )
        if recorded is None:
            client = MockLLMClient(
                [
                    {
                        "observations": [],
                        "hypotheses": [],
                        "assessment": {
                            "severity": "info",
                            "confidence": 0.0,
                            "summary": "FIXTURE advisory only: no attack established; no authority",
                            "supporting_evidence_ids": [
                                str(e.evidence_id) for e in investigation.incident_state.evidence
                            ],
                        },
                    }
                ]
            )
        assessment = await ThreatAssessor(llm_client=recorded or client).assess(
            investigation.incident_state
        )
    except (LLMError, PlanningError, AssessmentError) as error:
        blocked = Stage(status="BLOCKED", outcome=type(error).__name__)
        return (
            None,
            None,
            {"investigation": blocked, "threat_assessment": blocked},
            tuple(recorded.exchanges) if recorded else (),
        )
    return (
        investigation,
        assessment,
        {
            "investigation": Stage(
                status="PASS", outcome="REAL_LLM_READ_ONLY" if recorded else "READ_ONLY_NO_LLM"
            ),
            "threat_assessment": Stage(
                status="PASS",
                outcome="REAL_LLM_VALIDATED_ADVISORY"
                if recorded
                else "SCRIPTED_ADVISORY_NO_LIVE_LLM",
            ),
        },
        tuple(recorded.exchanges) if recorded else (),
    )
