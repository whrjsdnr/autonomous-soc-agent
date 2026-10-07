"""Deterministic projection of retained backend facts, never a governance decision."""

from soc_agent.api.dashboard.models import (
    ActivityView,
    DashboardOverview,
    HumanActionView,
    IncidentView,
    SignalView,
    WorkflowView,
)
from soc_agent.assessment import FusionAssessmentResult
from soc_agent.investigation.runtime.models import WorkflowStep
from soc_agent.review.persistence.dashboard import DashboardSource
from soc_agent.state import IncidentStatus


def project_overview(sources: tuple[DashboardSource, ...]) -> DashboardOverview:
    incidents, actions, activity = [], [], []
    signal_options: dict[str, list[SignalView]] = {
        "Network AI": [],
        "Authentication AI": [],
        "Fusion": [],
    }
    signal_ids = set()
    active_workflows = 0
    recovery = False
    for source in sources:
        state, saved = source.incident.state, source.checkpoint
        workflow = None
        activity.append(
            ActivityView(
                incident_id=state.incident_id,
                timestamp=state.created_at,
                description="Incident created",
                reference=str(state.incident_id),
            )
        )
        if saved:
            result = saved.result
            workflow = WorkflowView(
                run_id=saved.run_id,
                current=result.current_step,
                next_step=result.next_step,
                terminal=result.terminal,
                claimed=source.claimed,
                reason=result.reason,
                updated_at=saved.updated_at,
            )
            active_workflows += int(not result.terminal)
            recovery |= source.claimed or result.next_step == WorkflowStep.RECOVER
            if source.claimed or result.waiting_for_human:
                category = "Workflow input / dispatch"
                if source.claimed:
                    category = "Workflow claim requires operator inspection"
                elif result.next_step == WorkflowStep.RECOVER:
                    category = "Execution reconciliation"
                elif result.next_step == WorkflowStep.GOVERN:
                    if saved.review_id is None:
                        category = "Incident Review"
                    elif saved.artifacts.response_plan is None:
                        category = "Response candidate input"
                    elif saved.promoted_id is None:
                        category = "Response Review / response promotion"
                    elif saved.approval_id is None:
                        category = "Tool Approval"
                actions.append(
                    HumanActionView(
                        incident_id=state.incident_id,
                        run_id=saved.run_id,
                        category=category,
                        reason=result.reason,
                    )
                )
            activity.append(
                ActivityView(
                    incident_id=state.incident_id,
                    timestamp=saved.updated_at,
                    description=(
                        f"Checkpoint: {result.current_step.value} → {result.next_step.value}"
                    ),
                    reference=str(saved.run_id),
                )
            )
            assessment = saved.artifacts.assessment
            if isinstance(assessment, FusionAssessmentResult):
                fusion = assessment.model_derived_context
                signal_ids.update(s.signal_id for s in fusion.signals)
                signal_options["Fusion"].append(
                    SignalView(
                        domain="Fusion",
                        state=fusion.agreement_state.value.upper(),
                        incident_id=state.incident_id,
                        run_id=saved.run_id,
                        reference=fusion.fusion_id,
                        timestamp=fusion.created_at,
                        provenance=(
                            f"Coverage: {fusion.coverage_state.value}",
                            *fusion.limitations,
                        ),
                    )
                )
                for contribution in fusion.contributions:
                    domain = (
                        "Authentication AI"
                        if contribution.model_kind == "authentication_anomaly"
                        else "Network AI"
                    )
                    timestamps = [
                        s.source_created_at
                        for s in fusion.signals
                        if s.signal_id in contribution.signal_ids
                    ]
                    signal_options[domain].append(
                        SignalView(
                            domain=domain,
                            state=contribution.decision,
                            incident_id=state.incident_id,
                            run_id=saved.run_id,
                            reference=contribution.contribution_id,
                            timestamp=max(timestamps) if timestamps else None,
                            provenance=(
                                contribution.model_kind,
                                contribution.model_reference,
                                contribution.score_semantics,
                            ),
                        )
                    )
        incidents.append(
            IncidentView(
                incident_id=state.incident_id,
                status=state.status.value,
                severity=state.severity.value,
                updated_at=state.updated_at,
                evidence_count=len(state.evidence),
                observation_count=len(state.observations),
                hypothesis_count=len(state.hypotheses),
                sources=tuple(sorted({e.source for e in state.evidence})),
                workflow=workflow,
            )
        )
    signals = []
    for domain, options in signal_options.items():
        options.sort(
            key=lambda s: (s.timestamp.isoformat() if s.timestamp else "", s.reference or "")
        )
        signals.append(options[-1] if options else SignalView(domain=domain))
    incidents.sort(key=lambda i: (i.updated_at, str(i.incident_id)), reverse=True)
    actions.sort(key=lambda a: (str(a.incident_id), a.category))
    activity.sort(key=lambda a: (a.timestamp, str(a.incident_id), a.description), reverse=True)
    return DashboardOverview(
        posture=(
            "RECOVERY REQUIRED"
            if recovery
            else "ACTION REQUIRED"
            if actions
            else "INVESTIGATING"
            if active_workflows
            else "UNKNOWN"
        ),
        active_incident_count=sum(i.status != IncidentStatus.CLOSED for i in incidents),
        active_workflow_count=active_workflows,
        human_action_count=len(actions),
        security_signal_count=len(signal_ids),
        incidents=tuple(incidents),
        human_actions=tuple(actions),
        signals=tuple(signals),
        recent_activity=tuple(activity[:20]),
    )
