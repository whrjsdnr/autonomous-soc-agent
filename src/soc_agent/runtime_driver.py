"""Bounded scheduling of the existing durable runtime, without execution authority."""

from collections.abc import Callable
from uuid import UUID

from soc_agent.api.models import StepRequest, WorkflowView
from soc_agent.api.service import ApplicationService, NotFound
from soc_agent.evaluation import EvaluationStore, ExperienceEvaluator
from soc_agent.experience import ExperienceCaptureService, ExperienceStore


async def advance_until_stopped(
    service: ApplicationService, identity: UUID, *, notify: Callable[[str], None] = print
) -> WorkflowView:
    try:
        workflow = service.workflow(identity)
    except NotFound:
        workflow = service.start(identity)
    for _ in range(32):
        notify(
            f"Incident {identity} · checkpoint {workflow.checkpoint_revision}"
            f" · {workflow.current_step}"
        )
        if workflow.waiting_for_human or workflow.terminal or workflow.failure is not None:
            break
        workflow = await service.step(
            identity,
            StepRequest(
                run_id=workflow.workflow_id, expected_revision=workflow.checkpoint_revision
            ),
        )
    else:
        raise ValueError("Runtime scheduling limit reached; no forced transition or retry")
    if workflow.waiting_for_human or workflow.terminal:
        experiences = ExperienceStore(service.store)
        captured = ExperienceCaptureService(experiences).capture(identity)
        ExperienceEvaluator(EvaluationStore(experiences)).evaluate(captured.experience_id)
    notify(
        "Waiting for human"
        if workflow.waiting_for_human
        else "Workflow stopped; inspect durable checkpoint"
    )
    return workflow
