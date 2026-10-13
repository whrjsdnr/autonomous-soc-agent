"""Explicit synthetic seed/read composition. No credential or human intent is fabricated."""

from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from secrets import token_urlsafe
from typing import Literal
from uuid import UUID

from pydantic import Field

from soc_agent.api import SOCApplication
from soc_agent.api.models import StepRequest
from soc_agent.api.service import NotFound
from soc_agent.application import open_application_store
from soc_agent.demo.composition import compose_demo
from soc_agent.demo.scenarios import scenario_event
from soc_agent.evaluation import EvaluationStore, ExperienceEvaluator
from soc_agent.experience import ExperienceCaptureService, ExperienceStore
from soc_agent.feedback import FeedbackStore
from soc_agent.improvement_candidates import (
    ImprovementCandidateService,
    ImprovementCandidateStore,
)
from soc_agent.improvement_dataset import (
    ImprovementDatasetBuilder,
    ImprovementDatasetStore,
)
from soc_agent.review.authentication import AuthenticatedPrincipal
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.models import Frozen
from soc_agent.state.evidence import utc_now

MARKER = "soc-synthetic-demo.json"
DATABASE = "demo.sqlite"


class DemoManifest(Frozen):
    label: str = "DEMO / SYNTHETIC — scripted analysis, no human approval"
    version: str = "soc-command-center-demo:v1"
    incidents: tuple[UUID, ...] = Field(default=(), max_length=1000)
    mode: Literal["snapshot", "live-local"] = "snapshot"


def manifest(directory: Path) -> DemoManifest:
    value = DemoManifest.model_validate_json((directory / MARKER).read_text(encoding="utf-8"))
    if value.version != "soc-command-center-demo:v1" or value.label != DemoManifest().label:
        raise ValueError("Explicit synthetic demo directory required")
    if value.mode == "snapshot" and len(value.incidents) > 2:
        raise ValueError("Snapshot demo is limited to its two scenario incidents")
    return value


def prepare(directory: Path) -> None:
    if not directory.is_absolute() or directory.is_symlink():
        raise ValueError("Absolute non-symlink demo directory required")
    if not directory.exists():
        directory.mkdir(mode=0o700, parents=False)
    if (directory / MARKER).exists():
        manifest(directory)
        return
    if any(directory.iterdir()):
        raise ValueError("Use a fresh empty private demo directory; existing data is never reset")
    (directory / MARKER).write_text(DemoManifest().model_dump_json(), encoding="utf-8")


def open_demo(directory: Path, **composition):
    manifest(directory)
    store = open_application_store(directory / DATABASE, create=not (directory / DATABASE).exists())
    return compose_demo(store, **composition)


async def seed(directory: Path, scenario: str = "all") -> DemoManifest:
    """Idempotent reports and bounded stepping; no execute/review/approval is ever submitted."""
    if scenario not in ("a", "b", "c", "all"):
        raise ValueError("Unknown scenario")
    prepare(directory)
    if manifest(directory).mode != "snapshot":
        raise ValueError("Seed is snapshot-only; use the live runtime for this directory")
    service = open_demo(directory)
    names = ("a", "b") if scenario == "all" else ("b",) if scenario == "c" else (scenario,)
    identities = set(manifest(directory).incidents)
    for name in names:
        result = service.ingest(scenario_event(name))
        identity = result.incident_id
        identities.add(identity)
        try:
            workflow = service.workflow(identity)
        except NotFound:
            workflow = service.start(identity)
        for _ in range(16):
            if workflow.waiting_for_human or workflow.terminal:
                break
            workflow = await service.step(
                identity,
                StepRequest(
                    run_id=workflow.workflow_id, expected_revision=workflow.checkpoint_revision
                ),
            )
        else:
            raise ValueError("Bounded demo step limit reached; no retry or forced transition")
    if scenario in ("c", "all"):
        experiences = ExperienceStore(service.store)
        evaluations = EvaluationStore(experiences)
        ids = []
        for identity in sorted(identities):
            captured = ExperienceCaptureService(experiences).capture(identity)
            ids.append(
                ExperienceEvaluator(evaluations).evaluate(captured.experience_id).evaluation_id
            )
        datasets = ImprovementDatasetStore(FeedbackStore(evaluations))
        dataset = ImprovementDatasetBuilder(datasets).build(ids)
        # Existing selector excludes records with no human feedback. No backfill or labels.
        ImprovementCandidateService(ImprovementCandidateStore(datasets)).propose(dataset.dataset_id)
    value = DemoManifest(incidents=tuple(sorted(identities)))
    (directory / MARKER).write_text(value.model_dump_json(), encoding="utf-8")
    return value


class DemoObserver:
    """Process-local observation identity, empty roles, no human confirmation capability."""

    def __init__(self):
        self._credential = token_urlsafe(32)
        self._now = utc_now()

    def authenticate(self, credential):
        if credential != self._credential:
            raise HumanAuthorizationDenied("Unknown demo observer")
        return AuthenticatedPrincipal(
            subject_id="synthetic-demo-observer",
            provider_id="local-synthetic-observer",
            session_id="local-demo-session",
            subject_kind="human",
            authentication_context=("explicit-local-synthetic-observer",),
            authenticated_at=self._now,
            expires_at=self._now + timedelta(hours=8),
            scopes=(),
        )

    def confirm(self, *args):
        raise HumanAuthorizationDenied("Local observer cannot confirm human actions")


class DemoAccess:
    def __init__(self, incidents: tuple[UUID, ...] | Callable[[], tuple[UUID, ...]]):
        self._incidents = incidents

    def require_access(self, principal, incident_id, operation):
        if principal.provider_id != "local-synthetic-observer" or not operation.startswith("GET:"):
            raise HumanAuthorizationDenied("Demo observer access denied")
        incidents = self._incidents() if callable(self._incidents) else self._incidents
        if incident_id is not None and incident_id not in incidents:
            raise HumanAuthorizationDenied("Foreign incident access denied")


def observation_app(directory: Path):
    value = manifest(directory)
    service = open_demo(directory)

    def visible_incidents():
        current = manifest(directory)
        if current.mode != value.mode:
            raise ValueError("Local observation mode changed; restart observer")
        for identity in current.incidents:
            event = service.ingestion.load(identity).event
            if not event.synthetic or event.source != "synthetic-demo":
                raise ValueError("Non-demo incident cannot be served by local forwarding launcher")
        return current.incidents

    visible_incidents()
    observer = DemoObserver()
    observer.live_local = value.mode == "live-local"
    app = SOCApplication(
        lambda: service,
        provider=observer,
        provider_id="local-synthetic-observer",
        access=DemoAccess(visible_incidents),
    )
    return app, observer
