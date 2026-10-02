"""Deterministic eligibility; never infers truth or resolves analyst disagreement."""

from sqlite3 import Connection

from soc_agent.evaluation.models import EvaluationRecord
from soc_agent.evaluation.sources import validate_sources
from soc_agent.feedback.models import AnalystFeedback, DiagnosticLabel, Verdict
from soc_agent.feedback.store import FeedbackStore
from soc_agent.improvement_dataset.models import (
    ArtifactReference,
    EligibilityReason,
    EligibilityResult,
    ImprovementSample,
    ObjectiveContext,
    SampleContent,
    SourceSnapshot,
)
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError


def load_sources(
    connection: Connection,
    store: FeedbackStore,
    evaluation_id: str,
    *,
    pinned: SourceSnapshot | None = None,
) -> tuple[EvaluationRecord, tuple[AnalystFeedback, ...], SourceSnapshot]:
    row = connection.execute(
        "SELECT * FROM evaluations WHERE evaluation_id=?", (evaluation_id,)
    ).fetchone()
    if row is None:
        raise StoredDataError("Unknown dataset evaluation")
    evaluation = store.evaluations._decode(connection, row)
    c = evaluation.content
    row = connection.execute(
        "SELECT * FROM experiences WHERE experience_id=?", (c.experience_id,)
    ).fetchone()
    experience = store.evaluations.experiences._decode(row)
    validate_sources(connection, store.evaluations.experiences, experience)
    if pinned is None:
        rows = connection.execute(
            "SELECT * FROM analyst_feedback WHERE evaluation_id=? OR experience_id=? "
            "OR incident_id=? ORDER BY feedback_id",
            (evaluation_id, c.experience_id, str(c.incident_id)),
        ).fetchall()
    else:
        rows = []
        for ref in pinned.feedback:
            row = connection.execute(
                "SELECT * FROM analyst_feedback WHERE feedback_id=?", (ref.identity,)
            ).fetchone()
            if row is None:
                raise StoredDataError("Missing pinned feedback")
            rows.append(row)
    decoded = tuple(store._decode(connection, row) for row in rows)
    feedback = tuple(
        f for f in decoded if pinned is not None or f.request.evaluation_id == evaluation_id
    )
    for f in feedback:
        r = f.request
        if (
            r.evaluation_id,
            r.incident_id,
            r.experience_id,
            r.experience_digest,
            r.evaluation_digest,
        ) != (
            evaluation_id,
            c.incident_id,
            c.experience_id,
            c.experience_digest,
            content_digest(evaluation),
        ):
            raise StoredDataError("Foreign feedback in dataset selection")
    source = SourceSnapshot(
        incident_id=c.incident_id,
        experience=ArtifactReference(identity=c.experience_id, digest=c.experience_digest),
        evaluation=ArtifactReference(identity=evaluation_id, digest=content_digest(evaluation)),
        feedback=tuple(
            ArtifactReference(identity=f.feedback_id, digest=content_digest(f)) for f in feedback
        ),
    )
    if pinned is not None and source != pinned:
        raise StoredDataError("Dataset source snapshot changed")
    return evaluation, feedback, source


def select(
    evaluation: EvaluationRecord,
    feedback: tuple[AnalystFeedback, ...],
    source: SourceSnapshot,
) -> tuple[EligibilityResult, ImprovementSample | None]:
    labels = tuple(sorted({label for f in feedback for label in f.request.labels}))
    verdicts = {f.request.verdict for f in feedback}
    conclusive = verdicts - {Verdict.INCONCLUSIVE}
    if not feedback:
        reason = EligibilityReason.NO_FEEDBACK
    elif len(conclusive) > 1 or any(
        pair <= set(labels)
        for pair in (
            {DiagnosticLabel.FALSE_POSITIVE, DiagnosticLabel.FALSE_NEGATIVE},
            {DiagnosticLabel.UNNECESSARY_INVESTIGATION, DiagnosticLabel.MISSED_INVESTIGATION},
        )
    ):
        reason = EligibilityReason.ANALYST_DISAGREEMENT
    elif Verdict.INCONCLUSIVE in verdicts:
        reason = EligibilityReason.INCONCLUSIVE
    elif any(f.request.scope != "overall" for f in feedback):
        reason = EligibilityReason.UNSUPPORTED_SCOPE
    else:
        reason = EligibilityReason.ELIGIBLE
    sample = None
    if reason == EligibilityReason.ELIGIBLE:
        # Singleton verdict and label union are preserved human inputs, not inferred consensus.
        (verdict,) = verdicts
        content = SampleContent(
            sources=source,
            verdict=verdict,
            labels=labels,
            objective=ObjectiveContext(
                **{
                    field: getattr(evaluation.content, field)
                    for field in ObjectiveContext.model_fields
                }
            ),
        )
        sample = ImprovementSample(sample_id=content_digest(content), content=content)
    result = EligibilityResult(
        sources=source,
        reason=reason,
        sample=ArtifactReference(identity=sample.sample_id, digest=content_digest(sample))
        if sample
        else None,
    )
    return result, sample
