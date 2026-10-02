import json
import sqlite3

import pytest
from pydantic import ValidationError

from soc_agent.feedback import DiagnosticLabel as Label
from soc_agent.feedback import Verdict
from soc_agent.improvement_dataset import EligibilityReason as Reason
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence.models import StoredDataError
from tests.integration.experience.test_storage import table_snapshot

from .conftest import build, submit


@pytest.mark.parametrize(
    "verdict,labels",
    [
        (Verdict.CORRECT, ()),
        (Verdict.INCORRECT, ()),
        *[(Verdict.INCORRECT, (label,)) for label in Label],
    ],
)
def test_eligible_meaning_refs_and_export(dataset_case, verdict, labels):
    c = dataset_case
    feedback = submit(c, verdict, labels, note="Annotation must not enter offline export")
    value = build(c)
    assert value.manifest.sample_count == 1 and value.manifest.excluded_count == 0
    (result,) = value.manifest.selection
    assert result.reason == Reason.ELIGIBLE
    (sample,) = c.datasets.list_samples(value.dataset_id)
    s = sample.content
    assert (s.verdict, s.labels, s.scope) == (verdict, labels, "overall")
    assert s.sources.experience.digest == content_digest(c.experience)
    assert s.sources.evaluation.digest == content_digest(c.evaluation)
    assert s.sources.feedback[0].digest == content_digest(feedback)
    assert s.sources.incident_id == c.incident_id
    assert s.objective.execution_outcome == c.evaluation.content.execution_outcome
    assert s.objective.orchestration_step_count == c.evaluation.content.orchestration_step_count
    assert s.objective.waiting_for_human and not s.objective.terminal
    assert s.objective.investigation_count is None and s.objective.tool_call_count is None
    assert s.objective.analysis_observed == c.evaluation.content.analysis_observed
    assert c.datasets.get_sample(sample.sample_id) == sample
    assert c.datasets.get_dataset(value.dataset_id) == value
    assert c.datasets.list_datasets() == (value,)
    assert build(c) == value
    exported = c.datasets.export_json(value.dataset_id)
    assert exported == c.datasets.export_json(value.dataset_id)
    parsed = json.loads(exported)
    assert parsed["manifest"]["samples"][0]["identity"] == sample.sample_id
    assert "Annotation must not enter offline export" not in exported
    keys = set()

    def fields(value):
        if isinstance(value, dict):
            keys.update(value)
            for child in value.values():
                fields(child)
        elif isinstance(value, list):
            for child in value:
                fields(child)

    fields(parsed)
    assert (
        not {
            "note",
            "credential",
            "token",
            "session_id",
            "confirmation_id",
            "prompt",
            "accuracy",
            "quality_score",
            "target",
            "good",
            "bad",
            "created_at",
        }
        & keys
    )
    with pytest.raises(ValidationError):
        sample.content.verdict = Verdict.INCONCLUSIVE
    with pytest.raises(ValidationError):
        value.manifest.sample_count = 99


@pytest.mark.parametrize(
    "judgments,reason",
    [
        ([], Reason.NO_FEEDBACK),
        ([(Verdict.INCONCLUSIVE, ())], Reason.INCONCLUSIVE),
        ([(Verdict.CORRECT, ()), (Verdict.INCONCLUSIVE, ())], Reason.INCONCLUSIVE),
        ([(Verdict.CORRECT, ()), (Verdict.INCORRECT, ())], Reason.ANALYST_DISAGREEMENT),
        (
            [
                (Verdict.INCORRECT, (Label.UNNECESSARY_INVESTIGATION,)),
                (Verdict.INCORRECT, (Label.MISSED_INVESTIGATION,)),
            ],
            Reason.ANALYST_DISAGREEMENT,
        ),
        (
            [(Verdict.CORRECT, ()), (Verdict.CORRECT, ()), (Verdict.INCORRECT, ())],
            Reason.ANALYST_DISAGREEMENT,
        ),
        (
            [
                (Verdict.INCORRECT, (Label.FALSE_POSITIVE,)),
                (Verdict.INCORRECT, (Label.FALSE_NEGATIVE,)),
            ],
            Reason.ANALYST_DISAGREEMENT,
        ),
    ],
)
def test_exclusions_do_not_infer_or_vote(dataset_case, judgments, reason):
    c = dataset_case
    refs = [
        submit(c, verdict, labels, subject=f"analyst-{i}")
        for i, (verdict, labels) in enumerate(judgments)
    ]
    value = build(c)
    (result,) = value.manifest.selection
    assert result.reason == reason
    assert value.manifest.sample_count == 0 and value.manifest.excluded_count == 1
    assert c.datasets.list_samples(value.dataset_id) == ()
    assert {r.identity for r in result.sources.feedback} == {f.feedback_id for f in refs}
    assert result.sample is None


def test_compatible_feedback_all_preserved(dataset_case):
    c = dataset_case
    a = submit(c, Verdict.INCORRECT, (Label.FALSE_POSITIVE,))
    b = submit(c, Verdict.INCORRECT, (Label.UNNECESSARY_INVESTIGATION,), subject="bob")
    dataset = build(c)
    (sample,) = c.datasets.list_samples(dataset.dataset_id)
    assert sample.content.labels == (Label.FALSE_POSITIVE, Label.UNNECESSARY_INVESTIGATION)
    assert tuple(r.identity for r in sample.content.sources.feedback) == tuple(
        sorted((a.feedback_id, b.feedback_id))
    )


def test_new_feedback_explicit_rebuild_snapshot(dataset_case):
    c = dataset_case
    submit(c)
    old = build(c)
    old_export = c.datasets.export_json(old.dataset_id)
    old_members = c.datasets.list_samples(old.dataset_id)
    submit(c, Verdict.INCORRECT, subject="bob")
    assert c.datasets.get_dataset(old.dataset_id) == old
    assert c.datasets.list_samples(old.dataset_id) == old_members
    assert c.datasets.export_json(old.dataset_id) == old_export
    new = build(c)
    assert new.dataset_version != old.dataset_version
    assert new.manifest.selection[0].reason == Reason.ANALYST_DISAGREEMENT
    assert new.manifest.sample_count == 0
    assert len(c.datasets.list_datasets()) == 2
    assert build(c) == new


def test_excluded_snapshot_also_remains_fixed(dataset_case):
    c = dataset_case
    old = build(c)
    submit(c)
    new = build(c)
    assert new.dataset_version != old.dataset_version
    assert c.datasets.get_dataset(old.dataset_id).manifest.selection[0].reason == Reason.NO_FEEDBACK
    assert new.manifest.sample_count == 1


@pytest.mark.parametrize("table", ["experiences", "evaluations", "analyst_feedback"])
def test_corrupt_source_aborts_whole_build(dataset_case, table):
    c = dataset_case
    submit(c)
    with c.store.database.transaction() as connection:
        connection.execute(f"UPDATE {table} SET digest=?", ("0" * 64,))
    with pytest.raises(StoredDataError):
        build(c)
    assert c.datasets.list_datasets() == ()
    with c.store.database.transaction(write=False) as connection:
        assert connection.execute("SELECT count(*) FROM improvement_samples").fetchone()[0] == 0


def test_forged_id_and_evaluation_index_mismatch(dataset_case):
    c = dataset_case
    submit(c)
    with pytest.raises(StoredDataError):
        c.builder.build((c.evaluation.evaluation_id, "0" * 64))
    assert c.datasets.list_datasets() == ()
    with sqlite3.connect(c.store.database.path) as connection:
        connection.execute("UPDATE experiences SET run_id=?", ("0" * 64,))
    with pytest.raises(StoredDataError):
        build(c)


def test_no_authority_or_runtime_calls(dataset_case, monkeypatch):
    c = dataset_case
    submit(c)
    before = table_snapshot(c.store.database)
    state_before = c.store.load(c.incident_id)

    def forbidden(*args, **kwargs):
        raise AssertionError("Builder invoked a forbidden operation")

    monkeypatch.setattr(c.llm, "generate_structured", forbidden)
    monkeypatch.setattr(c.runtime, "advance", forbidden)
    monkeypatch.setattr(c.executor, "execute", forbidden)
    monkeypatch.setattr(c.feedback, "submit", forbidden)
    monkeypatch.setattr(c.evaluator, "evaluate", forbidden)
    value = build(c)
    c.datasets.export_json(value.dataset_id)
    after = table_snapshot(c.store.database)
    new = {"improvement_samples", "improvement_datasets", "dataset_sample_membership"}
    assert all(after[name] == rows for name, rows in before.items() if name not in new)
    assert c.mocks["inspect_logs"].call_count == 0
    assert c.store.load(c.incident_id) == state_before


@pytest.mark.asyncio
async def test_multi_evaluation_order_and_pinned_history(dataset_case):
    from soc_agent.review.models import ReviewOutcome
    from tests.integration.experience.test_capture import capture_service
    from tests.unit.investigation_runtime.conftest import review_for

    c = dataset_case
    submit(c)
    first = c.evaluation
    await c.runtime.advance(c.incident_id, review=review_for(c, ReviewOutcome.REJECTED))
    await c.runtime.advance(c.incident_id)
    c.experience = capture_service(c).capture(c.incident_id)
    c.evaluation = c.evaluator.evaluate(c.experience.experience_id)
    c.request = c.request.model_copy(
        update={
            "experience_id": c.experience.experience_id,
            "experience_digest": content_digest(c.experience),
            "evaluation_id": c.evaluation.evaluation_id,
            "evaluation_digest": content_digest(c.evaluation),
        }
    )
    submit(c, Verdict.INCORRECT, (Label.FALSE_NEGATIVE,))
    identities = (first.evaluation_id, c.evaluation.evaluation_id)
    before = table_snapshot(c.store.database)
    value = c.builder.build(reversed(identities))
    assert c.builder.build(identities + identities) == value
    assert tuple(s.sources.evaluation.identity for s in value.manifest.selection) == tuple(
        sorted(identities)
    )
    samples = c.datasets.list_samples(value.dataset_id)
    assert tuple(s.sample_id for s in samples) == tuple(sorted(s.sample_id for s in samples))
    assert len(samples) == 2
    after = table_snapshot(c.store.database)
    assert all(
        after[name] == rows
        for name, rows in before.items()
        if name not in {"improvement_samples", "improvement_datasets", "dataset_sample_membership"}
    )
    stats = c.datasets.statistics(value.dataset_id)
    assert stats.correct_count == stats.incorrect_count == stats.false_negative_count == 1
    assert stats.sample_count == 2
