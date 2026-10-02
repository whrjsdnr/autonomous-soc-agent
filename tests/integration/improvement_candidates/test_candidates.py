import multiprocessing
import sqlite3

import pytest

from soc_agent.evaluation import EvaluationStore
from soc_agent.experience import ExperienceStore
from soc_agent.feedback import FeedbackStore, Verdict
from soc_agent.improvement_candidates import (
    AnalysisConfig,
    CandidateType,
    ImprovementCandidateService,
    ImprovementCandidateStore,
    PatternType,
    migrate_candidates,
    schema,
)
from soc_agent.improvement_dataset import ImprovementDatasetStore
from soc_agent.review.identity import content_digest
from soc_agent.review.persistence import SQLiteGovernanceStore, ledger
from soc_agent.review.persistence.models import (
    StorageError,
    StoredDataError,
    UnsupportedSchemaError,
)
from tests.integration.experience.test_storage import table_snapshot
from tests.integration.improvement_dataset.conftest import submit

TABLES = {"failure_patterns", "improvement_candidates"}


def reopen(path):
    datasets = ImprovementDatasetStore(
        FeedbackStore(EvaluationStore(ExperienceStore(SQLiteGovernanceStore(path)))),
    )
    return ImprovementCandidateStore(datasets)


def test_end_to_end_grounding_query_and_statistics(candidate_case):
    c = candidate_case
    result = c.improvement.propose(
        c.dataset.dataset_id, expected_manifest_digest=c.dataset.manifest_digest
    )
    assert {p.content.pattern_type for p in result.patterns} == {
        PatternType.FALSE_POSITIVE,
        PatternType.INCORRECT,
    }
    sample_ids = tuple(r.identity for r in c.dataset.manifest.samples)
    for pattern in result.patterns:
        assert pattern.supporting_sample_ids == sample_ids
        assert pattern.content.occurrence_count == 2
        assert {r.identity for r in pattern.content.supporting_feedback_refs} == {
            f.feedback_id for f in c.feedback_refs
        }
        assert c.candidates.get_pattern(pattern.pattern_id) == pattern
    for candidate in result.candidates:
        assert c.candidates.get_candidate(candidate.candidate_id) == candidate
        assert candidate.content.candidate_type == CandidateType.PROMPT
        assert candidate.content.dataset.manifest_digest == c.dataset.manifest_digest
    assert c.candidates.list_patterns(c.dataset.dataset_id) == result.patterns
    assert c.candidates.list_candidates(c.dataset.dataset_id) == result.candidates
    assert c.improvement.propose(c.dataset.dataset_id) == result
    assert (
        c.improvement.generate(c.dataset.dataset_id, [p.pattern_id for p in result.patterns] * 2)
        == result.candidates
    )
    counts = c.candidates.statistics(c.dataset.dataset_id)
    assert counts.pattern_count == counts.candidate_count == 2
    assert sum(item.count for item in counts.candidate_type_counts) == 2
    assert dict(counts.pattern_support_counts) == {p.pattern_id: 2 for p in result.patterns}
    assert tuple(c.candidate_id for c in result.candidates) == tuple(
        sorted(c.candidate_id for c in result.candidates)
    )
    assert not {"score", "ranking", "success_rate", "probability"}.intersection(counts.model_dump())
    strict = ImprovementCandidateService(
        c.candidates, config=AnalysisConfig(minimum_pattern_support=3)
    )
    assert strict.propose(c.dataset.dataset_id).patterns == ()
    with pytest.raises(StoredDataError):
        c.improvement.propose(c.dataset.dataset_id, expected_manifest_digest="0" * 64)


def process_propose(path, dataset_id, barrier, queue):
    service = ImprovementCandidateService(reopen(path))
    barrier.wait(timeout=20)
    queue.put(service.propose(dataset_id).model_dump_json())


def test_process_race_and_restart(candidate_case):
    c = candidate_case
    context = multiprocessing.get_context("spawn")
    barrier, queue = context.Barrier(2), context.Queue()
    processes = [
        context.Process(
            target=process_propose,
            args=(
                c.store.database.path,
                c.dataset.dataset_id,
                barrier,
                queue,
            ),
        )
        for _ in range(2)
    ]
    for process in processes:
        process.start()
    try:
        results = [queue.get(timeout=60) for _ in processes]
    finally:
        for process in processes:
            process.join(timeout=20)
            if process.is_alive():
                process.terminate()
                process.join()
    assert all(p.exitcode == 0 for p in processes)
    assert results[0] == results[1]
    store = reopen(c.store.database.path)
    result = ImprovementCandidateService(store).propose(c.dataset.dataset_id)
    assert result.model_dump_json() == results[0]
    assert len(store.list_candidates(c.dataset.dataset_id)) == 2


def test_snapshots_and_explicit_reanalysis(candidate_case):
    c = candidate_case
    old = c.improvement.propose(c.dataset.dataset_id)
    before = table_snapshot(c.store.database)
    submit(c, Verdict.CORRECT, subject="bob")
    new_dataset = c.builder.build(
        s.sources.evaluation.identity for s in c.dataset.manifest.selection
    )
    assert new_dataset.dataset_id != c.dataset.dataset_id
    assert c.candidates.list_candidates(new_dataset.dataset_id) == ()
    assert c.candidates.list_candidates(c.dataset.dataset_id) == old.candidates
    assert c.improvement.propose(c.dataset.dataset_id) == old
    newer = c.improvement.propose(new_dataset.dataset_id)
    assert newer.patterns == newer.candidates == ()
    after = table_snapshot(c.store.database)
    assert all(after[name] == before[name] for name in TABLES)


@pytest.mark.parametrize("kind", ["dataset_digest", "membership", "sample_source", "manifest"])
def test_corrupt_dataset_rejected_before_persistence(candidate_case, kind):
    c = candidate_case
    with c.store.database.transaction() as connection:
        if kind == "dataset_digest":
            connection.execute("UPDATE improvement_datasets SET digest=?", ("0" * 64,))
        elif kind == "membership":
            connection.execute("DELETE FROM dataset_sample_membership")
        elif kind == "sample_source":
            connection.execute("UPDATE evaluations SET digest=?", ("0" * 64,))
        else:
            forged = c.dataset.model_copy(
                update={
                    "manifest": c.dataset.manifest.model_copy(
                        update={"source_snapshot_id": "0" * 64}
                    )
                }
            )
            connection.execute(
                "UPDATE improvement_datasets SET payload=?,digest=?",
                (
                    ledger.serialize(forged),
                    content_digest(forged),
                ),
            )
    with pytest.raises(StoredDataError):
        c.improvement.propose(c.dataset.dataset_id)
    with c.store.database.transaction(write=False) as connection:
        assert connection.execute("SELECT count(*) FROM failure_patterns").fetchone()[0] == 0
        assert connection.execute("SELECT count(*) FROM improvement_candidates").fetchone()[0] == 0


def test_cross_dataset_pattern_rejected(candidate_case):
    c = candidate_case
    patterns = c.improvement.analyze(c.dataset.dataset_id)
    other = c.builder.build(())
    with pytest.raises(StoredDataError):
        c.improvement.generate(other.dataset_id, (patterns[0].pattern_id,))
    assert c.candidates.list_candidates(c.dataset.dataset_id) == ()


def test_checksum_correct_pattern_facts_and_candidate_support_forgery(candidate_case):
    c = candidate_case
    result = c.improvement.propose(c.dataset.dataset_id)
    candidate = result.candidates[0]
    forged_content = candidate.content.model_copy(
        update={
            "supporting_sample_refs": candidate.content.supporting_sample_refs[:1],
        }
    )
    identity = content_digest(forged_content)
    forged = candidate.model_copy(
        update={
            "candidate_id": identity,
            "candidate_version": identity,
            "content": forged_content,
        }
    )
    with c.store.database.transaction() as connection:
        connection.execute(
            "UPDATE improvement_candidates SET candidate_id=?,payload=?,digest=? "
            "WHERE candidate_id=?",
            (identity, ledger.serialize(forged), content_digest(forged), candidate.candidate_id),
        )
    with pytest.raises(StoredDataError):
        c.candidates.get_candidate(identity)
    pattern = result.patterns[0]
    facts = tuple(
        f.model_copy(update={"recovery_observed": True}) for f in pattern.content.observed_facts
    )
    content = pattern.content.model_copy(update={"observed_facts": facts})
    identity = content_digest(content)
    forged = pattern.model_copy(update={"pattern_id": identity, "content": content})
    with c.store.database.transaction() as connection:
        connection.execute(
            "INSERT INTO failure_patterns VALUES (?,?,?,?)",
            (
                identity,
                c.dataset.dataset_id,
                ledger.serialize(forged),
                content_digest(forged),
            ),
        )
    with pytest.raises(StoredDataError):
        c.candidates.get_pattern(identity)


def test_no_runtime_governance_or_configuration_authority(candidate_case, monkeypatch):
    from soc_agent.assessment import prompts as assessment_prompts
    from soc_agent.planning import prompts as planning_prompts
    from soc_agent.policy import PolicyEngine

    c = candidate_case
    before = table_snapshot(c.store.database)
    state_before = c.store.load(c.incident_id)
    prompts = (assessment_prompts.SYSTEM_PROMPT, planning_prompts.SYSTEM_PROMPT)
    calls = {name: mock.call_count for name, mock in c.mocks.items()}

    def forbidden(*args, **kwargs):
        raise AssertionError("Offline improvement invoked an authority-bearing operation")

    for obj, attribute in (
        (c.runtime, "advance"),
        (c.executor, "execute"),
        (c.feedback, "submit"),
        (c.evaluator, "evaluate"),
        (c.llm, "generate_structured"),
        (PolicyEngine, "evaluate"),
    ):
        monkeypatch.setattr(obj, attribute, forbidden)
    c.improvement.propose(c.dataset.dataset_id)
    after = table_snapshot(c.store.database)
    assert all(after[name] == rows for name, rows in before.items() if name not in TABLES)
    assert c.store.load(c.incident_id) == state_before
    assert prompts == (assessment_prompts.SYSTEM_PROMPT, planning_prompts.SYSTEM_PROMPT)
    assert calls == {name: mock.call_count for name, mock in c.mocks.items()}


def test_v8_v9_preservation_rollback_future(dataset_case, monkeypatch):
    c = dataset_case
    submit(c)
    c.builder.build((c.evaluation.evaluation_id,))
    before = table_snapshot(c.store.database)
    assert all(
        before[name]
        for name in (
            "experiences",
            "evaluations",
            "analyst_feedback",
            "improvement_datasets",
            "improvement_samples",
            "human_confirmations",
            "incidents",
        )
    )
    with monkeypatch.context() as patch:
        patch.setattr(schema, "STATEMENTS", schema.STATEMENTS + ("INVALID SQL",))
        with pytest.raises(StorageError):
            migrate_candidates(c.store.database)
    assert table_snapshot(c.store.database) == before
    with c.store.database.transaction(write=False) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 8
    migrate_candidates(c.store.database)
    migrate_candidates(c.store.database)
    after = table_snapshot(c.store.database)
    assert {name: after[name] for name in before} == before
    assert (
        reopen(c.store.database.path).list_patterns(c.datasets.list_datasets()[0].dataset_id) == ()
    )
    with sqlite3.connect(c.store.database.path) as connection:
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(UnsupportedSchemaError):
        reopen(c.store.database.path)


def test_fresh_database_chain_and_empty_dataset(tmp_path):
    from soc_agent.evaluation import migrate_evaluations
    from soc_agent.execution.durable.schema import migrate
    from soc_agent.experience import migrate_experiences
    from soc_agent.feedback import migrate_feedback
    from soc_agent.improvement_dataset import ImprovementDatasetBuilder, migrate_datasets
    from soc_agent.investigation.runtime.persistence import migrate_checkpoints
    from soc_agent.review.persistence.confirmations import migrate_confirmations

    governance = SQLiteGovernanceStore.create(tmp_path / "fresh.sqlite")
    with pytest.raises(UnsupportedSchemaError):
        migrate_candidates(governance.database)
    for migration in (
        migrate,
        migrate_confirmations,
        migrate_checkpoints,
        migrate_experiences,
        migrate_evaluations,
        migrate_feedback,
        migrate_datasets,
        migrate_candidates,
    ):
        migration(governance.database)
    store = reopen(governance.database.path)
    dataset = ImprovementDatasetBuilder(store.datasets).build(())
    result = ImprovementCandidateService(store).propose(dataset.dataset_id)
    assert result.patterns == result.candidates == ()
    assert store.statistics(dataset.dataset_id).candidate_count == 0
    for method in (store.get_pattern, store.get_candidate):
        with pytest.raises(StoredDataError):
            method("0" * 64)


def test_checksum_correct_candidate_pattern_mismatch(candidate_case):
    c = candidate_case
    result = c.improvement.propose(c.dataset.dataset_id)
    candidate = result.candidates[0]
    (other,) = (
        p
        for p in result.patterns
        if p.pattern_id != candidate.content.failure_pattern_refs[0].identity
    )
    from soc_agent.improvement_dataset.models import ArtifactReference

    content = candidate.content.model_copy(
        update={
            "failure_pattern_refs": (
                ArtifactReference(
                    identity=other.pattern_id,
                    digest=content_digest(other.content),
                ),
            ),
        }
    )
    identity = content_digest(content)
    forged = candidate.model_copy(
        update={
            "candidate_id": identity,
            "candidate_version": identity,
            "content": content,
        }
    )
    with c.store.database.transaction() as connection:
        connection.execute(
            "UPDATE improvement_candidates SET candidate_id=?,pattern_id=?,payload=?,digest=? "
            "WHERE candidate_id=?",
            (
                identity,
                other.pattern_id,
                ledger.serialize(forged),
                content_digest(forged),
                candidate.candidate_id,
            ),
        )
    with pytest.raises(StoredDataError):
        c.candidates.get_candidate(identity)
