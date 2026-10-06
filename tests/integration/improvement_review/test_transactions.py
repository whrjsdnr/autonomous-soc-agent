import multiprocessing
from types import SimpleNamespace

import pytest
from tests.integration.experience.test_storage import table_snapshot
from tests.integration.improvement_review.test_review import issue, submission
from tests.integration.offline_comparison.test_storage import reopen

from soc_agent.improvement_review import (
    ImprovementReviewService,
    ImprovementReviewStore,
    ReviewDecision,
    ReviewSubmission,
    migrate_improvement_review,
    schema,
)
from soc_agent.review.authorization import RBACPermissionVerifier
from soc_agent.review.errors import HumanAuthorizationDenied
from soc_agent.review.persistence.models import StorageError, UnsupportedSchemaError


def worker(path, value, boundary, token, ready, start, output):
    try:
        store = ImprovementReviewStore(reopen(path))
        # Full graph validation holds the write transaction longer than the
        # default five-second busy timeout on a loaded host. Use the existing
        # bounded configuration; lock failures are NOT counted as human denials.
        store.database.timeout = 60.0
        service = ImprovementReviewService(
            store,
            provider=boundary.provider,
            provider_id="test-identity",
            permissions=RBACPermissionVerifier(roles=boundary.roles),
        )
        ready.put(True)
        if not start.wait(30):
            raise RuntimeError("Race start timed out")
        record = service.submit(ReviewSubmission.model_validate_json(value), credential=token)
        output.put(("committed", record.review_record_id))
    except HumanAuthorizationDenied:
        output.put(("denied", None))
    except Exception as error:
        output.put(("error", repr(error)))


@pytest.mark.parametrize("same_confirmation", [False, True])
def test_independent_process_terminal_decision_and_replay(review_case, same_confirmation):
    c = review_case
    left = submission(c, ReviewDecision.DEFER)
    right = left if same_confirmation else submission(c, ReviewDecision.REJECT)
    left_token = issue(c, left)
    right_token = left_token if same_confirmation else issue(c, right)
    ctx = multiprocessing.get_context("spawn")
    ready, output, start = ctx.Queue(), ctx.Queue(), ctx.Event()
    processes = [
        ctx.Process(
            target=worker,
            args=(
                str(c.store.database.path),
                value.model_dump_json(),
                SimpleNamespace(provider=c.boundary.provider, roles=c.boundary.roles),
                token,
                ready,
                start,
                output,
            ),
        )
        for value, token in ((left, left_token), (right, right_token))
    ]
    # Boundary has an RLock via its unused authority; only provider/roles cross processes.
    for p in processes:
        p.start()
    try:
        assert ready.get(timeout=45) and ready.get(timeout=45)
        start.set()
        outcomes = [output.get(timeout=90), output.get(timeout=90)]
        assert all(o[0] in {"committed", "denied"} for o in outcomes), outcomes
        # Exact safe retries may both return the SAME committed record.
        ids = {o[1] for o in outcomes if o[0] == "committed"}
        assert len(ids) == 1
        assert len(c.store.list_review_records(c.source.candidate.candidate_id)) == 1
    finally:
        for p in processes:
            p.join(timeout=5)
            if p.is_alive():
                p.terminate()
                p.join()


def test_migration_preservation_rollback_and_future_rejection(coverage_case, monkeypatch):
    c = coverage_case
    c.runner.evaluate(c.plan.plan_id, baseline_id=c.baseline.baseline_id)
    before = table_snapshot(c.store.database)
    with monkeypatch.context() as patch:
        patch.setattr(schema, "STATEMENTS", schema.STATEMENTS + ("INVALID SQL",))
        with pytest.raises(StorageError):
            migrate_improvement_review(c.store.database)
    assert table_snapshot(c.store.database) == before
    migrate_improvement_review(c.store.database)
    after = table_snapshot(c.store.database)
    assert all(after[t] == rows for t, rows in before.items())
    migrate_improvement_review(c.store.database)
    with c.store.database.transaction() as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 13
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(UnsupportedSchemaError):
        migrate_improvement_review(c.store.database)
    with pytest.raises(UnsupportedSchemaError):
        ImprovementReviewStore(c.comparison_store)


def test_record_insert_failure_rolls_back_confirmation_and_restart_replay(review_case):
    from soc_agent.review.persistence.confirmations import SQLiteConfirmationConsumer

    c = review_case
    value = submission(c)
    token = issue(c, value)
    with c.store.database.transaction() as connection:
        connection.execute(
            "CREATE TRIGGER block_improvement_insert "
            "BEFORE INSERT ON improvement_review_records BEGIN "
            "SELECT RAISE(ABORT, 'test atomic rollback'); END"
        )
    before = table_snapshot(c.store.database)
    with pytest.raises(StorageError):
        c.service.submit(value, credential=token)
    assert table_snapshot(c.store.database) == before
    with c.store.database.transaction() as connection:
        connection.execute("DROP TRIGGER block_improvement_insert")
    # Fake provider retains no production state; re-enable the same verified receipt
    # solely to prove durable rollback, rather than treating it as a consumed receipt.
    c.boundary.provider.used.clear()
    record = c.service.submit(value, credential=token)
    other = ImprovementReviewStore(reopen(c.store.database.path))
    consumer = SQLiteConfirmationConsumer(other.database)
    with pytest.raises(HumanAuthorizationDenied, match="consumed"):
        consumer.consume(record.verification)
    assert other.get_review_record(record.review_record_id) == record
