"""Real child-process forced termination and private SQLite, with explicit SSH fixtures."""

import pytest
from tests.authentication_crash_harness import POINTS, crash_case
from tests.unit.operational_features.test_native_authentication import row

from soc_agent.security_ai.operational.native_authentication import project_journal


@pytest.mark.parametrize("point", POINTS)
def test_owned_child_crash_preserves_authentication_effect(tmp_path, point):
    result = crash_case(tmp_path / point, project_journal(row()), point)
    assert (
        result["event_loss"] == result["duplicate_window_effect"] == result["write_spy_calls"] == 0
    )


@pytest.mark.parametrize("damage", ["receipt", "source", "cursor"])
def test_corruption_after_crash_is_fail_closed(tmp_path, damage):
    from tests.authentication_crash_harness import open_pipeline

    from soc_agent.security_ai.operational.authentication_investigation import (
        read_authentication_view,
    )
    from soc_agent.security_ai.operational.native_authentication import LinuxAuthenticationCollector

    root = tmp_path / damage
    crash_case(root, project_journal(row()), "CP-05")
    p = open_pipeline(root, LinuxAuthenticationCollector.identity)
    db = p.store.database if damage == "source" else p.queue.database
    with db.transaction() as c:
        if damage == "receipt":
            c.execute("UPDATE realtime_events SET outcome='{}'")
        elif damage == "source":
            c.execute("UPDATE operational_sources SET digest=?", ("0" * 64,))
        else:
            c.execute("UPDATE realtime_cursors SET digest=?", ("0" * 64,))
    with pytest.raises(ValueError):
        if damage == "cursor":
            p.queue.cursor(LinuxAuthenticationCollector.identity)
        else:
            read_authentication_view(p)


def test_retry_exhaustion_preserves_source_but_refuses_incomplete_read(tmp_path):
    from tests.authentication_crash_harness import INCIDENT, open_pipeline

    from soc_agent.security_ai.operational.authentication_investigation import (
        read_authentication_view,
    )
    from soc_agent.security_ai.operational.native_authentication import (
        LinuxAuthenticationCollector,
        ingest_authentication,
    )

    p = open_pipeline(tmp_path / "poison", LinuxAuthenticationCollector.identity, create=True)
    event = project_journal(row())
    p.queue.enqueue(event)
    claim = p.queue.claim()
    ingest_authentication(
        event, expected_event_digest=event.source_digest, store=p.store, incident_id=INCIDENT
    )
    # Explicitly exhausted retry budget is quarantine, not successful completed processing.
    for _ in range(p.queue.retry_limit - 1):
        p.queue.fail(claim)
        claim = p.queue.claim()
    p.queue.fail(claim)
    assert p.queue.counts() == {"POISON": 1}
    assert (
        sum(
            w.window.features.input_payload()["total_login_count"]
            for w in p.store.windows(INCIDENT)
        )
        == 1
    )
    with pytest.raises(ValueError, match="RECEIPT_LINK"):
        read_authentication_view(p)
