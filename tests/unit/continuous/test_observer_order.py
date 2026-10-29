"""Blocking status queries cannot age a previously acquired sample; no live service."""

import pytest

from soc_agent.continuous.process_identity import observe_service_health


def test_slow_service_queries_are_followed_by_fresh_snapshot():
    now = [100.0]
    calls = []

    def properties(unit):
        calls.append(unit)
        now[0] += 4
        return {"ActiveState": "active"}

    def snapshot():
        calls.append("read")
        return dict(
            heartbeat_unix=now[0] - 1, component_health=dict(collector_message_unix=now[0] - 2)
        )

    value, evidence = observe_service_health(properties, snapshot, lambda: now[0])
    assert calls[-1] == "read"
    assert evidence["query_seconds"] == 8 and evidence["source_age"] == 2
    assert value["heartbeat_unix"] == 107


@pytest.mark.parametrize("stamp", [94, 0, None, float("nan"), 101, True])
def test_stale_missing_future_and_nonfinite_source_still_block(stamp):
    with pytest.raises(ValueError, match="ROOT_HEARTBEAT_STALE"):
        observe_service_health(
            lambda _: dict(ActiveState="active"),
            lambda: dict(heartbeat_unix=100, component_health=dict(collector_message_unix=stamp)),
            lambda: 100,
        )


def test_operator_stop_breadcrumb_wins_over_already_stopped_service():
    value, _ = observe_service_health(
        lambda _: dict(ActiveState="inactive"),
        lambda: dict(stop_reason="OPERATOR_REQUEST"),
        lambda: 100,
    )
    assert value["stop_reason"] == "OPERATOR_REQUEST"
