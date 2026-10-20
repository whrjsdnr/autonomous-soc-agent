"""Linux 6.18 dev.c tcx_run + verdict model, not an executed kernel proof."""

import pytest


def evaluate(programs, legacy):
    visited = []
    result = -1
    for name, result in programs:
        visited.append(name)
        if result != -1:
            break
    # tcx_action_code maps unknown actions to NEXT *after* the loop broke.
    result = result if result in (-1, 0, 2, 7) else -1
    if result == -1:
        visited.append("legacy")
        result = legacy
    return visited, result


@pytest.mark.parametrize("foreign", [-1, 0, 2, 7])
def test_append_next_preserves_existing_order_and_verdict(foreign):
    before = [("foreign", foreign)]
    baseline, verdict = evaluate(before, 2)
    visited, actual = evaluate(before + [("observer", -1)], 2)
    assert actual == verdict
    assert [name for name in visited if name != "observer"] == baseline
    assert ("observer" in visited) == (foreign == -1)


def test_next_preserves_later_tcx_and_legacy_where_ok_and_pipe_do_not():
    assert evaluate([("observer", -1), ("later", -1)], 2) == (["observer", "later", "legacy"], 2)
    assert evaluate([("observer", 0), ("later", 2)], 2) == (["observer"], 0)
    assert evaluate([("observer", 3), ("later", 2)], 2) == (["observer", "legacy"], 2)
