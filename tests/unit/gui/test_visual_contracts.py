"""Presentation safety and measured chart contracts, independent of a display."""

import pytest

from soc_agent.gui.charts import MetricHistory
from soc_agent.gui.components import CRITICAL, HEALTHY, UNKNOWN, WARNING, color
from soc_agent.gui.presentation import sections


def sample(value):
    return {
        "queue_backlog": value,
        "completed_read_only": 1,
        "completed_llm": 0,
        "completed_scripted": 0,
    }


def test_duplicate_measurement_is_idempotent_but_later_poll_is_flat_sample():
    history = MetricHistory()
    history.observe(sample(4), now=1)
    history.observe(sample(4), now=1)
    assert len(history.samples) == 1
    history.observe(sample(4), now=2)
    assert len(history.samples) == 2
    assert [r.completed for r in history.samples] == [1, 1]
    with pytest.raises(ValueError, match="CONFLICTING_MEASUREMENT"):
        history.observe(sample(0), now=2)


def test_large_history_keeps_latest_real_measurements_in_order():
    history = MetricHistory(120)
    for i in range(10000):
        history.observe(sample(i % 5), now=i)
    assert len(history.samples) == 120
    assert history.samples[0].measured_at == 9880
    assert history.samples[-1].measured_at == 9999
    with pytest.raises(ValueError, match="MEASUREMENT_TIME_REVERSED"):
        history.observe(sample(3), now=2)


@pytest.mark.parametrize("value", ["UNKNOWN", "UNVERIFIED", "UNAVAILABLE", "STOPPED"])
def test_unverified_is_never_green(value):
    assert color(value) == UNKNOWN and color(value) != HEALTHY


@pytest.mark.parametrize(
    "value", ["NOT_READY", "NOT_INFERABLE", "INCONCLUSIVE", "PENDING_APPROVAL"]
)
def test_uncertainty_or_unready_is_warning(value):
    assert color(value) == WARNING


def test_regression_is_not_success_and_summary_never_fills_missing_assessment():
    assert color("REGRESSION") == CRITICAL
    assert color("NO_FP_FN_COUNT_REGRESSION") == WARNING
    value = {
        "rule_id": "SUDO_PAM_MODULE_FAILURE",
        "status": "DONE_READ_ONLY",
        "evidence_references": ["0" * 64],
        "observations": {"first_seen": "2026-01-01T00:00:00Z"},
    }
    result = dict(sections("Investigations", value))
    assert result["Advisory assessment • not an observed fact"] == "No stored model assessment"
    assert "UNKNOWN" in result["Event timeline (UTC)"]
    assert result["READ tool progress"].startswith("UNKNOWN")
    value["advisory_assessment"] = {
        "threat_assessment": {"summary": "SCRIPTED advisory; not attack fact"}
    }
    assert (
        dict(sections("Investigations", value))["Advisory assessment • not an observed fact"]
        == "SCRIPTED advisory; not attack fact"
    )
