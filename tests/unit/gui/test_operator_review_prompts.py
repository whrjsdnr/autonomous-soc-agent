"""No Root, journal read, model or API calls: exact dialogs are mocked explicitly."""

from types import SimpleNamespace

import pytest

from soc_agent.gui import operator_review


class App:
    def __init__(self):
        self.busy = self.closing = False
        self.config = SimpleNamespace(continuous_execution_evidence="FIXTURE_ONLY")
        self.calls = []
        self.batch = dict(jobs=[dict(job="sealed")], runtime_session="one", batch_digest="pin")
        self.api = dict(ready=True, runtime_session="one", review_digest="api-pin")

    def call(self, operation, *, callback):
        self.calls.append(operation)
        callback(self.batch if operation == "model_review_prepare" else self.api)


def live():
    return dict(continuous=dict(source="NATIVE_SERVICE", state="RUNNING", last_error=None))


def test_prompts_current_inputs_once_and_never_issues_grants(monkeypatch):
    app = App()
    dialogs = []
    monkeypatch.setattr(operator_review, "review_models", lambda a, b: dialogs.append(b))
    monkeypatch.setattr(operator_review, "review_api", lambda a, b: dialogs.append(b))
    operator_review.prompt_pending(app, live())
    operator_review.prompt_pending(app, live())
    assert dialogs == [app.batch, app.api]
    assert set(app.calls) == {"model_review_prepare", "api_review_prepare"}
    app.batch = app.batch | dict(batch_digest="new-sealed-input")
    operator_review.prompt_pending(app, live())
    assert dialogs == [dialogs[0], app.api, app.batch]


@pytest.mark.parametrize("state", ["STOPPED", "DEGRADED", "ERROR"])
def test_no_prompt_for_ended_or_failed_runtime(state):
    app = App()
    value = live()
    value["continuous"]["state"] = state
    operator_review.prompt_pending(app, value)
    assert app.calls == []


def test_waiting_inputs_are_not_approved_or_shown(monkeypatch):
    app = App()
    app.batch = dict(jobs=[])
    app.api = dict(ready=False)
    monkeypatch.setattr(operator_review, "review_models", lambda *_: pytest.fail("no inputs"))
    monkeypatch.setattr(operator_review, "review_api", lambda *_: pytest.fail("no inputs"))
    operator_review.prompt_pending(app, live())
    assert app.operator_review_seen == set()


def test_no_request_when_busy_or_not_bound():
    app = App()
    app.busy = True
    operator_review.prompt_pending(app, live())
    app.busy = False
    app.config.continuous_execution_evidence = None
    operator_review.prompt_pending(app, live())
    assert app.calls == []


@pytest.mark.parametrize("confirmed", [False, True])
def test_model_dialog_requires_human_answer_and_passes_only_exact_batch(monkeypatch, confirmed):
    from soc_agent.gui import continuous_view

    calls = []
    app = SimpleNamespace(
        root=object(),
        continuous_updated=lambda _: None,
        call=lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    shown = []

    def answer(title, text, *, parent):
        shown.append(text)
        return confirmed

    monkeypatch.setattr(continuous_view.messagebox, "askyesno", answer)
    batch = dict(
        jobs=[dict(job="exact-sealed-job", eligible=1, calls=2)],
        runtime_session="fixture-session",
        actor="fixture-human",
        previous_invocations=0,
        maximum_invocations=16,
        models=dict(quality="fixture-rf", edge="fixture-lr"),
        batch_digest="exact-batch-pin",
    )
    continuous_view.review_models(app, batch)
    assert "No future-input approval" in shown[0]
    assert "exact-sealed-job" in shown[0] and "fixture-session" in shown[0]
    assert [c[0] for c in calls] == (
        [("model_review_approve", "exact-batch-pin", True)] if confirmed else []
    )


@pytest.mark.parametrize("confirmed", [False, True])
def test_api_dialog_requires_human_answer_for_exact_evidence_and_cost(monkeypatch, confirmed):
    from soc_agent.gui import continuous_view

    calls = []
    app = SimpleNamespace(root=object(), call=lambda *args, **kwargs: calls.append((args, kwargs)))
    shown = []

    def answer(title, text, *, parent):
        shown.append(text)
        return confirmed

    monkeypatch.setattr(continuous_view.messagebox, "askyesno", answer)
    summary = dict(
        ready=True,
        incident_id="fixture-incident",
        evidence_revision="fixture-revision",
        base_url="https://example.invalid/v1",
        model="fixture-model",
        max_calls=2,
        budget_usd="0.05",
        timeout_seconds=20,
        review_digest="exact-api-pin",
    )
    continuous_view.review_api(app, summary)
    assert "fixture-revision" in shown[0] and "USD <= 0.05" in shown[0]
    assert "automatic retries=0" in shown[0]
    assert [c[0] for c in calls] == (
        [("api_review_approve", "exact-api-pin", True)] if confirmed else []
    )
