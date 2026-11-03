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
