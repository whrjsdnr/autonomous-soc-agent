"""Surface existing exact-input decisions without granting execution authority."""

from soc_agent.gui.continuous_view import review_api, review_models


def prompt_pending(app, snapshot):
    """Read-only preparation; every grant still requires the existing human dialog."""
    current = snapshot.get("continuous", {})
    if (
        app.busy
        or app.closing
        or not getattr(app.config, "continuous_execution_evidence", None)
        or current.get("source") != "NATIVE_SERVICE"
        or current.get("state") != "RUNNING"
        or current.get("last_error")
    ):
        return
    if not hasattr(app, "operator_review_seen"):
        app.operator_review_seen = set()

    def prepared_api(summary):
        if not summary.get("ready"):
            return
        key = ("API", summary["runtime_session"], summary["review_digest"])
        if key not in app.operator_review_seen:
            # A rejection is not an invitation to keep prompting. Manual review remains.
            app.operator_review_seen.add(key)
            review_api(app, summary)

    def prepared(batch):
        if batch.get("jobs"):
            key = ("MODEL", batch["runtime_session"], batch["batch_digest"])
            if key not in app.operator_review_seen:
                app.operator_review_seen.add(key)
                review_models(app, batch)
        if not app.busy and not app.closing:
            app.call("api_review_prepare", callback=prepared_api)

    app.call("model_review_prepare", callback=prepared)
