"""Fixed synthetic reports, not observations of real users or attacks."""

from datetime import UTC, datetime, timedelta
from uuid import NAMESPACE_URL, uuid5

from soc_agent.ingestion import SOCEvent


def scenario_event(name: str) -> SOCEvent:
    if name not in ("a", "b"):
        raise ValueError("Unknown demo scenario")
    start = datetime(2026, 1, 1, tzinfo=UTC)
    results = ("success",) if name == "a" else ("failure", "failure", "failure")
    return SOCEvent.model_validate(
        {
            "event_id": uuid5(NAMESPACE_URL, "soc-synthetic-command-center:" + name),
            "event_type": "authentication",
            "source": "synthetic-demo",
            "occurred_at": start + timedelta(minutes=1),
            "subject": "demo-alice" if name == "a" else "demo-bob",
            "resource": "demo-login",
            "severity_hint": "info" if name == "a" else "high",
            "synthetic": True,
            "attributes": {
                "attempts": [
                    {
                        "event_id": f"demo-{name}-{i}",
                        "event_time": start + timedelta(seconds=i),
                        "account_id": "demo-alice" if name == "a" else "demo-bob",
                        "authentication_result": result,
                        "source_identifier": "192.0.2.10",
                    }
                    for i, result in enumerate(results)
                ]
            },
        }
    )
