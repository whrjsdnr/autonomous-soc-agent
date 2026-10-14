"""Read-only authentication correlations over the existing validated pipeline.

Thresholds are examples; rules have fixture evidence, not production efficacy evidence.
PAM module failures stay separate from completed SSH authentication outcomes.
"""

from collections import defaultdict
from datetime import datetime

from pydantic import Field

from soc_agent.security_ai.external.models import Snapshot
from soc_agent.security_ai.operational.authentication_investigation import read_authentication_view
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import PAM_PROFILE


class DetectionConfig(Snapshot):
    profile: str = "EXAMPLE_UNVALIDATED"
    repeated_failures: int = Field(default=5, strict=True, ge=2, le=100)
    multiple_accounts: int = Field(default=3, strict=True, ge=2, le=100)


def detect(pipeline: AuthenticationPipeline, config: DetectionConfig) -> tuple[str, ...]:
    """Read validated authentication counts; return advisory signals without state changes."""
    view = read_authentication_view(pipeline)
    # Caller holds the pipeline writer lock across this read-only correlation.
    with pipeline.store.database.transaction(write=False) as c:
        accepted = {
            pipeline.store._decode(row).event.event_id
            for row in c.execute(
                "SELECT * FROM operational_sources WHERE incident_id=? AND status='ACCEPTED'",
                (str(pipeline.incident_id),),
            )
        }
    groups: dict[tuple[str, int], list[tuple[datetime, str, str]]] = defaultdict(list)
    signals: set[str] = set()
    with pipeline.queue.database.transaction(write=False) as c:
        for row in c.execute("SELECT * FROM realtime_events WHERE status='DONE' ORDER BY rowid"):
            event = pipeline.queue._decode(row)
            if event.source_digest not in view.source_reference:
                raise ValueError("AUTH_DETECTION_SNAPSHOT_CHANGED")
            if str(event.event_id) not in accepted:
                continue
            fields = dict(event.normalized_fields)
            if fields.get("parse_status") != "MAPPED_AUTHENTICATION":
                continue
            if fields["parser"] == PAM_PROFILE:
                signals.add("SUDO_PAM_MODULE_FAILURE")
                continue  # Module failure is not a completed SSH/login failure.
            window = int(event.event_timestamp.timestamp()) // 300
            groups[(fields["source_identifier"], window)].append(
                (event.event_timestamp, fields["account_id"], fields["authentication_result"])
            )
    for records in groups.values():
        failures = [r for r in records if r[2] == "failure"]
        if len(failures) >= config.repeated_failures:
            signals.add("REPEATED_AUTH_FAILURE")
        if len({r[1] for r in failures}) >= config.multiple_accounts:
            signals.add("MULTI_ACCOUNT_FAILURE")
        for timestamp, account, result in records:
            if result == "success" and any(
                failed_account == account and failed_at < timestamp
                for failed_at, failed_account, _ in failures
            ):
                signals.add("FAILURE_THEN_SUCCESS")
    return tuple(sorted(signals))
