"""Synthetic account behavior only; no enterprise security performance claims."""

from datetime import UTC, datetime, timedelta

from soc_agent.security_ai.authentication import (
    AuthenticationEvent,
    AuthenticationExample,
    AuthenticationWindowExtractor,
    authentication_record,
)
from soc_agent.security_ai.features import SourceReference


def record(event_id="e1", account="alice", seconds=0, result="failure", kind="dataset"):
    return authentication_record(
        AuthenticationEvent(
            event_id=event_id,
            event_time=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=seconds),
            account_id=account,
            authentication_result=result,
            source_identifier="192.0.2.1",
        ),
        source=SourceReference(
            source_type=kind,
            source_name="synthetic-auth" if kind == "dataset" else "auth_events",
            source_version="1",
            record_id=event_id,
        ),
    )


def fixture_examples(kind="dataset"):
    records = []
    for account in range(15):
        for window in range(2):
            failed = account % 3 if window == 0 else 30 + account
            success = 4 + account if window == 0 else 1
            for index in range(failed + success):
                records.append(
                    record(
                        event_id=f"{account}-{window}-{index}",
                        account=f"account-{account:02}",
                        seconds=window * 300 + index,
                        result="failure" if index < failed else "success",
                        kind=kind,
                    )
                )
    windows = AuthenticationWindowExtractor().extract(tuple(records))
    return tuple(
        AuthenticationExample(window=w, label="normal" if w.started_at.minute == 0 else "anomalous")
        for w in windows
    )
