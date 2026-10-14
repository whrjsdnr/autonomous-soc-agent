"""Verified source correlation with stable rule/source/window keys and no severity promotion."""

from collections import defaultdict

from soc_agent.linux_runtime.models import Finding, RuntimeConfig
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.security_ai.operational.authentication_investigation import read_authentication_view
from soc_agent.security_ai.operational.authentication_pipeline import AuthenticationPipeline
from soc_agent.security_ai.operational.native_authentication import PAM_PROFILE
from soc_agent.security_ai.operational.provenance import build_receipt


def correlate(pipeline: AuthenticationPipeline, config: RuntimeConfig) -> tuple[Finding, ...]:
    # Caller holds the runtime writer lock. Reuse the full queue/source/receipt guard.
    view = read_authentication_view(pipeline)
    with pipeline.store.database.transaction(write=False) as c:
        sources = {
            row["payload"]: pipeline.store._decode(row)
            for row in c.execute(
                "SELECT * FROM operational_sources WHERE incident_id=? AND status='ACCEPTED'",
                (str(pipeline.incident_id),),
            )
        }
    by_event = {source.event.event_id: source for source in sources.values()}
    groups = defaultdict(list)
    findings = []

    def emit(rule, scope, records):
        linked = tuple(by_event[str(e.event_id)] for e in records)
        provenance = build_receipt(pipeline.store, incident_id=pipeline.incident_id, sources=linked)
        findings.append(
            Finding(
                finding_id=content_digest_payload(
                    {
                        "incident": str(pipeline.incident_id),
                        "rule": rule,
                        "scope": list(scope) if isinstance(scope, tuple) else scope,
                    }
                ),
                incident_id=pipeline.incident_id,
                rule_id=rule,
                severity="info" if rule == "SUDO_PAM_MODULE_FAILURE" else "low",
                event_references=tuple(str(e.event_id) for e in records),
                evidence_references=tuple(s.content_digest for s in linked),
                first_seen=min(e.event_timestamp for e in records),
                last_seen=max(e.event_timestamp for e in records),
                detection_reason=f"{rule}; unique records={len(records)}; not attack confirmation",
                provenance=(provenance.receipt_digest,),
                input_origin="FIXTURE"
                if records[0].provenance == "explicit_log_fixture"
                else "NATIVE_OS",
            )
        )

    with pipeline.queue.database.transaction(write=False) as c:
        for row in c.execute("SELECT * FROM realtime_events WHERE status='DONE' ORDER BY rowid"):
            event = pipeline.queue._decode(row)
            if event.source_digest not in view.source_reference:
                raise ValueError("DETECTION_SNAPSHOT_CHANGED")
            if str(event.event_id) not in by_event:
                continue
            fields = dict(event.normalized_fields)
            if fields["parser"] == PAM_PROFILE:
                emit("SUDO_PAM_MODULE_FAILURE", str(event.event_id), [event])
            else:
                groups[
                    (fields["source_identifier"], int(event.event_timestamp.timestamp()) // 300)
                ].append(event)
    for scope, records in groups.items():
        failures = [
            e for e in records if dict(e.normalized_fields)["authentication_result"] == "failure"
        ]
        if len(failures) >= config.repeated_failures:
            emit("REPEATED_AUTH_FAILURE", scope, failures)
        accounts = defaultdict(list)
        for event in failures:
            accounts[dict(event.normalized_fields)["account_id"]].append(event)
        if len(accounts) >= config.multiple_accounts:
            emit("MULTI_ACCOUNT_FAILURE", scope, failures)
        for account, events in accounts.items():
            if len(events) >= config.repeated_failures:
                emit("REPEATED_ACCOUNT_FAILURE", (*scope, account), events)
        for event in records:
            f = dict(event.normalized_fields)
            prior = [
                e for e in accounts[f["account_id"]] if e.event_timestamp < event.event_timestamp
            ]
            if f["authentication_result"] == "success" and prior:
                emit("FAILURE_THEN_SUCCESS", (*scope, f["account_id"]), [*prior, event])
    return tuple(findings)


def validate_finding(pipeline: AuthenticationPipeline, finding: Finding) -> None:
    read_authentication_view(pipeline)
    if finding.incident_id != pipeline.incident_id:
        raise ValueError("FINDING_INCIDENT_MISMATCH")
    with pipeline.store.database.transaction(write=False) as c:
        rows = c.execute(
            "SELECT * FROM operational_sources WHERE incident_id=? AND status='ACCEPTED'",
            (str(pipeline.incident_id),),
        ).fetchall()
        sources = {
            pipeline.store._decode(r).event.event_id: pipeline.store._decode(r) for r in rows
        }
    linked = tuple(sources.get(ref) for ref in finding.event_references)
    if (
        any(s is None for s in linked)
        or tuple(s.content_digest for s in linked) != finding.evidence_references
    ):
        raise ValueError("FINDING_SOURCE_MISMATCH")
    receipt = build_receipt(pipeline.store, incident_id=pipeline.incident_id, sources=linked)
    if (receipt.receipt_digest,) != finding.provenance:
        raise ValueError("FINDING_PROVENANCE_MISMATCH")
