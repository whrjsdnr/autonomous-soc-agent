"""Finite authentication batches: UTC epoch-aligned five-minute account windows."""

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from soc_agent.security_ai.features import (
    DatasetRecordReference,
    DatasetSchema,
    FeatureDefinition,
    FeatureSchema,
    FeatureSet,
    SecurityRecord,
    SourceReference,
    SourceType,
    create_feature_set,
)
from soc_agent.security_ai.features.models import Snapshot
from soc_agent.state import IncidentState
from soc_agent.state.evidence import NonEmptyText, UTCTimestamp

WINDOW_SECONDS = 300
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


class AuthenticationResult(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"


class AuthenticationEvent(Snapshot):
    event_id: NonEmptyText
    event_time: UTCTimestamp
    account_id: NonEmptyText
    authentication_result: AuthenticationResult
    source_identifier: NonEmptyText


def authentication_record(event: AuthenticationEvent, *, source: SourceReference) -> SecurityRecord:
    """In-memory source adapter. Dataset labels remain external to event payloads.

    Source record IDs are adapter identities and need not equal globally unique event IDs.
    Evidence uses the existing record_from_evidence adapter with state validation instead.
    """
    event = AuthenticationEvent.model_validate(event.model_dump())
    source = SourceReference.model_validate(source.model_dump())
    if source.source_type == SourceType.EVIDENCE:
        raise ValueError("Evidence must be resolved through record_from_evidence")
    dataset_ref = None
    if source.source_type == SourceType.DATASET:
        if source.source_version is None:
            raise ValueError("Dataset sources require a version")
        dataset_ref = DatasetRecordReference(
            dataset=DatasetSchema(
                dataset_name=source.source_name,
                dataset_version=source.source_version,
                record_schema_version="1.0.0",
            ),
            record_id=source.record_id,
        )
    return SecurityRecord(
        record_type="authentication_event",
        record_schema_version="1.0.0",
        source=source.source_name,
        source_reference=source,
        dataset_reference=dataset_ref,
        fields=event.model_dump(mode="json"),
        observed_at=event.event_time,
    )


def authentication_feature_schema() -> FeatureSchema:
    return FeatureSchema(
        schema_name="authentication_behavior_features",
        schema_version="1.0.0",
        features=tuple(
            FeatureDefinition(name=name, data_type=kind, description=description)
            for name, kind, description in (
                ("failed_login_count", "int", "Failed attempts in this account window"),
                ("successful_login_count", "int", "Successful attempts in this account window"),
                ("total_login_count", "int", "All attempts in this account window"),
                ("failure_rate", "float", "Failed attempts divided by total attempts"),
                ("login_attempt_rate", "float", "Total attempts per second over 300 seconds"),
            )
        ),
    )


class AuthenticationBehavior(Snapshot):
    failed_login_count: int = Field(ge=0, strict=True)
    successful_login_count: int = Field(ge=0, strict=True)
    total_login_count: int = Field(gt=0, strict=True)
    failure_rate: float = Field(ge=0, le=1, allow_inf_nan=False, strict=True)
    login_attempt_rate: float = Field(gt=0, allow_inf_nan=False, strict=True)

    @model_validator(mode="after")
    def validate_calculations(self) -> Self:
        if self.total_login_count != self.failed_login_count + self.successful_login_count:
            raise ValueError("Authentication counts differ")
        if self.failure_rate != self.failed_login_count / self.total_login_count:
            raise ValueError("Invalid failure rate")
        if self.login_attempt_rate != self.total_login_count / WINDOW_SECONDS:
            raise ValueError("Invalid attempt rate for the fixed window")
        return self


def validate_authentication_features(feature: FeatureSet) -> FeatureSet:
    feature = FeatureSet.model_validate(feature.model_dump(warnings=False))
    if feature.feature_schema != authentication_feature_schema() or (
        feature.provenance.extractor_name,
        feature.provenance.extractor_version,
    ) != ("authentication_window", "1.0.0"):
        raise ValueError("Authentication schema or extractor mismatch")
    AuthenticationBehavior.model_validate(feature.input_payload())
    return feature


class AuthenticationWindow(Snapshot):
    """Grouping context is separate from the five model features."""

    account_id: NonEmptyText
    started_at: UTCTimestamp
    ended_at: UTCTimestamp
    event_ids: tuple[NonEmptyText, ...] = Field(min_length=1)
    features: FeatureSet

    @model_validator(mode="after")
    def validate_window(self) -> Self:
        feature = validate_authentication_features(self.features)
        if self.ended_at - self.started_at != timedelta(seconds=WINDOW_SECONDS):
            raise ValueError("Unsupported authentication window width")
        if (self.started_at - EPOCH) % timedelta(seconds=WINDOW_SECONDS):
            raise ValueError("Window must be epoch aligned")
        if len(set(self.event_ids)) != len(self.event_ids):
            raise ValueError("Duplicate event IDs")
        if len(self.event_ids) != feature.input_payload()["total_login_count"]:
            raise ValueError("Event count differs from feature counts")
        if len(feature.provenance.sources) != len(self.event_ids) or any(
            s.record_type != "authentication_event"
            or s.record_schema_version != "1.0.0"
            or not self.started_at <= s.observed_at < self.ended_at
            for s in feature.provenance.sources
        ):
            raise ValueError("Source records differ from the window contract")
        return self


class AuthenticationWindowExtractor:
    """Each event contributes to exactly one account/window; no synthesized empty windows."""

    def extract(
        self, records: tuple[SecurityRecord, ...], *, state: IncidentState | None = None
    ) -> tuple[AuthenticationWindow, ...]:
        groups: dict[tuple[str, datetime], list[tuple[AuthenticationEvent, SecurityRecord]]] = (
            defaultdict(list)
        )
        event_ids, record_ids, logical_ids = set(), set(), set()
        incident_ids = set()
        for record in records:
            record = SecurityRecord.model_validate(record.model_dump(warnings=False))
            if (record.record_type, record.record_schema_version) != (
                "authentication_event",
                "1.0.0",
            ):
                raise ValueError("Unsupported authentication event contract")
            # Unknown statuses and extra fields (including labels) fail closed.
            event = AuthenticationEvent.model_validate(record.payload())
            if record.observed_at != event.event_time:
                raise ValueError("Record timestamp differs from event time")
            source_key = tuple(record.source_reference.model_dump().values())
            if (
                event.event_id in event_ids
                or record.record_id in record_ids
                or source_key in logical_ids
            ):
                raise ValueError("Duplicate authentication source or event ID")
            event_ids.add(event.event_id)
            record_ids.add(record.record_id)
            logical_ids.add(source_key)
            incident_ids.add(record.incident_id)
            start = EPOCH + (
                (event.event_time - EPOCH) // timedelta(seconds=WINDOW_SECONDS)
            ) * timedelta(seconds=WINDOW_SECONDS)
            groups[(event.account_id, start)].append((event, record))
        if len(incident_ids) > 1:
            raise ValueError("Mixed incident authentication sources")
        windows: list[AuthenticationWindow] = []
        for (account, start), entries in sorted(groups.items()):
            entries.sort(key=lambda item: (item[0].event_time, item[0].event_id))
            failed = sum(
                e.authentication_result == AuthenticationResult.FAILURE for e, _ in entries
            )
            total = len(entries)
            values = AuthenticationBehavior(
                failed_login_count=failed,
                successful_login_count=total - failed,
                total_login_count=total,
                failure_rate=failed / total,
                login_attempt_rate=total / WINDOW_SECONDS,
            )
            feature = create_feature_set(
                feature_schema=authentication_feature_schema(),
                values=values.model_dump(),
                records=tuple(r for _, r in entries),
                extractor_name="authentication_window",
                extractor_version="1.0.0",
                state=state,
            )
            windows.append(
                AuthenticationWindow(
                    account_id=account,
                    started_at=start,
                    ended_at=start + timedelta(seconds=WINDOW_SECONDS),
                    event_ids=tuple(e.event_id for e, _ in entries),
                    features=feature,
                )
            )
        return tuple(windows)
