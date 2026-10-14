"""Versioned source observations; predictions are never normalized source fields."""

from datetime import UTC, datetime
from typing import Annotated, Literal, Self
from uuid import NAMESPACE_URL, UUID, uuid5

from pydantic import Field, StringConstraints, model_validator

from soc_agent.external_runtime import FeatureRow
from soc_agent.ingestion.models import Event
from soc_agent.review.identity import content_digest
from soc_agent.review.models import Frozen
from soc_agent.security_ai.external.models import content_digest_payload
from soc_agent.state.evidence import UTCTimestamp

Text = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class SourceIdentity(Frozen):
    namespace: Text
    generation: Text
    record: Text


class SourceMetadata(Frozen):
    channel: Text
    provider: Text
    code: Text | None = None
    original_timestamp: Text | None = None


class CommonEvent(Frozen):
    schema_version: Literal["soc-common-event:v1", "soc-common-event:v2"] = "soc-common-event:v1"
    event_id: UUID
    platform: Literal["windows", "linux", "validated_fixture"]
    collector_id: Text
    event_type: Literal["os_record", "validated_model_input"]
    event_timestamp: UTCTimestamp
    ingestion_timestamp: UTCTimestamp
    source: SourceIdentity
    metadata: SourceMetadata
    normalized_fields: tuple[tuple[Text, Text], ...] = Field(default=(), max_length=16)
    provenance: Literal["native_read_only", "explicit_precomputed_fixture", "explicit_log_fixture"]
    validation_status: Literal["VALIDATED_SOURCE_RECORD"] = "VALIDATED_SOURCE_RECORD"
    soc_event: Event | None = None
    feature_payload: tuple[FeatureRow, ...] = Field(default=(), max_length=3)

    @model_validator(mode="after")
    def identities(self) -> Self:
        expected = uuid5(NAMESPACE_URL, content_digest(self.source))
        if self.event_id != expected:
            raise ValueError("Common source identity mismatch")
        if self.event_type == "os_record":
            if self.soc_event is not None or self.feature_payload:
                raise ValueError("OS records cannot invent model inputs")
            fixture = (
                self.schema_version == "soc-common-event:v2"
                and self.platform == "validated_fixture"
                and self.provenance == "explicit_log_fixture"
                and self.collector_id == "scenario-auth-pam:v1"
                and self.source.namespace.startswith("scenario:")
            )
            native = (
                self.schema_version == "soc-common-event:v1"
                and self.provenance == "native_read_only"
                and self.platform != "validated_fixture"
                and self.collector_id != "scenario-auth-pam:v1"
                and not self.source.namespace.startswith("scenario:")
            )
            if not (fixture or native):
                raise ValueError("Native observation provenance required")
        else:
            if (
                self.platform != "validated_fixture"
                or self.provenance != "explicit_precomputed_fixture"
            ):
                raise ValueError("Explicit feature provenance required")
            if self.soc_event is None or self.soc_event.occurred_at != self.event_timestamp:
                raise ValueError("Original SOC event and timestamp required")
            if self.source.record != str(self.soc_event.event_id):
                raise ValueError("Fixture source identity must retain original event ID")
            for row in self.feature_payload:
                if (
                    row.event_id != self.soc_event.event_id
                    or row.observation.association is not None
                ):
                    raise ValueError("Feature event binding mismatch")
        if len({k for k, _ in self.normalized_fields}) != len(self.normalized_fields):
            raise ValueError("Duplicate normalized fields")
        if len(self.model_dump_json().encode("utf-8")) > 262144:
            raise ValueError("Common event size limit exceeded")
        return self

    @property
    def source_digest(self) -> str:
        # Receipt time is not part of source identity; first committed receipt is retained.
        return content_digest_payload(self.model_dump(mode="json", exclude={"ingestion_timestamp"}))


def native_event(platform, collector, source, metadata, timestamp) -> CommonEvent:
    return CommonEvent(
        event_id=uuid5(NAMESPACE_URL, content_digest(source)),
        platform=platform,
        collector_id=collector,
        event_type="os_record",
        event_timestamp=timestamp,
        ingestion_timestamp=datetime.now(UTC),
        source=source,
        metadata=metadata,
        provenance="native_read_only",
    )
