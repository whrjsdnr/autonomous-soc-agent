"""Small behavioral flow contract shared by offline and userspace sources."""

from pydantic import BaseModel, ConfigDict, Field

from soc_agent.security_ai.features import (
    FeatureDefinition,
    FeatureSchema,
    FeatureSet,
    SecurityRecord,
    create_feature_set,
)
from soc_agent.state import IncidentState

# Explicit supported CSV dialect, never guessed aliases or positional column selection.
COLUMNS = (
    ("Flow Duration", "duration_us"),
    ("Total Fwd Packets", "fwd_packets"),
    ("Total Backward Packets", "bwd_packets"),
    ("Total Length of Fwd Packets", "fwd_bytes"),
    ("Total Length of Bwd Packets", "bwd_bytes"),
)


def network_feature_schema() -> FeatureSchema:
    return FeatureSchema(
        schema_name="network_attack_features",
        schema_version="1.0.0",
        features=(
            FeatureDefinition(
                name="duration_us", data_type="float", description="Flow duration, microseconds"
            ),
            *(
                FeatureDefinition(name=name, data_type="int", description=description)
                for name, description in (
                    ("fwd_packets", "Packets in initiating direction"),
                    ("bwd_packets", "Packets in reverse direction"),
                    ("fwd_bytes", "CIC flow-meter forward packet length total"),
                    ("bwd_bytes", "CIC flow-meter backward packet length total"),
                )
            ),
        ),
    )


class NetworkFlowInput(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, allow_inf_nan=False, hide_input_in_errors=True
    )
    duration_us: float = Field(gt=0)
    fwd_packets: int = Field(ge=0)
    bwd_packets: int = Field(ge=0)
    fwd_bytes: int = Field(ge=0)
    bwd_bytes: int = Field(ge=0)


class NetworkFeatureExtractor:
    def extract(self, record: SecurityRecord, *, state: IncidentState | None = None) -> FeatureSet:
        try:
            record = SecurityRecord.model_validate(record.model_dump(warnings=False))
            if record.record_type != "network_flow" or record.record_schema_version != "1.0.0":
                raise ValueError("Unsupported network record contract")
            payload = record.payload()
            if record.dataset_reference is not None:
                label = record.dataset_reference.dataset.label_field
                if label is not None:
                    payload.pop(label)
            source = NetworkFlowInput.model_validate(payload)
            return create_feature_set(
                feature_schema=network_feature_schema(),
                values=source.model_dump(),
                records=(record,),
                extractor_name="network_flow",
                extractor_version="1.0.0",
                state=state,
            )
        except (ValueError, TypeError):
            raise ValueError("Invalid network feature source") from None
