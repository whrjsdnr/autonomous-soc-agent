"""DNS9 training/extraction evidence inspection; never an inference permission.

Published feature descriptions are not a byte-for-byte extractor or model/scaler
training provenance. Preserve this distinction instead of guessing nine features.
"""

import hashlib
from pathlib import Path
from typing import Literal

from pydantic import Field

from soc_agent.security_ai.research.dns import catalogue
from soc_agent.security_ai.research.environment import read_local
from soc_agent.security_ai.research.models import Frozen, digest


class TrainingExtractionReview(Frozen):
    contract: Literal["soc-dns9-training-extraction-review:v1"]
    status: Literal["INCOMPLETE"]
    upstream_reference: str
    schema_version: str
    feature_names: tuple[str, ...] = Field(min_length=9, max_length=9)
    source_files: dict[str, str]
    feature_units: dict[str, str]
    upstream_documented_semantics: dict[str, str]
    upstream_extractor: None
    golden_raw_query_feature_pairs: tuple = Field(max_length=0)
    missing: tuple[str, ...] = Field(min_length=1)
    authority: Literal["RESEARCH_REVIEW_ONLY_NO_INFERENCE_OR_EXECUTION_GRANT"]


def inspect_training(ml_root: Path | None = None) -> dict:
    review = TrainingExtractionReview.model_validate_json(
        read_local(Path(__file__).with_name("dns9_training_contract.json"), 32768)
    )
    model = catalogue()["model"]
    if (
        list(review.feature_names) != model["feature_names"]
        or review.schema_version != model["feature_schema_version"]
        or set(review.feature_units) != set(review.feature_names)
    ):
        raise ValueError("DNS9_TRAINING_SCHEMA_MISMATCH")
    sources = {}
    if ml_root:
        for name, pin in review.source_files.items():
            path = Path(name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("DNS9_TRAINING_SOURCE_SCOPE")
            body = read_local(ml_root / path, 4 * 1024**2)
            if hashlib.sha256(body).hexdigest() != pin:
                raise ValueError("DNS9_TRAINING_SOURCE_CHANGED")
            sources[name] = pin
    return dict(
        status="INCOMPLETE",
        operational_inference="BLOCKED",
        schema_version=review.schema_version,
        feature_names=list(review.feature_names),
        model_sha256=model["artifacts"]["model_path"]["sha256"],
        feature_contract_digest=model["feature_contract_digest"],
        source_files=sources,
        source_validation="VERIFIED_HASHES" if ml_root else "NOT_CHECKED",
        missing=list(review.missing),
        upstream_reference=review.upstream_reference,
        contract_digest=digest(review.model_dump(mode="json")),
        raw_dns_collection="INDEPENDENT_OF_DNS9_MODEL_ELIGIBILITY",
        model_action_granted=False,
    )
