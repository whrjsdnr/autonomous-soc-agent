"""Account-disjoint evaluation and normal-only fitting; labels are never model inputs."""

import platform
from dataclasses import dataclass
from typing import Literal, Self

import numpy as np
import sklearn
from pydantic import model_validator
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from soc_agent.security_ai.anomaly_common import (
    AnomalyEvaluation,
    AnomalyPrediction,
    AnomalyScoreReference,
    AnomalyTrainingConfig,
    ScalerState,
    evaluate_anomaly,
)
from soc_agent.security_ai.authentication.aggregation import AuthenticationWindow
from soc_agent.security_ai.authentication.anomaly import (
    AuthenticationAnomalyDetector,
    AuthenticationInferenceProfile,
    AuthenticationModelContract,
    feature_matrix,
)
from soc_agent.security_ai.features import FeatureSet
from soc_agent.security_ai.features.models import Snapshot
from soc_agent.security_ai.splitting import SplitMetadata, split_examples


class AuthenticationExample(Snapshot):
    window: AuthenticationWindow
    label: Literal["normal", "anomalous"]

    @property
    def features(self) -> FeatureSet:
        return self.window.features

    @property
    def group_id(self) -> str:
        return self.window.account_id

    @property
    def row_id(self) -> str:
        # Length-prefix the account to avoid delimiter collisions.
        return f"{len(self.group_id)}:{self.group_id}:{self.window.started_at.isoformat()}"


def split_authentication(
    examples: tuple[AuthenticationExample, ...], seed: int = 42
) -> SplitMetadata:
    examples = tuple(AuthenticationExample.model_validate(e.model_dump()) for e in examples)
    events, sources = set(), set()
    for example in examples:
        for event_id in example.window.event_ids:
            if event_id in events:
                raise ValueError("An event occurs in multiple training windows")
            events.add(event_id)
        for source in example.features.provenance.sources:
            key = tuple(source.source_reference.model_dump().values())
            if key in sources:
                raise ValueError("A source record occurs in multiple training windows")
            sources.add(key)
    # The shared splitter unions account IDs and identical feature fingerprints,
    # requires five independent groups per class, and never falls back to random rows.
    return split_examples(examples, seed)


class AuthenticationTrainingMetadata(Snapshot):
    profile: AuthenticationInferenceProfile
    split: SplitMetadata
    baseline_indices: tuple[int, ...]
    baseline_label: Literal["normal"] = "normal"
    persistence: Literal["in_memory_only"] = "in_memory_only"
    validation: AnomalyEvaluation
    test: AnomalyEvaluation
    numpy_version: str
    sklearn_version: str
    python_version: str

    @model_validator(mode="after")
    def validate_population(self) -> Self:
        ids = self.baseline_indices
        if len(ids) != len(set(ids)) or not set(ids) <= set(self.split.train):
            raise ValueError("Baseline must be distinct training members")
        if len(ids) != self.profile.scaler.samples:
            raise ValueError("Baseline population differs from fitted profile")
        for evaluation, partition in (
            (self.validation, self.split.validation),
            (self.test, self.split.test),
        ):
            if evaluation.normal_support + evaluation.anomaly_support != len(partition):
                raise ValueError("Evaluation population differs from split")
        return self


@dataclass(frozen=True)
class AuthenticationTrainingResult:
    detector: AuthenticationAnomalyDetector
    metadata: AuthenticationTrainingMetadata

    def __post_init__(self) -> None:
        if self.detector.profile != self.metadata.profile:
            raise ValueError("Detector and metadata profiles differ")


def fit_authentication_anomaly(
    features: tuple[FeatureSet, ...],
    *,
    config: AnomalyTrainingConfig | None = None,
    model_version: str = "1.0.0",
) -> AuthenticationAnomalyDetector:
    """Fit explicitly supplied normal training features only; never evaluates holdouts."""
    config = AnomalyTrainingConfig.model_validate((config or AnomalyTrainingConfig()).model_dump())
    if len({f.input_fingerprint for f in features}) < 2:
        raise ValueError("At least two distinct normal training inputs required")
    baseline = feature_matrix(features).astype(np.float64)
    scaler = StandardScaler().fit(baseline)
    scaler_state = ScalerState(
        mean=tuple(scaler.mean_),
        scale=tuple(scaler.scale_),
        variance=tuple(scaler.var_),
        samples=int(scaler.n_samples_seen_),
    )
    scaled = scaler_state.transform(baseline)
    model = IsolationForest(
        n_estimators=config.n_estimators,
        max_samples=min(config.max_samples, len(features)),
        contamination=config.contamination,
        random_state=config.seed,
        n_jobs=config.n_jobs,
        max_features=1.0,
        bootstrap=False,
        warm_start=False,
    ).fit(scaled)
    reference = AnomalyScoreReference(
        sorted_measures=tuple(sorted(float(-v) for v in model.score_samples(scaled))),
        threshold=config.threshold,
        sklearn_offset=float(model.offset_),
    )
    profile = AuthenticationInferenceProfile(
        contract=AuthenticationModelContract(model_version=model_version),
        config=config,
        scaler=scaler_state,
        normalization=reference,
        fitted_max_samples=int(model.max_samples_),
    )
    detector = AuthenticationAnomalyDetector(profile=profile, _model=model)

    return detector


def train_authentication(
    examples: tuple[AuthenticationExample, ...],
    *,
    config: AnomalyTrainingConfig | None = None,
    model_version: str = "1.0.0",
) -> AuthenticationTrainingResult:
    examples = tuple(AuthenticationExample.model_validate(e.model_dump()) for e in examples)
    config = AnomalyTrainingConfig.model_validate((config or AnomalyTrainingConfig()).model_dump())
    split = split_authentication(examples, config.seed)
    indices = tuple(i for i in split.train if examples[i].label == "normal")
    if len({examples[i].features.input_fingerprint for i in indices}) < 2:
        raise ValueError("At least two distinct normal training inputs required")
    detector = fit_authentication_anomaly(
        tuple(examples[i].features for i in indices), config=config, model_version=model_version
    )
    profile = detector.profile

    def metrics(partition: tuple[int, ...]) -> AnomalyEvaluation:
        predictions = tuple(detector.predict(examples[i].features) for i in partition)
        return evaluate_anomaly(
            tuple(examples[i].label == "anomalous" for i in partition),
            tuple(
                AnomalyPrediction.model_validate(
                    p.model_dump(include=set(AnomalyPrediction.model_fields))
                )
                for p in predictions
            ),
        )

    return AuthenticationTrainingResult(
        detector=detector,
        metadata=AuthenticationTrainingMetadata(
            profile=profile,
            split=split,
            baseline_indices=indices,
            validation=metrics(split.validation),
            test=metrics(split.test),
            numpy_version=np.__version__,
            sklearn_version=sklearn.__version__,
            python_version=platform.python_version(),
        ),
    )
