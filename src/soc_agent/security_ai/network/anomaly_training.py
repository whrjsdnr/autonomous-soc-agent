"""Benign-only fitting after the existing grouped split; no persistence or tuning."""

import platform
from dataclasses import dataclass
from typing import Literal, Self

import numpy as np
import sklearn
from pydantic import Field, model_validator
from sklearn.ensemble import IsolationForest
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.preprocessing import StandardScaler

from soc_agent.security_ai.features import DatasetSchema
from soc_agent.security_ai.features.models import Snapshot
from soc_agent.security_ai.network.anomaly import (
    AnomalyInferenceProfile,
    AnomalyModelContract,
    AnomalyScoreReference,
    AnomalyTrainingConfig,
    NetworkAnomalyDetector,
    NetworkAnomalyPrediction,
    Probability,
    ScalerState,
)
from soc_agent.security_ai.network.dataset import PreparedDataset
from soc_agent.security_ai.network.preprocessing import feature_matrix
from soc_agent.security_ai.network.training import SplitMetadata, split_dataset


class AnomalyEvaluation(Snapshot):
    precision: Probability
    recall: Probability
    f1: Probability
    confusion_matrix: tuple[tuple[int, int], tuple[int, int]]
    normal_support: int = Field(ge=0)
    anomaly_support: int = Field(ge=0)
    roc_auc: Probability | None
    average_precision: Probability | None


def evaluate_anomaly(
    truth: tuple[bool, ...], predictions: tuple[NetworkAnomalyPrediction, ...]
) -> AnomalyEvaluation:
    if not truth or len(truth) != len(predictions) or any(type(y) is not bool for y in truth):
        raise ValueError("Evaluation requires aligned nonempty binary labels and predictions")
    predictions = tuple(
        NetworkAnomalyPrediction.model_validate(p.model_dump()) for p in predictions
    )
    y = np.asarray(truth, dtype=int)
    decisions = [p.is_anomaly for p in predictions]
    # Raw measure retains ranking beyond the empirical percentile's saturated tails.
    scores = [p.raw_anomaly_measure for p in predictions]
    precision, recall, f1, _ = precision_recall_fscore_support(
        y, decisions, average="binary", zero_division=0
    )
    both_classes = len(set(truth)) == 2
    matrix = confusion_matrix(y, decisions, labels=[0, 1])
    return AnomalyEvaluation(
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
        confusion_matrix=tuple(tuple(int(v) for v in row) for row in matrix),
        normal_support=int(np.count_nonzero(y == 0)),
        anomaly_support=int(np.count_nonzero(y == 1)),
        roc_auc=float(roc_auc_score(y, scores)) if both_classes else None,
        average_precision=float(average_precision_score(y, scores)) if both_classes else None,
    )


class AnomalyTrainingMetadata(Snapshot):
    """Artifact contract only; serialized metadata cannot reconstruct a forest."""

    profile: AnomalyInferenceProfile
    dataset: DatasetSchema
    dataset_files: tuple[tuple[str, str], ...]
    rejected_rows: tuple[str, ...]
    invalid_policy: Literal["reject", "drop"]
    grouping: str
    split: SplitMetadata
    baseline_indices: tuple[int, ...]
    baseline_label: Literal["BENIGN"] = "BENIGN"
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
            raise ValueError("Baseline rows must be distinct members of the training partition")
        if len(ids) != self.profile.scaler.samples:
            raise ValueError("Baseline population differs from fitted profile")
        if self.validation.normal_support + self.validation.anomaly_support != len(
            self.split.validation
        ):
            raise ValueError("Validation population differs from split")
        if self.test.normal_support + self.test.anomaly_support != len(self.split.test):
            raise ValueError("Test population differs from split")
        return self


@dataclass(frozen=True)
class AnomalyTrainingResult:
    detector: NetworkAnomalyDetector
    metadata: AnomalyTrainingMetadata

    def __post_init__(self) -> None:
        if self.detector.profile != self.metadata.profile:
            raise ValueError("Detector profile and training metadata differ")


def train_anomaly(
    dataset: PreparedDataset,
    *,
    config: AnomalyTrainingConfig | None = None,
    model_version: str = "1.0.0",
) -> AnomalyTrainingResult:
    dataset = PreparedDataset.model_validate(dataset.model_dump(warnings=False))
    config = AnomalyTrainingConfig.model_validate((config or AnomalyTrainingConfig()).model_dump())
    split = split_dataset(dataset, config.seed)
    indices = tuple(i for i in split.train if dataset.examples[i].label == "BENIGN")
    if (
        len(indices) < 2
        or len({dataset.examples[i].features.input_fingerprint for i in indices}) < 2
    ):
        raise ValueError("At least two distinct BENIGN training inputs are required")
    contract = AnomalyModelContract(model_version=model_version)
    baseline = feature_matrix(
        tuple(dataset.examples[i].features for i in indices), contract
    ).astype(np.float64)
    scaler = StandardScaler(with_mean=True, with_std=True).fit(baseline)
    scaler_state = ScalerState(
        mean=tuple(float(v) for v in scaler.mean_),
        scale=tuple(float(v) for v in scaler.scale_),
        variance=tuple(float(v) for v in scaler.var_),
        samples=int(scaler.n_samples_seen_),
    )
    scaled = scaler_state.transform(baseline)
    model = IsolationForest(
        n_estimators=config.n_estimators,
        max_samples=min(config.max_samples, len(indices)),
        contamination=config.contamination,
        random_state=config.seed,
        n_jobs=config.n_jobs,
        max_features=1.0,
        bootstrap=False,
        warm_start=False,
    )
    model.fit(scaled)  # No y/labels are passed to unsupervised fitting.
    reference = AnomalyScoreReference(
        sorted_measures=tuple(sorted(float(-value) for value in model.score_samples(scaled))),
        threshold=config.threshold,
        sklearn_offset=float(model.offset_),
    )
    profile = AnomalyInferenceProfile(
        contract=contract,
        config=config,
        scaler=scaler_state,
        normalization=reference,
        fitted_max_samples=int(model.max_samples_),
    )
    detector = NetworkAnomalyDetector(profile=profile, _model=model)

    def metrics(partition: tuple[int, ...]) -> AnomalyEvaluation:
        return evaluate_anomaly(
            tuple(dataset.examples[i].label != "BENIGN" for i in partition),
            tuple(detector.predict(dataset.examples[i].features) for i in partition),
        )

    metadata = AnomalyTrainingMetadata(
        profile=profile,
        dataset=dataset.dataset,
        dataset_files=tuple((f.name, f.sha256) for f in dataset.inspection.files),
        rejected_rows=dataset.rejected_rows,
        invalid_policy=dataset.invalid_policy,
        grouping=dataset.grouping,
        split=split,
        baseline_indices=indices,
        validation=metrics(split.validation),
        test=metrics(split.test),
        numpy_version=np.__version__,
        sklearn_version=sklearn.__version__,
        python_version=platform.python_version(),
    )
    return AnomalyTrainingResult(detector=detector, metadata=metadata)
