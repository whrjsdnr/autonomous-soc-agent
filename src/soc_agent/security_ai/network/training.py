"""Deterministic grouped split, CPU baseline fitting, and untouched test evaluation."""

import hashlib
import platform
from dataclasses import dataclass
from typing import Self

import numpy as np
import sklearn
import xgboost as xgb
from pydantic import Field, field_validator, model_validator
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

from soc_agent._json import canonical_json_object
from soc_agent.security_ai.features.models import Snapshot
from soc_agent.security_ai.network.classifier import (
    ModelContract,
    NetworkAttackClassifier,
    feature_matrix,
)
from soc_agent.security_ai.network.dataset import PreparedDataset
from soc_agent.security_ai.splitting import SplitMetadata as SplitMetadata
from soc_agent.security_ai.splitting import split_examples


class TrainingConfig(Snapshot):
    seed: int = Field(default=42, ge=0, le=2147483647, strict=True)
    n_estimators: int = Field(default=40, ge=1, le=1000, strict=True)
    max_depth: int = Field(default=3, ge=1, le=16, strict=True)
    learning_rate: float = Field(default=0.1, gt=0, le=1)

    def parameters(self, num_classes: int) -> dict[str, object]:
        return dict(
            objective="multi:softprob",
            num_class=num_classes,
            max_depth=self.max_depth,
            eta=self.learning_rate,
            subsample=1.0,
            colsample_bytree=1.0,
            tree_method="hist",
            device="cpu",
            nthread=1,
            seed=self.seed,
            eval_metric="mlogloss",
        )


class PerClassMetric(Snapshot):
    label: str
    precision: float
    recall: float
    f1: float
    support: int


class ClassificationEvaluation(Snapshot):
    accuracy: float
    macro_precision: float
    macro_recall: float
    macro_f1: float
    weighted_f1: float
    per_class: tuple[PerClassMetric, ...]
    confusion_matrix: tuple[tuple[int, ...], ...]


def split_dataset(dataset: PreparedDataset, seed: int = 42) -> SplitMetadata:
    return split_examples(dataset.examples, seed)


def evaluate(
    y_true: list[int], y_pred: list[int], classes: tuple[str, ...]
) -> ClassificationEvaluation:
    labels = list(range(len(classes)))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    return ClassificationEvaluation(
        accuracy=float(accuracy_score(y_true, y_pred)),
        macro_precision=float(np.mean(precision)),
        macro_recall=float(np.mean(recall)),
        macro_f1=float(np.mean(f1)),
        weighted_f1=float(np.average(f1, weights=support)),
        per_class=tuple(
            PerClassMetric(
                label=label,
                precision=float(precision[i]),
                recall=float(recall[i]),
                f1=float(f1[i]),
                support=int(support[i]),
            )
            for i, label in enumerate(classes)
        ),
        confusion_matrix=tuple(
            tuple(int(v) for v in row) for row in confusion_matrix(y_true, y_pred, labels=labels)
        ),
    )


class TrainingMetadata(Snapshot):
    contract: ModelContract
    config: TrainingConfig
    hyperparameters: str
    dataset_name: str
    dataset_version: str
    dataset_files: tuple[tuple[str, str], ...]
    rejected_rows: tuple[str, ...]
    invalid_policy: str
    grouping: str
    split: SplitMetadata
    validation: ClassificationEvaluation
    test: ClassificationEvaluation
    numpy_version: str
    sklearn_version: str
    xgboost_version: str
    python_version: str

    @field_validator("hyperparameters", mode="before")
    @classmethod
    def canonical_parameters(cls, value: object) -> str:
        return canonical_json_object(value)

    @model_validator(mode="after")
    def validate_parameters(self) -> Self:
        if self.hyperparameters != canonical_json_object(
            self.config.parameters(len(self.contract.classes))
        ):
            raise ValueError("Training configuration and XGBoost parameters differ")
        return self


@dataclass(frozen=True)
class TrainingResult:
    classifier: NetworkAttackClassifier
    metadata: TrainingMetadata


def train(
    dataset: PreparedDataset, *, config: TrainingConfig | None = None, model_version: str = "1.0.0"
) -> TrainingResult:
    dataset = PreparedDataset.model_validate(dataset.model_dump(warnings=False))
    config = TrainingConfig.model_validate((config or TrainingConfig()).model_dump())
    split = split_dataset(dataset, config.seed)
    contract = ModelContract(
        model_version=model_version, classes=tuple(sorted({e.label for e in dataset.examples}))
    )
    matrix = feature_matrix(tuple(e.features for e in dataset.examples), contract)
    encoding = {label: i for i, label in enumerate(contract.classes)}
    y = np.asarray([encoding[e.label] for e in dataset.examples])

    def subset(indices: tuple[int, ...]) -> xgb.DMatrix:
        return xgb.DMatrix(
            matrix[list(indices)],
            label=y[list(indices)],
            nthread=1,
            feature_names=[f.name for f in contract.feature_schema.features],
        )

    booster = xgb.train(
        config.parameters(len(contract.classes)),
        subset(split.train),
        num_boost_round=config.n_estimators,
        evals=[(subset(split.validation), "validation")],
        verbose_eval=False,
    )
    booster.set_attr(feature_contract=canonical_json_object(contract.model_dump(mode="json")))

    def metrics(indices: tuple[int, ...]) -> ClassificationEvaluation:
        predictions = np.argmax(booster.predict(subset(indices)), axis=1)
        return evaluate(y[list(indices)].tolist(), predictions.tolist(), contract.classes)

    metadata = TrainingMetadata(
        contract=contract,
        config=config,
        hyperparameters=canonical_json_object(config.parameters(len(contract.classes))),
        dataset_name=dataset.dataset.dataset_name,
        dataset_version=dataset.dataset.dataset_version,
        dataset_files=tuple((f.name, f.sha256) for f in dataset.inspection.files),
        rejected_rows=dataset.rejected_rows,
        invalid_policy=dataset.invalid_policy,
        grouping=dataset.grouping,
        split=split,
        validation=metrics(split.validation),
        test=metrics(split.test),
        numpy_version=np.__version__,
        sklearn_version=sklearn.__version__,
        xgboost_version=xgb.__version__,
        python_version=platform.python_version(),
    )
    booster.set_attr(
        training_metadata_digest=hashlib.sha256(metadata.model_dump_json().encode()).hexdigest()
    )
    return TrainingResult(
        classifier=NetworkAttackClassifier(booster=booster, contract=contract), metadata=metadata
    )
