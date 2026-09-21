"""Bounded numerical IsolationForest format; no Python object reconstruction."""

from typing import Annotated, Literal, Self

import numpy as np
import sklearn
from pydantic import Field, model_validator
from sklearn.ensemble import IsolationForest

from soc_agent.security_ai.features.models import Snapshot

Integer = Annotated[int, Field(strict=True)]
Finite = Annotated[float, Field(strict=True, allow_inf_nan=False)]


def average_path_length(counts: np.ndarray) -> np.ndarray:
    """sklearn 1.9.1 unsuccessful-BST approximation, including n=1/2 cases."""
    result = np.zeros(counts.shape)
    result[counts == 2] = 1.0
    mask = counts > 2
    n = counts[mask]
    result[mask] = 2.0 * (np.log(n - 1.0) + np.euler_gamma) - 2.0 * (n - 1.0) / n
    return result


class NumericTree(Snapshot):
    left: tuple[Integer, ...] = Field(min_length=1, max_length=131071)
    right: tuple[Integer, ...]
    feature: tuple[Integer, ...]
    threshold: tuple[Finite, ...]
    samples: tuple[Integer, ...]

    def depths(self, features: int, max_samples: int) -> np.ndarray:
        n = len(self.left)
        if any(len(v) != n for v in (self.right, self.feature, self.threshold, self.samples)):
            raise ValueError("Tree array lengths differ")
        if n > 2 * max_samples - 1 or self.samples[0] != max_samples:
            raise ValueError("Tree population differs from fitted max_samples")
        depths = np.zeros(n, dtype=np.int64)
        depths[0] = 1
        # Preorder indices: children always follow parents; every node has one parent.
        for i in range(n):
            if depths[i] == 0 or not 1 <= self.samples[i] <= max_samples:
                raise ValueError("Unreachable node or invalid population")
            left, right = self.left[i], self.right[i]
            if left == right == -1:
                if self.feature[i] != -2 or self.threshold[i] != -2.0:
                    raise ValueError("Invalid leaf sentinel")
                continue
            if not 0 <= self.feature[i] < features or not i < left < right < n:
                raise ValueError("Invalid child/feature index")
            if depths[left] or depths[right]:
                raise ValueError("Tree node has multiple parents")
            if self.samples[left] + self.samples[right] != self.samples[i]:
                raise ValueError("Child populations differ")
            depths[left] = depths[right] = depths[i] + 1
        if max(depths) > int(np.ceil(np.log2(max_samples))) + 1:
            raise ValueError("Tree exceeds IsolationForest depth bound")
        return depths


class NumericForest(Snapshot):
    format: Literal["isolation_forest_numeric:v1"] = "isolation_forest_numeric:v1"
    source_sklearn: Literal["1.9.1"] = "1.9.1"
    n_features: int = Field(strict=True, ge=1, le=64)
    max_samples: int = Field(strict=True, ge=2, le=65536)
    trees: tuple[NumericTree, ...] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_trees(self) -> Self:
        if sum(len(t.left) for t in self.trees) > 200000:
            raise ValueError("Forest exceeds node budget")
        for tree in self.trees:
            tree.depths(self.n_features, self.max_samples)
        return self

    @classmethod
    def from_fitted(cls, model: IsolationForest) -> "NumericForest":
        if type(model) is not IsolationForest or sklearn.__version__ != "1.9.1":
            raise ValueError("Unsupported estimator or sklearn export version")
        if model.max_features != 1.0 or model.bootstrap or model.warm_start:
            raise ValueError("Unsupported forest configuration")
        trees = []
        for estimator, indices in zip(model.estimators_, model.estimators_features_, strict=True):
            if not np.array_equal(indices, np.arange(model.n_features_in_)):
                raise ValueError("Feature subsampling is unsupported")
            tree = estimator.tree_
            trees.append(
                NumericTree(
                    left=tuple(map(int, tree.children_left)),
                    right=tuple(map(int, tree.children_right)),
                    feature=tuple(map(int, tree.feature)),
                    threshold=tuple(map(float, tree.threshold)),
                    samples=tuple(map(int, tree.n_node_samples)),
                )
            )
        return cls(
            n_features=int(model.n_features_in_),
            max_samples=int(model.max_samples_),
            trees=tuple(trees),
        )

    def score_samples(self, matrix: np.ndarray) -> np.ndarray:
        x = np.asarray(matrix, dtype=np.float32)
        if x.ndim != 2 or x.shape[1] != self.n_features or not np.isfinite(x).all():
            raise ValueError("Invalid forest input")
        depths = np.zeros(len(x), order="f")
        for tree in self.trees:
            lengths = tree.depths(self.n_features, self.max_samples)
            corrections = average_path_length(np.asarray(tree.samples))
            for row, values in enumerate(x):
                node = 0
                for _ in range(len(tree.left)):
                    if tree.left[node] == -1:
                        break
                    node = (
                        tree.left[node]
                        if float(values[tree.feature[node]]) <= tree.threshold[node]
                        else tree.right[node]
                    )
                depths[row] += lengths[node] + corrections[node] - 1.0
        denominator = len(self.trees) * average_path_length(np.asarray([self.max_samples]))
        return -(
            2 ** (-np.divide(depths, denominator, out=np.ones_like(depths), where=denominator != 0))
        )
