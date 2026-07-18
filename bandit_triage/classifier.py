"""
A small logistic regression classifier predicting whether a Bandit finding
is a true positive (worth fixing now) or a false positive (safe to
deprioritize). Saved as plain JSON, not pickle -- consistent with treating
model files as untrusted-by-default data, not something to blindly
deserialize.
"""
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

import numpy as np

from .features import FEATURE_NAMES


@dataclass
class Prediction:
    true_positive_probability: float
    label: str  # "likely_true_positive" or "likely_false_positive"
    contributions: List[dict]


class TriageClassifier:
    def __init__(self, weights: np.ndarray, bias: float, mean: np.ndarray, std: np.ndarray):
        self.weights = weights
        self.bias = bias
        self.mean = mean
        self.std = std

    @classmethod
    def train(cls, X: np.ndarray, y: np.ndarray) -> "TriageClassifier":
        from sklearn.linear_model import LogisticRegression

        mean = X.mean(axis=0)
        std = X.std(axis=0)
        std[std == 0] = 1.0
        X_scaled = (X - mean) / std

        model = LogisticRegression(max_iter=1000)
        model.fit(X_scaled, y)

        return cls(weights=model.coef_[0], bias=float(model.intercept_[0]), mean=mean, std=std)

    def predict(self, x: np.ndarray, threshold: float = 0.5) -> Prediction:
        x_scaled = (x - self.mean) / self.std
        z = np.dot(self.weights, x_scaled) + self.bias
        prob = 1.0 / (1.0 + np.exp(-z))

        contributions = []
        for name, w, xv, raw in zip(FEATURE_NAMES, self.weights, x_scaled, x):
            contributions.append({
                "feature": name,
                "contribution": float(w * xv),
                "raw_value": float(raw),
            })
        contributions.sort(key=lambda c: c["contribution"], reverse=True)

        label = "likely_true_positive" if prob >= threshold else "likely_false_positive"
        return Prediction(true_positive_probability=float(prob), label=label, contributions=contributions)

    def save(self, path: str):
        data = {
            "weights": self.weights.tolist(),
            "bias": self.bias,
            "mean": self.mean.tolist(),
            "std": self.std.tolist(),
            "feature_names": FEATURE_NAMES,
        }
        Path(path).write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, path: str) -> "TriageClassifier":
        data = json.loads(Path(path).read_text())
        return cls(
            weights=np.array(data["weights"]),
            bias=data["bias"],
            mean=np.array(data["mean"]),
            std=np.array(data["std"]),
        )
