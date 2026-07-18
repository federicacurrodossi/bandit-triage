"""
Trains the triage classifier on the hand-labeled dataset.

    python3 train_classifier.py
"""
import numpy as np

from bandit_triage.classifier import TriageClassifier
from bandit_triage.features import extract_features
from bandit_triage.loader import load_labeled_data


def main():
    findings = load_labeled_data("data/labeled_findings.json")
    X = np.array([extract_features(f) for f in findings])
    y = np.array([1 if f.label == "true_positive" else 0 for f in findings])

    print(f"Loaded {len(y)} labeled findings "
          f"({sum(y == 1)} true positive, {sum(y == 0)} false positive)")

    model = TriageClassifier.train(X, y)
    model.save("model.json")
    print("Saved trained model to model.json")

    correct = 0
    for x, label in zip(X, y):
        pred = model.predict(x)
        predicted = 1 if pred.label == "likely_true_positive" else 0
        correct += predicted == label
    print(f"Training-set accuracy: {correct}/{len(y)} "
          f"(small dataset -- treat as a sanity check, not a real evaluation)")


if __name__ == "__main__":
    main()
