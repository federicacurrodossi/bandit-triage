# Dataset balance and training-set accuracy

> **Note:** accuracy here is *training-set* accuracy — a diagnostic measured on the same data the model learned from, so it looks optimistic. A real evaluation needs a separate held-out test set. Use it to spot unbalanced rules or ones the model struggles with, not to claim real-world accuracy.

| Rule | True | False | Total | Accuracy | Balance |
|------|-----:|------:|------:|:--------:|---------|
| B101 | 12 | 10 | 22 | 22/22 (100%) | ok |
| B105 | 12 | 13 | 25 | 24/25 (96%) | ok |
| B608 | 13 | 10 | 23 | 23/23 (100%) | ok |
| **TOTAL** | **37** | **33** | **70** | **69/70 (99%)** | |

- **Rules covered:** 3
- **Overall:** 37 true_positive, 33 false_positive
- **Misclassified:** 1 (see `misclassified.md`)
