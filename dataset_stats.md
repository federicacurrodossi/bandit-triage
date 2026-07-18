# Dataset balance and training-set accuracy

> **Note:** accuracy here is *training-set* accuracy — a diagnostic measured on the same data the model learned from, so it looks optimistic. A real evaluation needs a separate held-out test set. Use it to spot unbalanced rules or ones the model struggles with, not to claim real-world accuracy.

| Rule | True | False | Total | Accuracy | Balance |
|------|-----:|------:|------:|:--------:|---------|
| B101 | 12 | 10 | 22 | 22/22 (100%) | ok |
| B105 | 12 | 13 | 25 | 21/25 (84%) | ok |
| B301 | 1 | 1 | 2 | 2/2 (100%) | need ~18 more to reach 20 |
| B602 | 2 | 2 | 4 | 4/4 (100%) | need ~16 more to reach 20 |
| B608 | 1 | 2 | 3 | 3/3 (100%) | need ~17 more to reach 20 |
| B614 | 1 | 1 | 2 | 2/2 (100%) | need ~18 more to reach 20 |
| B615 | 1 | 1 | 2 | 2/2 (100%) | need ~18 more to reach 20 |
| **TOTAL** | **30** | **30** | **60** | **56/60 (93%)** | |

- **Rules covered:** 7
- **Overall:** 30 true_positive, 30 false_positive
- **Misclassified:** 4 (see `misclassified.md`)
