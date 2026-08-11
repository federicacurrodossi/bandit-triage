# Held-out evaluation

Source: `heldout/heldout_b101.json`

> A real evaluation on findings the model was never trained on, hand-labeled with the same policy as the training data. Unlike the training-set accuracy in `dataset_stats.md`, this measures how well the model generalizes to unseen code from a different project.

## Summary

| Metric | Value |
|--------|-------|
| Findings | 32 (20 true, 12 false) |
| Accuracy | 27/32 (84%) |
| Precision (true_positive) | 1.00 |
| Recall (true_positive) | 0.75 |
| F1 score | 0.86 |

## Confusion matrix (overall)

| | predicted true | predicted false |
|--|--|--|
| **actual true** | 15 | 5 |
| **actual false** | 0 | 12 |

## Results by rule

### B101

- **Accuracy:** 27/32 (84%)
- **Precision / Recall / F1:** 1.00 / 0.75 / 0.86
- **Confusion:** TP 15, FP 0, TN 12, FN 5

**Misclassified (5):** the informative cases, worth reading to see where the model's signals fall short.

#### `target_django/django/test/client.py:92`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.06)
- **Top signal:** is_test_file (contribution = -3.72)

```python
92         assert isinstance(data, dict)
```

#### `target_django/django/test/client.py:105`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.06)
- **Top signal:** is_test_file (contribution = -3.72)

```python
105         assert isinstance(extra, dict)
```

#### `target_django/django/test/runner.py:998`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.06)
- **Top signal:** is_test_file (contribution = -3.72)

```python
998         assert tests is None
```

#### `target_django/django/test/utils.py:577`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.06)
- **Top signal:** is_test_file (contribution = -3.72)

```python
577         assert not kwargs
```

#### `target_django/django/test/utils.py:580`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.06)
- **Top signal:** is_test_file (contribution = -3.72)

```python
580         assert not args
```

