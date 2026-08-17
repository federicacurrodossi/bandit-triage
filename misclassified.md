# Misclassified findings

_Cases where the model's prediction disagrees with your hand label._

> A disagreement is often a genuinely **ambiguous** finding (fine to miss), not necessarily a labeling error. Use this to decide, per case, whether it's healthy ambiguity (leave it) or a label worth revising.

**Total misclassified: 1**

## B105 — 1 misclassified

### `target_insecure_app/app/config.py:13`

- **Your label:** false_positive
- **Model says:** likely_true_positive (p=0.88)
- **Flagged value:** `John Ripper` (secret_score = 0.72)
- **Top signal:** secret_score (contribution = +1.24)

```python
12 
13 SUPER_SECRET_NAME = "John Ripper"  # FIXME: os.getenv("SUPER_SECRET_NAME")
14
```

