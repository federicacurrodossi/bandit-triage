# Misclassified findings

_Cases where the model's prediction disagrees with your hand label._

> A disagreement is often a genuinely **ambiguous** finding (fine to miss), not necessarily a labeling error. Use this to decide, per case, whether it's healthy ambiguity (leave it) or a label worth revising.

**Total misclassified: 2**

## B105 — 1 misclassified

### `target_insecure_app/app/config.py:13`

- **Your label:** false_positive
- **Model says:** likely_true_positive (p=0.87)
- **Flagged value:** `John Ripper` (secret_score = 0.72)
- **Top signal:** secret_score (contribution = +1.27)

```python
12 
13 SUPER_SECRET_NAME = "John Ripper"  # FIXME: os.getenv("SUPER_SECRET_NAME")
14
```

## B608 — 1 misclassified

### `./constructed_examples/sql_injection_examples.py:87`

- **Your label:** true_positive
- **Model says:** likely_false_positive (p=0.24)
- **Top signal:** rule_B101 (contribution = -0.85)

```python
86     # parameterization can't protect a table name, so this is genuinely unsafe
87     cur.execute(f"SELECT COUNT(*) FROM {table}")
88     return str(cur.fetchone())
```

