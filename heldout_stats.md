# Held-out evaluation

Sources (3 files): `heldout_b101.json`, `heldout_b608.json`, `heldout_keylogger_b608.json`

> A real evaluation on findings the model was never trained on, hand-labeled with the same policy as the training data. Unlike the training-set accuracy in `dataset_stats.md`, this measures how well the model generalizes to unseen code from a different project.

## Summary

| Metric | Value |
|--------|-------|
| Findings | 63 (28 true, 35 false) |
| Accuracy | 58/63 (92%) |
| Precision (true_positive) | 0.87 |
| Recall (true_positive) | 0.96 |
| F1 score | 0.92 |

## Confusion matrix (overall)

| | predicted true | predicted false |
|--|--|--|
| **actual true** | 27 | 1 |
| **actual false** | 4 | 31 |

## Results by rule

### B101

- **Accuracy:** 31/32 (97%)
- **Precision / Recall / F1:** 0.95 / 1.00 / 0.98
- **Confusion:** TP 20, FP 1, TN 11, FN 0

**Misclassified (1):** the informative cases, worth reading to see where the model's signals fall short.

#### `target_django/tests/auth_tests/test_management.py:68`

- **Hand label:** false_positive
- **Model says:** likely_true_positive (p=0.79)
- **Top signal:** has_tainted_input (contribution = +3.56)

```python
63	                    if callable(inputs["password"]):
64	                        return inputs["password"]()
65	                    return inputs["password"]
66	
67	            def mock_input(prompt):
68	                assert "__proxy__" not in prompt
69	                response = None
70	                for key, val in inputs.items():
71	                    if val == "KeyboardInterrupt":
72	                        raise KeyboardInterrupt
73	                    # get() fallback because sometimes 'key' is the actual
```

### B608

- **Accuracy:** 27/31 (87%)
- **Precision / Recall / F1:** 0.70 / 0.88 / 0.78
- **Confusion:** TP 7, FP 3, TN 20, FN 1

**Misclassified (4):** the informative cases, worth reading to see where the model's signals fall short.

#### `target_django/django/db/backends/base/operations.py:113`

- **Hand label:** false_positive
- **Model says:** likely_true_positive (p=0.72)
- **Top signal:** confidence (contribution = +2.77)

```python
112         cache_key = self.quote_name("cache_key")
113         return f"SELECT {cache_key} FROM %s ORDER BY {cache_key} LIMIT 1 OFFSET %%s"
114
```

#### `target_django/django/db/backends/oracle/operations.py:73`

- **Hand label:** false_positive
- **Model says:** likely_true_positive (p=0.72)
- **Top signal:** confidence (contribution = +2.77)

```python
72         return (
73             f"SELECT {cache_key} "
74             f"FROM %s "
75             f"ORDER BY {cache_key} OFFSET %%s ROWS FETCH FIRST 1 ROWS ONLY"
76         )
```

#### `target_django/django/contrib/gis/db/backends/postgis/operations.py:212`

- **Hand label:** false_positive
- **Model says:** likely_true_positive (p=0.88)
- **Top signal:** confidence (contribution = +2.77)

```python
211                 raise ImproperlyConfigured(
212                     'Cannot determine PostGIS version for database "%s" '
213                     'using command "SELECT postgis_lib_version()". '
214                     "GeoDjango requires at least PostGIS version 3.2. "
215                     "Was the database created from a spatial database "
216                     "template?" % self.connection.settings_dict["NAME"]
217                 )
```

#### `target_hackable/main.py:25`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.43)
- **Top signal:** rule_B101 (contribution = -0.98)

```python
24         g.db = connect_db()
25         cur = g.db.execute("SELECT * FROM employees WHERE username = '%s' AND password = '%s'" %(uname, hash_pass(pword)))
26         if cur.fetchone():
```

