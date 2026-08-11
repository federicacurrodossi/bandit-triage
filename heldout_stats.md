# Held-out evaluation

Sources (2 files): `heldout_b101.json`, `heldout_b608.json`

> A real evaluation on findings the model was never trained on, hand-labeled with the same policy as the training data. Unlike the training-set accuracy in `dataset_stats.md`, this measures how well the model generalizes to unseen code from a different project.

## Summary

| Metric | Value |
|--------|-------|
| Findings | 57 (22 true, 35 false) |
| Accuracy | 47/57 (82%) |
| Precision (true_positive) | 0.83 |
| Recall (true_positive) | 0.68 |
| F1 score | 0.75 |

## Confusion matrix (overall)

| | predicted true | predicted false |
|--|--|--|
| **actual true** | 15 | 7 |
| **actual false** | 3 | 32 |

## Results by rule

### B101

- **Accuracy:** 26/32 (81%)
- **Precision / Recall / F1:** 0.94 / 0.75 / 0.83
- **Confusion:** TP 15, FP 1, TN 11, FN 5

**Misclassified (6):** the informative cases, worth reading to see where the model's signals fall short.

#### `target_django/django/test/client.py:92`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.06)
- **Top signal:** is_test_file (contribution = -3.72)

```python
91             size = self.__len
92         assert (
93             self.__len >= size
94         ), "Cannot read more than the available bytes from the HTTP incoming data."
95         content = self.__content.read(size)
```

#### `target_django/django/test/client.py:105`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.06)
- **Top signal:** is_test_file (contribution = -3.72)

```python
104             size = self.__len
105         assert (
106             self.__len >= size
107         ), "Cannot read more than the available bytes from the HTTP incoming data."
108         content = self.__content.readline(size)
```

#### `target_django/django/test/runner.py:998`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.06)
- **Top signal:** is_test_file (contribution = -3.72)

```python
997             if os.path.exists(label_as_path):
998                 assert tests is None
999                 raise RuntimeError(
```

#### `target_django/django/test/utils.py:577`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.06)
- **Top signal:** is_test_file (contribution = -3.72)

```python
576             # Hack used when instantiating from SimpleTestCase.setUpClass.
577             assert not kwargs
578             self.operations = args[0]
```

#### `target_django/django/test/utils.py:580`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.06)
- **Top signal:** is_test_file (contribution = -3.72)

```python
579         else:
580             assert not args
581             self.operations = list(kwargs.items())
```

#### `target_django/tests/auth_tests/test_management.py:68`

- **Hand label:** false_positive
- **Model says:** likely_true_positive (p=0.86)
- **Top signal:** has_tainted_input (contribution = +3.48)

```python
67             def mock_input(prompt):
68                 assert "__proxy__" not in prompt
69                 response = None
```

### B608

- **Accuracy:** 21/25 (84%)
- **Precision / Recall / F1:** 0.00 / 0.00 / 0.00
- **Confusion:** TP 0, FP 2, TN 21, FN 2

**Misclassified (4):** the informative cases, worth reading to see where the model's signals fall short.

#### `target_django/django/db/backends/base/operations.py:113`

- **Hand label:** false_positive
- **Model says:** likely_true_positive (p=0.51)
- **Top signal:** confidence (contribution = +1.69)

```python
112         cache_key = self.quote_name("cache_key")
113         return f"SELECT {cache_key} FROM %s ORDER BY {cache_key} LIMIT 1 OFFSET %%s"
114
```

#### `target_django/django/db/backends/oracle/operations.py:73`

- **Hand label:** false_positive
- **Model says:** likely_true_positive (p=0.51)
- **Top signal:** confidence (contribution = +1.69)

```python
72         return (
73             f"SELECT {cache_key} "
74             f"FROM %s "
75             f"ORDER BY {cache_key} OFFSET %%s ROWS FETCH FIRST 1 ROWS ONLY"
76         )
```

#### `target_hackable/main.py:25`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.09)
- **Top signal:** rule_B608 (contribution = -1.27)

```python
24         g.db = connect_db()
25         cur = g.db.execute("SELECT * FROM employees WHERE username = '%s' AND password = '%s'" %(uname, hash_pass(pword)))
26         if cur.fetchone():
```

#### `target_hackable/main.py:56`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.09)
- **Top signal:** rule_B608 (contribution = -1.27)

```python
55     #curs = g.db.execute("SELECT * FROM shop_items WHERE name=?", item) #The safe way to actually get data from db
56     curs = g.db.execute("SELECT * FROM shop_items WHERE name = '%s'" %item)
57     results = [dict(name=row[0], quantity=row[1], price=row[2]) for row in curs.fetchall()]
```

