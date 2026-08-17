# Held-out evaluation

Sources (2 files): `heldout_b101.json`, `heldout_b608.json`

> A real evaluation on findings the model was never trained on, hand-labeled with the same policy as the training data. Unlike the training-set accuracy in `dataset_stats.md`, this measures how well the model generalizes to unseen code from a different project.

## Summary

| Metric | Value |
|--------|-------|
| Findings | 57 (22 true, 35 false) |
| Accuracy | 48/57 (84%) |
| Precision (true_positive) | 0.81 |
| Recall (true_positive) | 0.77 |
| F1 score | 0.79 |

## Confusion matrix (overall)

| | predicted true | predicted false |
|--|--|--|
| **actual true** | 17 | 5 |
| **actual false** | 4 | 31 |

## Results by rule

### B101

- **Accuracy:** 26/32 (81%)
- **Precision / Recall / F1:** 0.94 / 0.75 / 0.83
- **Confusion:** TP 15, FP 1, TN 11, FN 5

**Misclassified (6):** the informative cases, worth reading to see where the model's signals fall short.

#### `target_django/django/test/client.py:92`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.07)
- **Top signal:** is_test_file (contribution = -3.28)

```python
87	        if not self.read_started:
88	            self.__content.seek(0)
89	            self.read_started = True
90	        if size == -1 or size is None:
91	            size = self.__len
92	        assert (
93	            self.__len >= size
94	        ), "Cannot read more than the available bytes from the HTTP incoming data."
95	        content = self.__content.read(size)
96	        self.__len -= len(content)
97	        return content
```

#### `target_django/django/test/client.py:105`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.07)
- **Top signal:** is_test_file (contribution = -3.28)

```python
100	        if not self.read_started:
101	            self.__content.seek(0)
102	            self.read_started = True
103	        if size == -1 or size is None:
104	            size = self.__len
105	        assert (
106	            self.__len >= size
107	        ), "Cannot read more than the available bytes from the HTTP incoming data."
108	        content = self.__content.readline(size)
109	        self.__len -= len(content)
110	        return content
```

#### `target_django/django/test/runner.py:998`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.02)
- **Top signal:** is_test_file (contribution = -3.28)

```python
993	        if is_importable:
994	            if not is_package:
995	                return tests
996	        elif not os.path.isdir(label_as_path):
997	            if os.path.exists(label_as_path):
998	                assert tests is None
999	                raise RuntimeError(
1000	                    f"One of the test labels is a path to a file: {label!r}, "
1001	                    f"which is not supported. Use a dotted module name or "
1002	                    f"path to a directory instead."
1003	                )
```

#### `target_django/django/test/utils.py:577`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.07)
- **Top signal:** is_test_file (contribution = -3.28)

```python
572	    """
573	
574	    def __init__(self, *args, **kwargs):
575	        if args:
576	            # Hack used when instantiating from SimpleTestCase.setUpClass.
577	            assert not kwargs
578	            self.operations = args[0]
579	        else:
580	            assert not args
581	            self.operations = list(kwargs.items())
582	        super(override_settings, self).__init__()
```

#### `target_django/django/test/utils.py:580`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.07)
- **Top signal:** is_test_file (contribution = -3.28)

```python
575	        if args:
576	            # Hack used when instantiating from SimpleTestCase.setUpClass.
577	            assert not kwargs
578	            self.operations = args[0]
579	        else:
580	            assert not args
581	            self.operations = list(kwargs.items())
582	        super(override_settings, self).__init__()
583	
584	    def save_options(self, test_func):
585	        if test_func._modified_settings is None:
```

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

- **Accuracy:** 22/25 (88%)
- **Precision / Recall / F1:** 0.40 / 1.00 / 0.57
- **Confusion:** TP 2, FP 3, TN 20, FN 0

**Misclassified (3):** the informative cases, worth reading to see where the model's signals fall short.

#### `target_django/django/db/backends/base/operations.py:113`

- **Hand label:** false_positive
- **Model says:** likely_true_positive (p=0.72)
- **Top signal:** confidence (contribution = +2.77)

```python
108	
109	        This is used by the 'db' cache backend to determine where to start
110	        culling.
111	        """
112	        cache_key = self.quote_name("cache_key")
113	        return f"SELECT {cache_key} FROM %s ORDER BY {cache_key} LIMIT 1 OFFSET %%s"
114	
115	    def unification_cast_sql(self, output_field):
116	        """
117	        Given a field instance, return the SQL that casts the result of a union
118	        to that type. The resulting string should contain a '%s' placeholder
```

#### `target_django/django/db/backends/oracle/operations.py:73`

- **Hand label:** false_positive
- **Model says:** likely_true_positive (p=0.72)
- **Top signal:** confidence (contribution = +2.77)

```python
68	    }
69	
70	    def cache_key_culling_sql(self):
71	        cache_key = self.quote_name("cache_key")
72	        return (
73	            f"SELECT {cache_key} "
74	            f"FROM %s "
75	            f"ORDER BY {cache_key} OFFSET %%s ROWS FETCH FIRST 1 ROWS ONLY"
76	        )
77	
78	    # EXTRACT format cannot be passed in parameters.
```

#### `target_django/django/contrib/gis/db/backends/postgis/operations.py:212`

- **Hand label:** false_positive
- **Model says:** likely_true_positive (p=0.88)
- **Top signal:** confidence (contribution = +2.77)

```python
207	
208	            try:
209	                vtup = self.postgis_version_tuple()
210	            except ProgrammingError:
211	                raise ImproperlyConfigured(
212	                    'Cannot determine PostGIS version for database "%s" '
213	                    'using command "SELECT postgis_lib_version()". '
214	                    "GeoDjango requires at least PostGIS version 3.2. "
215	                    "Was the database created from a spatial database "
216	                    "template?" % self.connection.settings_dict["NAME"]
217	                )
```

