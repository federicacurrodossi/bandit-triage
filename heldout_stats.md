# Held-out evaluation

Sources (2 files): `heldout_b101.json`, `heldout_b608.json`

> A real evaluation on findings the model was never trained on, hand-labeled with the same policy as the training data. Unlike the training-set accuracy in `dataset_stats.md`, this measures how well the model generalizes to unseen code from a different project.

## Summary

| Metric | Value |
|--------|-------|
| Findings | 57 (22 true, 35 false) |
| Accuracy | 47/57 (82%) |
| Precision (true_positive) | 0.80 |
| Recall (true_positive) | 0.73 |
| F1 score | 0.76 |

## Confusion matrix (overall)

| | predicted true | predicted false |
|--|--|--|
| **actual true** | 16 | 6 |
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
- **Model says:** likely_false_positive (p=0.06)
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
- **Model says:** likely_true_positive (p=0.72)
- **Top signal:** has_tainted_input (contribution = +2.91)

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

- **Accuracy:** 21/25 (84%)
- **Precision / Recall / F1:** 0.25 / 0.50 / 0.33
- **Confusion:** TP 1, FP 3, TN 20, FN 1

**Misclassified (4):** the informative cases, worth reading to see where the model's signals fall short.

#### `target_django/django/db/backends/base/operations.py:113`

- **Hand label:** false_positive
- **Model says:** likely_true_positive (p=0.53)
- **Top signal:** confidence (contribution = +1.54)

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
- **Model says:** likely_true_positive (p=0.53)
- **Top signal:** confidence (contribution = +1.54)

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
- **Model says:** likely_true_positive (p=0.58)
- **Top signal:** confidence (contribution = +1.54)

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

#### `target_hackable/main.py:56`

- **Hand label:** true_positive
- **Model says:** likely_false_positive (p=0.28)
- **Top signal:** rule_B101 (contribution = -0.85)

```python
51	
52	@app.route('/api/v1.0/storeAPI/<item>', methods=['GET'])
53	def searchAPI(item):
54	    g.db = connect_db()
55	    #curs = g.db.execute("SELECT * FROM shop_items WHERE name=?", item) #The safe way to actually get data from db
56	    curs = g.db.execute("SELECT * FROM shop_items WHERE name = '%s'" %item)
57	    results = [dict(name=row[0], quantity=row[1], price=row[2]) for row in curs.fetchall()]
58	    g.db.close()
59	    return jsonify(results)
60	
61	@app.errorhandler(404)
```

