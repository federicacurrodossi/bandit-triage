# Misclassified findings

_Cases where the model's prediction disagrees with your hand label._

> A disagreement is often a genuinely **ambiguous** finding (fine to miss), not necessarily a labeling error. Use this to decide, per case, whether it's healthy ambiguity (leave it) or a label worth revising.

**Total misclassified: 4**

## B105 — 4 misclassified

### `target_flask/src/flask/app.py:211`

- **Your label:** false_positive
- **Model says:** likely_true_positive (p=0.54)
- **Flagged value:** `None` (secret_score = 0.38)
- **Top signal:** is_test_file (contribution = +1.44)

```python
210             "PROPAGATE_EXCEPTIONS": None,
211             "SECRET_KEY": None,
212             "SECRET_KEY_FALLBACKS": None,
213             "PERMANENT_SESSION_LIFETIME": timedelta(days=31),
214             "USE_X_SENDFILE": False,
215             "TRUSTED_HOSTS": None,
216             "SERVER_NAME": None,
217             "APPLICATION_ROOT": "/",
218             "SESSION_COOKIE_NAME": "session",
219             "SESSION_COOKIE_DOMAIN": None,
220             "SESSION_COOKIE_PATH": None,
221             "SESSION_COOKIE_HTTPONLY": True,
222             "SESSION_COOKIE_SECURE": False,
223             "SESSION_COOKIE_PARTITIONED": False,
224             "SESSION_COOKIE_SAMESITE": None,
225             "SESSION_REFRESH_EACH_REQUEST": True,
226             "MAX_CONTENT_LENGTH": None,
227             "MAX_FORM_MEMORY_SIZE": 500_000,
228             "MAX_FORM_PARTS": 1_000,
229             "SEND_FILE_MAX_AGE_DEFAULT": None,
230             "TRAP_BAD_REQUEST_ERRORS": None,
231             "TRAP_HTTP_EXCEPTIONS": False,
232             "EXPLAIN_TEMPLATE_LOADING": False,
233             "PREFERRED_URL_SCHEME": "http",
234             "TEMPLATES_AUTO_RELOAD": None,
235             "MAX_COOKIE_SIZE": 4093,
236             "PROVIDE_AUTOMATIC_OPTIONS": True,
237         }
238     )
239 
240     #: The class that is used for request objects.  See :class:`~flask.Request`
241     #: for more information.
242     request_class: type[Request] = Request
```

### `target_flask/src/flask/app.py:212`

- **Your label:** false_positive
- **Model says:** likely_true_positive (p=0.54)
- **Flagged value:** `None` (secret_score = 0.38)
- **Top signal:** is_test_file (contribution = +1.44)

```python
211             "SECRET_KEY": None,
212             "SECRET_KEY_FALLBACKS": None,
213             "PERMANENT_SESSION_LIFETIME": timedelta(days=31),
214             "USE_X_SENDFILE": False,
215             "TRUSTED_HOSTS": None,
216             "SERVER_NAME": None,
217             "APPLICATION_ROOT": "/",
218             "SESSION_COOKIE_NAME": "session",
219             "SESSION_COOKIE_DOMAIN": None,
220             "SESSION_COOKIE_PATH": None,
221             "SESSION_COOKIE_HTTPONLY": True,
222             "SESSION_COOKIE_SECURE": False,
223             "SESSION_COOKIE_PARTITIONED": False,
224             "SESSION_COOKIE_SAMESITE": None,
225             "SESSION_REFRESH_EACH_REQUEST": True,
226             "MAX_CONTENT_LENGTH": None,
227             "MAX_FORM_MEMORY_SIZE": 500_000,
228             "MAX_FORM_PARTS": 1_000,
229             "SEND_FILE_MAX_AGE_DEFAULT": None,
230             "TRAP_BAD_REQUEST_ERRORS": None,
231             "TRAP_HTTP_EXCEPTIONS": False,
232             "EXPLAIN_TEMPLATE_LOADING": False,
233             "PREFERRED_URL_SCHEME": "http",
234             "TEMPLATES_AUTO_RELOAD": None,
235             "MAX_COOKIE_SIZE": 4093,
236             "PROVIDE_AUTOMATIC_OPTIONS": True,
237         }
238     )
239 
240     #: The class that is used for request objects.  See :class:`~flask.Request`
241     #: for more information.
242     request_class: type[Request] = Request
243
```

### `target_bandit/examples/hardcoded-passwords.py:58`

- **Your label:** true_positive
- **Model says:** likely_false_positive (p=0.49)
- **Flagged value:** `secret` (secret_score = 0.31)
- **Top signal:** is_test_file (contribution = +1.44)

```python
57 # Severity: Low   Confidence: Medium
58 EMAIL_PASSWORD = "secret"
59
```

### `target_insecure_app/app/config.py:13`

- **Your label:** false_positive
- **Model says:** likely_true_positive (p=0.78)
- **Flagged value:** `John Ripper` (secret_score = 0.72)
- **Top signal:** secret_score (contribution = +1.46)

```python
12 
13 SUPER_SECRET_NAME = "John Ripper"  # FIXME: os.getenv("SUPER_SECRET_NAME")
14
```

