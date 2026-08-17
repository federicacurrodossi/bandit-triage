"""Tests for the taint engine primitives.

Each primitive is checked on small functions taken from the held-out cases, so
the tests exercise the same code the end-to-end evaluation runs on. See
docs/taint-engine.md for what each primitive is meant to do.
"""
from bandit_triage.taint import (
    variables_in_sink,
    last_assignment_of,
    classify_origin,
    is_route_param,
    RuleConfig,
    SourceType,
)


# Call names that count as SQL sinks for B608.
SQL_SINKS = {"execute", "executemany", "executescript", "raw"}


class TestVariablesInSink:
    """Primitive 1: the variables that feed the sink."""

    def test_route_param_case(self):
        # target_hackable/main.py:56, the real SQL injection: item comes from
        # the Flask route. The variable feeding the sink is exactly {item}.
        code = "curs = g.db.execute(\"SELECT * FROM shop_items WHERE name = '%s'\" % item)"
        assert variables_in_sink(code, SQL_SINKS) == {"item"}

    def test_string_concatenation(self):
        code = "cursor.execute(\"SELECT * FROM users WHERE name = '\" + username + \"'\")"
        assert variables_in_sink(code, SQL_SINKS) == {"username"}

    def test_single_variable(self):
        code = "cursor.execute(query)"
        assert variables_in_sink(code, SQL_SINKS) == {"query"}

    def test_format_call(self):
        code = 'db.execute("SELECT * FROM t WHERE id = {}".format(user_id))'
        assert variables_in_sink(code, SQL_SINKS) == {"user_id"}

    def test_keyword_argument(self):
        code = "db.execute(sql=my_query)"
        assert variables_in_sink(code, SQL_SINKS) == {"my_query"}

    def test_object_and_target_excluded(self):
        # curs (assignment target) and g (the object execute is called on) must
        # not appear: only what is inside the call's arguments counts.
        code = "curs = g.db.execute(\"SELECT * FROM t WHERE x = '%s'\" % item)"
        result = variables_in_sink(code, SQL_SINKS)
        assert "curs" not in result
        assert "g" not in result
        assert result == {"item"}

    def test_no_sink_present(self):
        # A return of an f-string is a different kind of sink (not a call), so
        # this primitive finds no sink call and returns empty.
        code = 'return f"SELECT {cache_key} FROM x"'
        assert variables_in_sink(code, SQL_SINKS) == set()

    def test_syntax_error_is_safe(self):
        # Malformed snippets must not crash the engine.
        code = "cursor.execute(  # broken"
        assert variables_in_sink(code, SQL_SINKS) == set()

    def test_two_variables(self):
        code = "cursor.execute(\"SELECT * FROM t WHERE a = %s AND b = %s\" % (a, b))"
        assert variables_in_sink(code, SQL_SINKS) == {"a", "b"}


class TestLastAssignmentOf:
    """Primitive 2: where a value is born."""

    def test_static_template_case(self):
        # operations.py:113: cache_key is assigned from a call on a literal.
        code = '''
def cache_key_culling_sql(self):
    cache_key = self.quote_name("cache_key")
    return f"SELECT {cache_key} FROM x"
'''
        assert last_assignment_of(code, "cache_key") == "self.quote_name('cache_key')"

    def test_route_param_returns_none(self):
        # main.py:56: item is never assigned, it is a parameter. None is correct.
        code = '''
def searchAPI(item):
    g.db = connect_db()
    curs = g.db.execute("SELECT * FROM t WHERE name = '%s'" % item)
'''
        assert last_assignment_of(code, "item") is None

    def test_last_assignment_wins(self):
        # When a variable is reassigned, the most recent value reaches the sink.
        code = '''
def f():
    x = "safe"
    x = request.args["q"]
    cursor.execute("SELECT ... " + x)
'''
        assert last_assignment_of(code, "x") == 'request.args[\'q\']'

    def test_variable_not_present(self):
        code = '''
def f():
    y = 1
    return y
'''
        assert last_assignment_of(code, "z") is None

    def test_syntax_error_is_safe(self):
        assert last_assignment_of("def broken(", "x") is None


class TestClassifyOrigin:
    """Primitive 3: judge where a value comes from."""

    def test_request_is_untrusted(self):
        for code in ["request.args['q']", "request.form['user']",
                     "request.cookies.get('x')"]:
            info = classify_origin(code)
            assert info.source_type == SourceType.REQUEST
            assert info.source_type.is_untrusted

    def test_program_input_is_untrusted(self):
        for code in ["input()", "sys.argv[1]", "os.environ['HOME']",
                     "os.getenv('PATH')"]:
            info = classify_origin(code)
            assert info.source_type == SourceType.INPUT
            assert info.source_type.is_untrusted

    def test_literal_is_constant(self):
        assert classify_origin("'SELECT * FROM users'").source_type == SourceType.CONSTANT
        assert classify_origin("42").source_type == SourceType.CONSTANT

    def test_unknown_call(self):
        info = classify_origin("self.some_helper(x)")
        assert info.source_type == SourceType.UNKNOWN
        assert not info.is_sanitizer

    def test_none_is_unknown(self):
        assert classify_origin(None).source_type == SourceType.UNKNOWN

    def test_sanitizer_recorded(self):
        cfg = RuleConfig(rule_id="B608", sanitizers={"quote_name", "escape"})
        info = classify_origin("self.quote_name('cache_key')", cfg)
        assert info.sanitizer_name == "quote_name"
        assert info.is_sanitizer

    def test_non_sanitizer_call_with_config(self):
        cfg = RuleConfig(rule_id="B608", sanitizers={"quote_name"})
        info = classify_origin("some_other(x)", cfg)
        assert info.sanitizer_name is None


class TestIsRouteParam:
    """Primitive 3, route case: a view parameter bound from the URL."""

    def test_flask_route_param(self):
        # main.py:56, the real injection: item comes from the route.
        code = '''
@app.route('/api/v1.0/storeAPI/<item>', methods=['GET'])
def searchAPI(item):
    curs = g.db.execute("SELECT ... '%s'" % item)
'''
        assert is_route_param(code, "item") is True

    def test_typed_converter(self):
        code = '''
@app.route('/x/<int:item>')
def f(item):
    return item
'''
        assert is_route_param(code, "item") is True

    def test_param_without_route_is_not(self):
        code = '''
def helper(item):
    return item + 1
'''
        assert is_route_param(code, "item") is False

    def test_name_not_a_param(self):
        code = '''
@app.route('/x/<item>')
def f(item):
    return item
'''
        assert is_route_param(code, "other") is False