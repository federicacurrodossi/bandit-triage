"""Tests for the taint engine primitives.

Each primitive is checked on small functions taken from the held-out cases, so
the tests exercise the same code the end-to-end evaluation runs on. See
docs/taint-engine.md for what each primitive is meant to do.
"""
from bandit_triage.taint import variables_in_sink, last_assignment_of


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