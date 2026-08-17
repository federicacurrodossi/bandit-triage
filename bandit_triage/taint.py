"""
Lightweight intra-procedural taint analysis for Bandit injection findings.

Bandit flags injection issues (SQL, shell, XSS) by matching the shape of the
sink alone: it sees a query built with string formatting and reports it, with
no idea whether the value came from user input or whether it was sanitized
first. Academic work names this directly: Bandit analyzes each AST node in
isolation and cannot consider data flow, so it cannot tell a real injection
from a safe query built out of internal identifiers.

This module adds the missing piece, kept deliberately small in scope:

  * intra-procedural only (a single function), the same boundary Semgrep's
    free tier draws. Inter-procedural flow (across function calls and files)
    is left to heavier tools like CodeQL and is reported as "unknown" here
    rather than guessed.
  * it works backward from the sink: starting at the variables used in the
    flagged expression, it follows assignments up through the function to find
    where each value comes from, building a dependency tree as it goes.
  * the tree is then examined for two things Bandit ignores: whether a value
    originates from an untrusted SOURCE, and whether a SANITIZER lies on the
    path between the source and the sink.

The engine is generic. What counts as a sink or a sanitizer for a given Bandit
rule lives in a RuleConfig, so extending from SQL (B608) to the command and
XSS families (B602/B603/B703/...) is a matter of adding configuration, not
changing the analysis.

This file defines the data structures; the engine that fills them lives
alongside them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set


class SourceType(Enum):
    """Where a value ultimately comes from, as far as the backward walk could
    determine within the function."""
    REQUEST = "request"          # request.*, form[...], args.get(...), cookies
    ROUTE_PARAM = "route_param"  # a Flask/Django view parameter bound from the URL
    INPUT = "input"              # input(), sys.argv, os.environ, stdin
    NETWORK = "network"          # socket / queue / cache reads (redis, kafka, ...)
    CONSTANT = "constant"        # a literal or an internal constant: safe
    UNKNOWN = "unknown"          # comes from a call we don't follow, or a global

    @property
    def is_untrusted(self) -> bool:
        """True for sources that carry attacker-controllable data."""
        return self in {
            SourceType.REQUEST,
            SourceType.ROUTE_PARAM,
            SourceType.INPUT,
            SourceType.NETWORK,
        }


class NodeKind(Enum):
    """What a node in the dependency tree represents."""
    VARIABLE = "variable"     # a local name being traced
    SOURCE = "source"         # a value origin (trusted or not; see SourceType)
    SANITIZER = "sanitizer"   # a call that neutralizes taint for this rule
    CONSTANT = "constant"     # a literal value
    PARAM = "param"           # a function parameter
    SINK = "sink"             # the flagged expression itself (tree root)


@dataclass
class DepNode:
    """One node in the dependency tree.

    The tree is rooted at the sink and grows downward toward origins. We keep
    it a tree (not a shared graph): if two branches reach the same source, that
    source appears twice. This costs a little duplication but keeps the
    structure easy to walk and easy to render as an explanation.
    """
    label: str                                  # variable name or short repr
    kind: NodeKind
    line: int = 0                               # source line where it appears
    source_type: Optional[SourceType] = None    # set when kind == SOURCE
    sanitizer_name: Optional[str] = None        # set when kind == SANITIZER
    children: List["DepNode"] = field(default_factory=list)

    def add_child(self, node: "DepNode") -> "DepNode":
        self.children.append(node)
        return node

    def walk(self):
        """Yield this node and all descendants, depth first."""
        yield self
        for child in self.children:
            yield from child.walk()


@dataclass
class RuleConfig:
    """Per-rule configuration: what the generic engine should treat as a
    sanitizer for this particular Bandit rule. Sources are shared across all
    injection rules (untrusted input is the same regardless of the sink), so
    they are not repeated here.

    Adding a new rule (B602, B703, ...) means adding one of these, not touching
    the engine.
    """
    rule_id: str                                # e.g. "B608"
    sanitizers: Set[str] = field(default_factory=set)   # call names that clean data
    # for SQL, a parameterized query (execute(sql, params)) is safe regardless of
    # how sql was built; other families leave this False
    parametrization_is_safe: bool = False

    def is_sanitizer(self, call_name: str) -> bool:
        return call_name in self.sanitizers


@dataclass
class TaintResult:
    """The engine's verdict for one finding, rich enough to derive several
    model features rather than a single yes/no."""
    is_tainted: bool = False           # an untrusted source reaches the sink
    has_sanitizer: bool = False        # a sanitizer sits on the source->sink path
    source_type: SourceType = SourceType.UNKNOWN
    path_length: int = 0               # assignments between source and sink
    analysis_complete: bool = True     # False if we hit something we don't follow
    tree: Optional[DepNode] = None     # the dependency tree, kept for explanation

    @property
    def likely_exploitable(self) -> bool:
        """Untrusted data reaching the sink with nothing cleaning it on the way.
        This is exactly the case Bandit cannot distinguish on its own."""
        return self.is_tainted and not self.has_sanitizer


# ---------------------------------------------------------------------------
# Engine primitives
#
# The engine is built from small, independently testable primitives. Each one
# does a single step of the backward walk described in docs/taint-engine.md.
# ---------------------------------------------------------------------------

import ast


def _call_name(call: ast.Call) -> Optional[str]:
    """The bare name of the function being called.

    For an attribute call like g.db.execute(...) this returns "execute"; for a
    plain call like execute(...) it returns "execute". Anything more exotic
    returns None.
    """
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return None


def variables_in_sink(code: str, sink_names: Set[str]) -> Set[str]:
    """Primitive 1: the variables that feed the sink.

    Given a snippet of code and the set of call names that count as sinks for
    the active rule (for B608, names like "execute" and "executemany"), locate
    the sink call and return the variable names that appear inside its
    arguments. These are the starting points of the backward walk.

    Only names inside the call's own arguments (positional and keyword) are
    collected, so the object the method is called on (g, cursor, self) and any
    assignment target on the left hand side are left out. If the snippet does
    not parse, or contains no matching sink call, an empty set is returned.
    """
    try:
        tree = ast.parse(code.strip())
    except SyntaxError:
        return set()

    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in sink_names:
            for arg in node.args:
                for sub in ast.walk(arg):
                    if isinstance(sub, ast.Name):
                        names.add(sub.id)
            for kw in node.keywords:
                for sub in ast.walk(kw.value):
                    if isinstance(sub, ast.Name):
                        names.add(sub.id)
    return names


def last_assignment_of(function_code: str, var_name: str) -> Optional[str]:
    """Primitive 2: where a value is born.

    Given the source of a function and a variable name, find the last place in
    that function where the variable is assigned, and return the right hand
    side of that assignment as text (for example "self.quote_name('cache_key')").

    "Last" matters: if a variable is assigned more than once, the value that
    reaches the sink is the most recent one, so later assignments win over
    earlier ones.

    Returns None when the variable is never assigned in the function. That is
    not a failure: it usually means the variable is a function parameter (see
    primitive 3, which decides whether that parameter is bound from an untrusted
    route) or a name defined outside the function.
    """
    try:
        tree = ast.parse(function_code.strip())
    except SyntaxError:
        return None

    last: Optional[ast.Assign] = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == var_name:
                    last = node
    if last is None:
        return None
    return ast.unparse(last.value)


# Names whose attribute access carries attacker-controllable web input.
UNTRUSTED_REQUEST_ROOTS = {"request"}

# Callables that read input from outside the program.
INPUT_CALLS = {"input", "getpass"}
# Attribute accesses that read input from the environment or arguments.
INPUT_ATTRS = {"argv", "environ", "getenv", "stdin"}


@dataclass
class OriginInfo:
    """What primitive 3 concluded about one origin: its source type, and, when
    the origin is a sanitizer call, the name of that sanitizer so the walk can
    look through it at what it wraps."""
    source_type: SourceType = SourceType.UNKNOWN
    sanitizer_name: Optional[str] = None

    @property
    def is_sanitizer(self) -> bool:
        return self.sanitizer_name is not None


def _root_name(node: ast.AST) -> Optional[str]:
    """The leftmost name of an attribute chain: for request.args.get returns
    'request', for os.environ returns 'os'."""
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        if isinstance(node, ast.Attribute):
            node = node.value
        elif isinstance(node, ast.Subscript):
            node = node.value
        else:  # ast.Call
            node = node.func
    return node.id if isinstance(node, ast.Name) else None


def classify_origin(rhs_code: Optional[str],
                    config: Optional["RuleConfig"] = None) -> OriginInfo:
    """Primitive 3: judge where a value comes from.

    Given the right hand side of an assignment (as returned by primitive 2),
    decide which SourceType it represents. When a RuleConfig is supplied and the
    value is produced by one of its sanitizer calls, the sanitizer name is
    recorded so the walk can look through it.

    Recognized cases:
      * request.* (Flask/Django web input)        -> REQUEST (untrusted)
      * input(), sys.argv, os.environ, os.getenv  -> INPUT   (untrusted)
      * a literal string or number                -> CONSTANT (safe)
      * a call listed as a sanitizer for the rule -> sanitizer recorded
      * anything else (a call we do not follow)   -> UNKNOWN

    Route parameters are handled separately by is_route_param, since deciding
    that needs the whole function, not just this expression.
    """
    if rhs_code is None:
        return OriginInfo(SourceType.UNKNOWN)
    try:
        tree = ast.parse(rhs_code, mode="eval")
    except SyntaxError:
        return OriginInfo(SourceType.UNKNOWN)

    body = tree.body

    # A bare literal: safe.
    if isinstance(body, ast.Constant):
        return OriginInfo(SourceType.CONSTANT)

    # Web input: any reference rooted at 'request'.
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in UNTRUSTED_REQUEST_ROOTS:
            return OriginInfo(SourceType.REQUEST)

    # Program input: input()/getpass(), or sys.argv / os.environ / os.getenv.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = node.func.id if isinstance(node.func, ast.Name) else None
            if name in INPUT_CALLS:
                return OriginInfo(SourceType.INPUT)
        if isinstance(node, ast.Attribute) and node.attr in INPUT_ATTRS:
            return OriginInfo(SourceType.INPUT)

    # A sanitizer call for this rule: record its name so the walk sees through it.
    if config is not None and isinstance(body, ast.Call):
        call_name = _call_name(body)
        if call_name is not None and config.is_sanitizer(call_name):
            return OriginInfo(SourceType.UNKNOWN, sanitizer_name=call_name)

    # A call or name we do not follow within the function: honestly unknown.
    return OriginInfo(SourceType.UNKNOWN)


def is_route_param(function_code: str, var_name: str) -> bool:
    """Primitive 3, route case: is var_name a view parameter bound from the URL?

    True when the variable is a parameter of the function and the function
    carries a Flask/Django route decorator whose pattern contains <var_name>
    (Flask style, including typed converters like <int:item>) . This is the
    origin of the real injection in main.py:56, which no assignment search can
    find because the value never gets assigned: it arrives through the route.
    """
    try:
        tree = ast.parse(function_code.strip())
    except SyntaxError:
        return False

    func = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            func = node
            break
    if func is None:
        return False

    # Is var_name one of the function's parameters?
    params = {a.arg for a in func.args.args}
    if var_name not in params:
        return False

    # Does any route decorator mention <var_name> (optionally <conv:var_name>)?
    for dec in func.decorator_list:
        for s in ast.walk(dec):
            if isinstance(s, ast.Constant) and isinstance(s.value, str):
                pattern = s.value
                if f"<{var_name}>" in pattern:
                    return True
                # typed converter form, e.g. <int:item> or <path:item>
                if f":{var_name}>" in pattern:
                    return True
    return False