from __future__ import annotations
"""Rule DSL Parser Scaffold.

Parses detection expressions defined in rule_dsl_grammar.ebnf into an AST.
Provides minimal evaluation stubs; full temporal/statistical evaluation delegated to pipeline.
"""
import re
from dataclasses import dataclass
from typing import Any, List, Optional

TOKEN_SPEC = [
    ("NUMBER",   r'-?\d+(?:\.\d+)?'),
    ("STRING",   r'"[^"\\]*(?:\\.[^"\\]*)*"'),
    ("OP",       r'==|!=|>=|<=|>|<|~|IN\b'),
    ("KW",       r'\b(AND|OR|NOT|SEQ|WITHIN|ABSENCE|RATE|ZSCORE|LOOKUP|EXISTS)\b'),
    ("LBRACK",   r'\['),
    ("RBRACK",   r'\]'),
    ("LPAREN",   r'\('),
    ("RPAREN",   r'\)'),
    ("COMMA",    r','),
    ("DOT",      r'\.'),
    ("TIMEUNIT", r'\b(?:\d+(?:\.\d+)?)(?:s|m|h|d)\b'),  # captured as single token if standalone
    ("IDENT",    r'[A-Za-z_][A-Za-z0-9_]*'),
    ("WS",       r'\s+'),
]
TOKEN_RE = re.compile('|'.join(f'(?P<{name}>{pattern})' for name, pattern in TOKEN_SPEC))

@dataclass
class ASTNode: pass
@dataclass
class Comparison(ASTNode): field: List[str]; op: str; value: Any
@dataclass
class Exists(ASTNode): field: List[str]
@dataclass
class Sequence(ASTNode): steps: List[Comparison]; window: float; unit: str
@dataclass
class Absence(ASTNode): predicate: Comparison; window: float; unit: str
@dataclass
class RateExpr(ASTNode): field: List[str]; window: float; unit: str; op: str; threshold: float
@dataclass
class ZScoreExpr(ASTNode): field: List[str]; window: float; unit: str; op: str; threshold: float
@dataclass
class LookupExpr(ASTNode): func: str; field: List[str]; op: str; value: Any
@dataclass
class Logical(ASTNode): op: str; left: ASTNode; right: ASTNode
@dataclass
class Not(ASTNode): expr: ASTNode

class DSLParserError(Exception): pass

class Lexer:
    def __init__(self, text: str):
        self.text = text
        self.tokens = []
        for m in TOKEN_RE.finditer(text):
            kind = m.lastgroup
            val = m.group()
            if kind == 'WS':
                continue
            self.tokens.append((kind, val))
        self.pos = 0

    def peek(self) -> Optional[tuple[str,str]]:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def pop(self, expected: Optional[str] = None) -> tuple[str,str]:
        tok = self.peek()
        if tok is None:
            raise DSLParserError('unexpected EOF')
        if expected and tok[0] != expected:
            raise DSLParserError(f'expected {expected} got {tok}')
        self.pos += 1
        return tok

    def match(self, *types: str) -> bool:
        tok = self.peek()
        return tok is not None and tok[0] in types

class Parser:
    def __init__(self, text: str):
        self.lexer = Lexer(text)

    def parse(self) -> ASTNode:
        node = self.parse_or()
        if self.lexer.peek() is not None:
            raise DSLParserError(f'Extra tokens after parse: {self.lexer.peek()}')
        return node

    def parse_or(self) -> ASTNode:
        node = self.parse_and()
        while self._accept_kw('OR'):
            right = self.parse_and()
            node = Logical('OR', node, right)
        return node

    def parse_and(self) -> ASTNode:
        node = self.parse_unary()
        while self._accept_kw('AND'):
            right = self.parse_unary()
            node = Logical('AND', node, right)
        return node

    def parse_unary(self) -> ASTNode:
        if self._accept_kw('NOT'):
            return Not(self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> ASTNode:
        if self._accept('LPAREN'):
            expr = self.parse_or()
            self._expect('RPAREN')
            return expr
        if self._accept_kw('EXISTS'):
            return Exists(self._parse_field())
        if self._accept_kw('SEQ'):
            return self._parse_seq()
        if self._accept_kw('ABSENCE'):
            return self._parse_absence()
        if self._accept_kw('RATE'):
            return self._parse_rate()
        if self._accept_kw('ZSCORE'):
            return self._parse_zscore()
        if self._accept_kw('LOOKUP'):
            return self._parse_lookup()
        return self._parse_comparison()

    def _parse_comparison(self) -> Comparison:
        field = self._parse_field()
        op = self._parse_op()
        val = self._parse_value()
        return Comparison(field, op, val)

    def _parse_field(self) -> List[str]:
        parts: List[str] = []
        if not self._accept('IDENT'):
            raise DSLParserError('expected identifier for field')
        parts.append(self._last()[1])
        while self._accept('DOT'):
            self._expect('IDENT')
            parts.append(self._last()[1])
        return parts

    def _parse_op(self) -> str:
        if self._accept('OP'):
            return self._last()[1]
        raise DSLParserError('comparison operator expected')

    def _parse_value(self) -> Any:
        if self._accept('NUMBER'):
            return float(self._last()[1])
        if self._accept('STRING'):
            s = self._last()[1]
            return s[1:-1]
        if self._accept('LBRACK'):
            items = []
            if not self._check('RBRACK'):
                items.append(self._parse_value())
                while self._accept('COMMA'):
                    items.append(self._parse_value())
            self._expect('RBRACK')
            return items
        raise DSLParserError('value expected')

    def _parse_seq(self) -> Sequence:
        self._expect('LBRACK')
        steps: List[Comparison] = []
        steps.append(self._parse_comparison())
        while self._accept('COMMA'):
            steps.append(self._parse_comparison())
        self._expect('RBRACK')
        self._expect_kw('WITHIN')
        window, unit = self._parse_time_window()
        return Sequence(steps, window, unit)

    def _parse_absence(self) -> Absence:
        self._expect('LBRACK')
        pred = self._parse_comparison()
        self._expect('RBRACK')
        self._expect_kw('WITHIN')
        window, unit = self._parse_time_window()
        return Absence(pred, window, unit)

    def _parse_rate(self) -> RateExpr:
        self._expect('LPAREN')
        field = self._parse_field()
        self._expect('COMMA')
        window, unit = self._parse_time_window()
        self._expect('RPAREN')
        op = self._parse_op()
        self._expect('NUMBER')
        thresh = float(self._last()[1])
        return RateExpr(field, window, unit, op, thresh)

    def _parse_zscore(self) -> ZScoreExpr:
        self._expect('LPAREN')
        field = self._parse_field()
        self._expect('COMMA')
        window, unit = self._parse_time_window()
        self._expect('RPAREN')
        op = self._parse_op()
        self._expect('NUMBER')
        thresh = float(self._last()[1])
        return ZScoreExpr(field, window, unit, op, thresh)

    def _parse_lookup(self) -> LookupExpr:
        self._expect('DOT')
        self._expect('IDENT')
        func = self._last()[1]
        self._expect('LPAREN')
        field = self._parse_field()
        self._expect('RPAREN')
        op = self._parse_op()
        val = self._parse_value()
        return LookupExpr(func, field, op, val)

    def _parse_time_window(self) -> tuple[float,str]:
        # Accept NUMBER TIMEUNIT or a combined TIMEUNIT token (e.g., 5m) parsed as IDENT? We handle combined manually.
        if self._accept('NUMBER'):
            num = float(self._last()[1])
            if self._accept('IDENT'):
                unit = self._last()[1]
                if unit not in ('s','m','h','d'):
                    raise DSLParserError(f'unknown time unit {unit}')
                return num, unit
            # Fallback: missing unit defaults to seconds
            return num, 's'
        # Combined pattern like 5m is matched by TOKEN_SPEC TIMEUNIT? treat as IDENT fallback
        if self._accept('IDENT'):
            raw = self._last()[1]
            m = re.match(r'(?P<num>\d+(?:\.\d+)?)(?P<unit>[smhd])', raw)
            if m:
                return float(m.group('num')), m.group('unit')
        raise DSLParserError('time window expected')

    # --------------- Helper consumption methods ---------------
    def _accept(self, kind: str) -> bool:
        if self.lexer.match(kind):
            self._last_tok = self.lexer.pop(kind)
            return True
        return False
    def _accept_kw(self, kw: str) -> bool:
        tok = self.lexer.peek()
        if tok and tok[0] == 'KW' and tok[1] == kw:
            self._last_tok = self.lexer.pop('KW')
            return True
        return False
    def _expect(self, kind: str):
        tok = self.lexer.pop(kind)
        self._last_tok = tok
    def _expect_kw(self, kw: str):
        if not self._accept_kw(kw):
            raise DSLParserError(f'expected keyword {kw}')
    def _last(self):
        return getattr(self, '_last_tok')
    def _check(self, kind: str) -> bool:
        return self.lexer.match(kind)

# Public API

def parse_rule(text: str) -> ASTNode:
    return Parser(text).parse()

# Basic evaluator stub (non-temporal) for simple comparisons & existence

def evaluate(ast: ASTNode, event: dict[str, Any]) -> bool:
    if isinstance(ast, Logical):
        if ast.op == 'AND':
            return evaluate(ast.left, event) and evaluate(ast.right, event)
        return evaluate(ast.left, event) or evaluate(ast.right, event)
    if isinstance(ast, Not):
        return not evaluate(ast.expr, event)
    if isinstance(ast, Exists):
        return _get_field(event, ast.field) is not None
    if isinstance(ast, Comparison):
        val = _get_field(event, ast.field)
        return _cmp(val, ast.op, ast.value)
    # Other node types require pipeline context; return False placeholder
    return False

def _get_field(event: dict[str, Any], path: List[str]):
    cur = event
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur

def _cmp(left: Any, op: str, right: Any) -> bool:
    try:
        if op == '==': return left == right
        if op == '!=': return left != right
        if op == '>': return left > right
        if op == '>=': return left >= right
        if op == '<': return left < right
        if op == '<=': return left <= right
        if op == '~': # substring
            if left is None: return False
            return str(right) in str(left)
        if op == 'IN':
            return left in (right if isinstance(right, list) else [right])
    except Exception:
        return False
    return False

__all__ = [
    'parse_rule','evaluate','ASTNode','Comparison','Exists','Sequence','Absence','RateExpr','ZScoreExpr','LookupExpr','Logical','Not','DSLParserError'
]
