"""Instrument silent ``except X: pass`` blocks so failures emit a debug log.

This is a conservative AST-driven transform:

* Targets only ``except <Type>: pass`` and ``except <Type> as <name>: pass``
  where the handler body is a single ``pass`` (no comments, no other stmts).
* Rewrites the body to ``logger.debug('silent_swallow %s:%d %s', __file__, <line>, _exc)``
  while binding the exception via ``as _exc`` if no name was already present.
* Ensures the target file has a module-level ``logger`` available; if not, it
  inserts ``import logging`` (when missing) plus ``logger = logging.getLogger(__name__)``
  after the existing imports / docstring.
* Leaves ``pragma: no cover`` and ``# noqa`` blocks alone on request via --skip-pragma.
* Idempotent: re-running over an instrumented file is a no-op.

Run::

    python scripts/instrument_silent_excepts.py src/api/deep_analyze_endpoints.py
    python scripts/instrument_silent_excepts.py --check src/api/app.py    # dry run

The script preserves indentation by re-emitting the handler header from the
source line (we never touch the header text), then replaces the body lines
between handler.body[0].lineno and end_lineno (Python 3.8+).
"""
from __future__ import annotations

import argparse
import ast
import os
import sys
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class Edit:
    start_line: int           # 1-based inclusive line of the ``except ...:`` header
    body_start: int           # 1-based inclusive line of the body (the `pass`)
    body_end: int             # 1-based inclusive line of the body
    indent: str               # leading whitespace of the body
    handler_header: str       # full original header text (with newline)
    new_header: str           # rewritten header text (adds ``as _exc`` if needed)
    has_name: bool            # whether the original handler already bound the exception


def _is_solo_pass(handler: ast.ExceptHandler) -> bool:
    if len(handler.body) != 1:
        return False
    stmt = handler.body[0]
    return isinstance(stmt, ast.Pass)


def _handler_header_text(source_lines: List[str], handler: ast.ExceptHandler) -> str:
    """Return the original ``except ...:`` header line(s)."""
    start = handler.lineno - 1
    end = handler.body[0].lineno - 1     # body_start exclusive
    return ''.join(source_lines[start:end])


def _body_indent(source_lines: List[str], body_lineno: int) -> str:
    line = source_lines[body_lineno - 1]
    return line[: len(line) - len(line.lstrip())]


def _ensure_as_clause(handler_header: str, has_name: bool) -> Tuple[str, bool]:
    """Rewrite ``except X:`` → ``except X as _exc:``. No-op when name already bound."""
    if has_name:
        return handler_header, False
    # Only patch the trailing ``:`` of the handler. Be defensive about comments.
    stripped = handler_header.rstrip('\n')
    # Split off any trailing comment to preserve it.
    code, _, comment = stripped.partition('#')
    code = code.rstrip()
    if not code.endswith(':'):
        return handler_header, False
    code = code[:-1].rstrip() + ' as _exc:'
    rebuilt = code
    if comment:
        rebuilt = rebuilt + '  #' + comment
    return rebuilt + '\n', True


def collect_edits(source: str, *, skip_pragma: bool = True) -> Tuple[List[Edit], ast.Module]:
    tree = ast.parse(source)
    source_lines = source.splitlines(keepends=True)
    edits: List[Edit] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if not _is_solo_pass(node):
            continue
        body_stmt = node.body[0]
        body_start = body_stmt.lineno
        body_end = getattr(body_stmt, 'end_lineno', body_start)
        # Skip single-line handlers like ``except X: pass`` — header and body
        # share a line, so our line-based replacement cannot rewrite them
        # safely. They're rare and low-value in production code.
        if body_start == node.lineno:
            continue
        header_text = _handler_header_text(source_lines, node)

        if skip_pragma and ('pragma' in header_text.lower() or 'noqa' in header_text.lower()):
            continue

        # Refuse to touch handlers with inline comments inside the body line —
        # those frequently encode intent we should not silently rewrite.
        body_line = source_lines[body_start - 1]
        if '#' in body_line.split('pass', 1)[-1]:
            continue

        indent = _body_indent(source_lines, body_start)
        new_header, _added = _ensure_as_clause(header_text, has_name=bool(node.name))
        edits.append(
            Edit(
                start_line=node.lineno,
                body_start=body_start,
                body_end=body_end,
                indent=indent,
                handler_header=header_text,
                new_header=new_header,
                has_name=bool(node.name),
            )
        )

    return edits, tree


_LOGGER_BOOTSTRAP = (
    "import logging  # auto-added by instrument_silent_excepts\n"
    "logger = logging.getLogger(__name__)  # auto-added by instrument_silent_excepts\n"
)


def _ensure_logger(source: str) -> Tuple[str, bool]:
    """Ensure the file exposes a module-level ``logger`` near the top.

    Inserts a bootstrap right after the module's leading import block / docstring
    if the file does not already define ``logger`` *within the first 100 lines*.
    Files that define ``logger`` only at module-bottom break our instrumentation
    when handlers above the definition try to use it.

    Returns (new_source, modified).
    """
    head = '\n'.join(source.splitlines()[:100])
    if 'logger = logging.getLogger' in head or 'logger = logging.' in head:
        return source, False

    tree = ast.parse(source)
    insert_line = 0  # 1-based; we insert *before* this line
    for stmt in tree.body:
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            insert_line = stmt.end_lineno or stmt.lineno
            continue
        if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
            insert_line = stmt.end_lineno or stmt.lineno
            continue
        break

    lines = source.splitlines(keepends=True)
    has_logging_import = any(
        isinstance(s, ast.Import) and any(a.name == 'logging' for a in s.names)
        for s in tree.body
    ) or any(
        isinstance(s, ast.ImportFrom) and s.module == 'logging'
        for s in tree.body
    )

    bootstrap = _LOGGER_BOOTSTRAP if not has_logging_import else (
        "logger = logging.getLogger(__name__)  # auto-added by instrument_silent_excepts\n"
    )
    new_lines = lines[:insert_line] + ['\n', bootstrap, '\n'] + lines[insert_line:]
    return ''.join(new_lines), True


def apply_edits(source: str, edits: List[Edit]) -> str:
    """Apply edits in reverse order so line numbers stay valid."""
    lines = source.splitlines(keepends=True)
    for edit in sorted(edits, key=lambda e: e.start_line, reverse=True):
        # Rewrite header (may have appended ``as _exc``)
        header_start_idx = edit.start_line - 1
        header_end_idx = edit.body_start - 1   # exclusive
        new_header_lines = edit.new_header
        # Rewrite body
        new_body = (
            f"{edit.indent}logger.debug("
            f"'silent_swallow at %s:%d: %s', __file__, {edit.start_line}, _exc"
            ")\n"
        )
        lines[header_start_idx:header_end_idx] = [new_header_lines]
        # body_start was at header_end_idx; recompute after header replacement
        body_start_idx_new = header_start_idx + 1
        body_end_idx_new = body_start_idx_new + (edit.body_end - edit.body_start + 1)
        lines[body_start_idx_new:body_end_idx_new] = [new_body]
    return ''.join(lines)


def transform_file(path: str, *, check: bool = False, skip_pragma: bool = True) -> int:
    with open(path, 'r', encoding='utf-8') as fh:
        source = fh.read()
    edits, _ = collect_edits(source, skip_pragma=skip_pragma)
    if not edits:
        return 0
    new_source = apply_edits(source, edits)
    new_source, _logger_added = _ensure_logger(new_source)
    # Re-parse to confirm we didn't break syntax.
    try:
        ast.parse(new_source)
    except SyntaxError as exc:
        print(f'[ERROR] {path}: rewrite produced invalid Python: {exc}', file=sys.stderr)
        return -1
    if check:
        print(f'[DRY] {path}: would instrument {len(edits)} silent-swallow blocks')
        return len(edits)
    backup = path + '.silentbak'
    if not os.path.exists(backup):
        with open(backup, 'w', encoding='utf-8') as fh:
            fh.write(source)
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(new_source)
    print(f'[OK] {path}: instrumented {len(edits)} silent-swallow blocks (backup → {backup})')
    return len(edits)


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description='Instrument silent except: pass blocks')
    parser.add_argument('paths', nargs='+')
    parser.add_argument('--check', action='store_true', help='Dry run only')
    parser.add_argument('--include-pragma', action='store_true',
                        help='Also rewrite handlers tagged with pragma/noqa')
    args = parser.parse_args(argv)

    total = 0
    for p in args.paths:
        n = transform_file(p, check=args.check, skip_pragma=not args.include_pragma)
        if n < 0:
            return 2
        total += n
    print(f'\nTotal: {total} blocks {"would be" if args.check else ""} instrumented')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
