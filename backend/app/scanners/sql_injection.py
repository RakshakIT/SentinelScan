from __future__ import annotations

import ast
import re

from app.models.schemas import Severity, Vulnerability
from app.scanners.base import BaseScanner

# Regex patterns for non-Python files
_SQL_CONCAT_PATTERNS = [
    re.compile(
        r"""(?:execute|query|cursor\.execute|\.raw|\.extra)\s*\(\s*(?:f['\"]|['\"].*%s|['\"].*\+|.*\.format\()""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*(?:\+\s*[\w\.]+|\$\{|\%s|''\s*\+)""",
        re.IGNORECASE,
    ),
]


class _SQLInjectionASTVisitor(ast.NodeVisitor):
    """Walk a Python AST looking for SQL injection patterns."""

    DANGEROUS_CALLS = {
        "execute",
        "executemany",
        "raw",
        "extra",
        "executescript",
    }

    def __init__(self, source_lines: list[str], filename: str) -> None:
        self.source_lines = source_lines
        self.filename = filename
        self.findings: list[Vulnerability] = []

    # --- helpers -----------------------------------------------------------

    def _add(self, node: ast.AST, snippet: str) -> None:
        self.findings.append(
            Vulnerability(
                rule_id="SQL_INJECTION",
                title="Potential SQL Injection",
                severity=Severity.HIGH,
                file=self.filename,
                line=node.lineno,
                column=getattr(node, "col_offset", 0),
                snippet=snippet.strip(),
                description=(
                    "User-controlled data appears to be concatenated or "
                    "interpolated directly into a SQL query string."
                ),
                recommendation=(
                    "Use parameterized queries or an ORM's built-in escaping "
                    "instead of string formatting for SQL statements."
                ),
            )
        )

    @staticmethod
    def _is_sql_keyword_string(node: ast.AST) -> bool:
        """Return True when node is a string constant containing SQL keywords."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            upper = node.value.upper()
            return any(
                kw in upper
                for kw in ("SELECT ", "INSERT ", "UPDATE ", "DELETE ", "DROP ")
            )
        return False

    # --- visitors ----------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id

        if func_name in self.DANGEROUS_CALLS and node.args:
            first_arg = node.args[0]
            # f-string with SQL keywords
            if isinstance(first_arg, ast.JoinedStr):
                snippet = self.source_lines[node.lineno - 1] if node.lineno <= len(self.source_lines) else ""
                self._add(node, snippet)
            # "..." % (...)  or "...".format(...)
            elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
                if self._is_sql_keyword_string(first_arg.left):
                    snippet = self.source_lines[node.lineno - 1] if node.lineno <= len(self.source_lines) else ""
                    self._add(node, snippet)
            # string concatenation with +
            elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                if self._is_sql_keyword_string(first_arg.left):
                    snippet = self.source_lines[node.lineno - 1] if node.lineno <= len(self.source_lines) else ""
                    self._add(node, snippet)

        self.generic_visit(node)


class SQLInjectionScanner(BaseScanner):
    def scan(self, source: str, filename: str) -> list[Vulnerability]:
        lines = source.splitlines()
        findings: list[Vulnerability] = []

        # AST-based analysis for Python files
        if filename.endswith(".py"):
            try:
                tree = ast.parse(source, filename=filename)
                visitor = _SQLInjectionASTVisitor(lines, filename)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                pass

        # Regex fallback for all files
        for lineno, line in enumerate(lines, start=1):
            for pattern in _SQL_CONCAT_PATTERNS:
                if pattern.search(line):
                    # Avoid duplicate if AST already caught it
                    if not any(f.line == lineno for f in findings):
                        findings.append(
                            Vulnerability(
                                rule_id="SQL_INJECTION",
                                title="Potential SQL Injection",
                                severity=Severity.HIGH,
                                file=filename,
                                line=lineno,
                                snippet=line.strip(),
                                description="SQL query appears to use string concatenation or interpolation.",
                                recommendation="Use parameterized queries instead of string formatting.",
                            )
                        )

        return findings
