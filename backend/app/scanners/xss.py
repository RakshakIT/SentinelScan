from __future__ import annotations

import ast
import re

from app.models.schemas import Severity, Vulnerability
from app.scanners.base import BaseScanner

_XSS_PATTERNS = [
    re.compile(r"innerHTML\s*=", re.IGNORECASE),
    re.compile(r"document\.write\s*\(", re.IGNORECASE),
    re.compile(r"\.html\s*\(", re.IGNORECASE),
    re.compile(r"dangerouslySetInnerHTML", re.IGNORECASE),
    re.compile(r"v-html\s*=", re.IGNORECASE),
    re.compile(r"\|\s*safe\b"),
    re.compile(r"<%[-=]?\s*.*%>"),
    re.compile(r"eval\s*\(\s*(?:request|params|query)", re.IGNORECASE),
]

_TEMPLATE_INJECTION = re.compile(
    r"""(?:render_template_string|Markup)\s*\(.*(?:\+|%|\.format|f['"])""",
    re.IGNORECASE,
)


class _XSSASTVisitor(ast.NodeVisitor):
    """Detect XSS-prone patterns in Python code via AST."""

    DANGEROUS_FUNCS = {"Markup", "render_template_string", "mark_safe"}

    def __init__(self, source_lines: list[str], filename: str) -> None:
        self.source_lines = source_lines
        self.filename = filename
        self.findings: list[Vulnerability] = []

    def _add(self, node: ast.AST, detail: str) -> None:
        line = node.lineno
        snippet = self.source_lines[line - 1] if line <= len(self.source_lines) else ""
        self.findings.append(
            Vulnerability(
                rule_id="XSS",
                title="Potential Cross-Site Scripting (XSS)",
                severity=Severity.HIGH,
                file=self.filename,
                line=line,
                column=getattr(node, "col_offset", 0),
                snippet=snippet.strip(),
                description=detail,
                recommendation=(
                    "Sanitize and escape all user-controlled data before "
                    "rendering it in HTML. Use framework-provided auto-escaping."
                ),
            )
        )

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in self.DANGEROUS_FUNCS and node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, (ast.JoinedStr, ast.BinOp)):
                self._add(
                    node,
                    f"User data may be injected into HTML via {func_name}().",
                )

        self.generic_visit(node)


class XSSScanner(BaseScanner):
    def scan(self, source: str, filename: str) -> list[Vulnerability]:
        lines = source.splitlines()
        findings: list[Vulnerability] = []

        # AST pass for Python
        if filename.endswith(".py"):
            try:
                tree = ast.parse(source, filename=filename)
                visitor = _XSSASTVisitor(lines, filename)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                pass

        # Regex pass for JS / HTML / templates / Python
        for lineno, line in enumerate(lines, start=1):
            for pattern in _XSS_PATTERNS:
                if pattern.search(line):
                    if not any(f.line == lineno for f in findings):
                        findings.append(
                            Vulnerability(
                                rule_id="XSS",
                                title="Potential Cross-Site Scripting (XSS)",
                                severity=Severity.MEDIUM,
                                file=filename,
                                line=lineno,
                                snippet=line.strip(),
                                description=(
                                    "This code may render unsanitized user input "
                                    "as HTML, enabling XSS attacks."
                                ),
                                recommendation="Escape user input before rendering in HTML.",
                            )
                        )

            if _TEMPLATE_INJECTION.search(line):
                if not any(f.line == lineno for f in findings):
                    findings.append(
                        Vulnerability(
                            rule_id="XSS",
                            title="Server-Side Template Injection / XSS",
                            severity=Severity.HIGH,
                            file=filename,
                            line=lineno,
                            snippet=line.strip(),
                            description="Dynamic content is interpolated into a template without escaping.",
                            recommendation="Avoid passing user data to Markup() or render_template_string().",
                        )
                    )

        return findings
