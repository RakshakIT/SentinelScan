from __future__ import annotations

import ast
import re

from app.models.schemas import Severity, Vulnerability
from app.scanners.base import BaseScanner

# Language-agnostic regex patterns
_UNSAFE_PATTERNS: list[tuple[re.Pattern[str], str, str, Severity]] = [
    (
        re.compile(r"\beval\s*\("),
        "Use of eval()",
        "eval() executes arbitrary code and should be avoided.",
        Severity.HIGH,
    ),
    (
        re.compile(r"\bexec\s*\("),
        "Use of exec()",
        "exec() executes arbitrary code and should be avoided.",
        Severity.HIGH,
    ),
    (
        re.compile(r"\b(?:os\.system|subprocess\.call|subprocess\.Popen)\s*\("),
        "Shell command execution",
        "Calling shell commands can lead to command injection if inputs are not validated.",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"pickle\.loads?\s*\("),
        "Unsafe deserialization (pickle)",
        "pickle.load() can execute arbitrary code during deserialization.",
        Severity.HIGH,
    ),
    (
        re.compile(r"yaml\.load\s*\([^)]*\)"),
        "Unsafe YAML loading",
        "yaml.load() without SafeLoader can execute arbitrary code.",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"marshal\.loads?\s*\("),
        "Unsafe deserialization (marshal)",
        "marshal.load() is not secure against malicious data.",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"__import__\s*\("),
        "Dynamic import",
        "__import__() with user input can load arbitrary modules.",
        Severity.MEDIUM,
    ),
    (
        re.compile(r"compile\s*\([^)]+,\s*['\"]exec['\"]"),
        "Dynamic code compilation",
        "compile() with exec mode can execute arbitrary code.",
        Severity.MEDIUM,
    ),
]


class _UnsafeFuncASTVisitor(ast.NodeVisitor):
    """Detect dangerous function calls via the Python AST."""

    DANGEROUS = {
        "eval": ("Use of eval()", Severity.HIGH),
        "exec": ("Use of exec()", Severity.HIGH),
        "__import__": ("Dynamic import via __import__()", Severity.MEDIUM),
    }

    DANGEROUS_ATTRS = {
        ("os", "system"): ("os.system() call", Severity.MEDIUM),
        ("os", "popen"): ("os.popen() call", Severity.MEDIUM),
        ("subprocess", "call"): ("subprocess.call()", Severity.MEDIUM),
        ("subprocess", "Popen"): ("subprocess.Popen()", Severity.MEDIUM),
        ("pickle", "load"): ("pickle.load() deserialization", Severity.HIGH),
        ("pickle", "loads"): ("pickle.loads() deserialization", Severity.HIGH),
        ("yaml", "load"): ("yaml.load() without SafeLoader", Severity.MEDIUM),
        ("marshal", "load"): ("marshal.load()", Severity.MEDIUM),
        ("marshal", "loads"): ("marshal.loads()", Severity.MEDIUM),
    }

    def __init__(self, source_lines: list[str], filename: str) -> None:
        self.source_lines = source_lines
        self.filename = filename
        self.findings: list[Vulnerability] = []

    def _add(self, node: ast.AST, title: str, severity: Severity, desc: str) -> None:
        line = node.lineno
        snippet = self.source_lines[line - 1] if line <= len(self.source_lines) else ""
        self.findings.append(
            Vulnerability(
                rule_id="UNSAFE_FUNCTION",
                title=title,
                severity=severity,
                file=self.filename,
                line=line,
                column=getattr(node, "col_offset", 0),
                snippet=snippet.strip(),
                description=desc,
                recommendation="Replace with a safer alternative or validate all inputs rigorously.",
            )
        )

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # Direct name calls: eval(), exec(), __import__()
        if isinstance(node.func, ast.Name) and node.func.id in self.DANGEROUS:
            title, severity = self.DANGEROUS[node.func.id]
            self._add(
                node,
                title,
                severity,
                f"{node.func.id}() can execute arbitrary code.",
            )

        # Attribute calls: os.system(), pickle.loads(), …
        if isinstance(node.func, ast.Attribute):
            obj = node.func.value
            if isinstance(obj, ast.Name):
                key = (obj.id, node.func.attr)
                if key in self.DANGEROUS_ATTRS:
                    title, severity = self.DANGEROUS_ATTRS[key]
                    self._add(
                        node,
                        title,
                        severity,
                        f"{obj.id}.{node.func.attr}() is potentially unsafe.",
                    )

        self.generic_visit(node)


class UnsafeFunctionsScanner(BaseScanner):
    def scan(self, source: str, filename: str) -> list[Vulnerability]:
        lines = source.splitlines()
        findings: list[Vulnerability] = []

        # AST analysis for Python
        if filename.endswith(".py"):
            try:
                tree = ast.parse(source, filename=filename)
                visitor = _UnsafeFuncASTVisitor(lines, filename)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                pass

        # Regex fallback for non-Python or as supplement
        for lineno, line in enumerate(lines, start=1):
            for pattern, title, desc, severity in _UNSAFE_PATTERNS:
                if pattern.search(line):
                    if not any(f.line == lineno for f in findings):
                        findings.append(
                            Vulnerability(
                                rule_id="UNSAFE_FUNCTION",
                                title=title,
                                severity=severity,
                                file=filename,
                                line=lineno,
                                snippet=line.strip(),
                                description=desc,
                                recommendation="Replace with a safer alternative or validate all inputs.",
                            )
                        )

        return findings
