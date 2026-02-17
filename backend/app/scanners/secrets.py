from __future__ import annotations

import ast
import re

from app.models.schemas import Severity, Vulnerability
from app.scanners.base import BaseScanner

# Patterns that indicate hardcoded secrets
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(
            r"""(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{4,}['"]""",
            re.IGNORECASE,
        ),
        "Hardcoded password",
    ),
    (
        re.compile(
            r"""(?:api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*['"][^'"]{8,}['"]""",
            re.IGNORECASE,
        ),
        "Hardcoded API key",
    ),
    (
        re.compile(
            r"""(?:secret|token|auth[_-]?token)\s*[=:]\s*['"][^'"]{8,}['"]""",
            re.IGNORECASE,
        ),
        "Hardcoded secret or token",
    ),
    (
        re.compile(
            r"""(?:aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['"][^'"]+['"]""",
            re.IGNORECASE,
        ),
        "Hardcoded AWS credential",
    ),
    (
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "AWS Access Key ID",
    ),
    (
        re.compile(
            r"""(?:-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----)""",
        ),
        "Embedded private key",
    ),
    (
        re.compile(
            r"""(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}""",
        ),
        "GitHub personal access token",
    ),
]


class _SecretsASTVisitor(ast.NodeVisitor):
    """Walk Python AST looking for secrets assigned to suspicious variable names."""

    SECRET_VAR_NAMES = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "api_key",
        "apikey",
        "access_key",
        "auth_token",
        "private_key",
        "secret_key",
    }

    def __init__(self, source_lines: list[str], filename: str) -> None:
        self.source_lines = source_lines
        self.filename = filename
        self.findings: list[Vulnerability] = []

    def _add(self, node: ast.AST, title: str) -> None:
        line = node.lineno
        snippet = self.source_lines[line - 1] if line <= len(self.source_lines) else ""
        self.findings.append(
            Vulnerability(
                rule_id="HARDCODED_SECRET",
                title=title,
                severity=Severity.HIGH,
                file=self.filename,
                line=line,
                column=getattr(node, "col_offset", 0),
                snippet=snippet.strip(),
                description="A secret value appears to be hardcoded in the source code.",
                recommendation=(
                    "Move secrets to environment variables or a dedicated "
                    "secrets manager. Never commit credentials to source control."
                ),
            )
        )

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        for target in node.targets:
            name = ""
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr

            if name.lower() in self.SECRET_VAR_NAMES:
                if isinstance(node.value, ast.Constant) and isinstance(
                    node.value.value, str
                ):
                    if len(node.value.value) >= 4:
                        self._add(node, f"Hardcoded secret in '{name}'")

        self.generic_visit(node)


class SecretsScanner(BaseScanner):
    def scan(self, source: str, filename: str) -> list[Vulnerability]:
        lines = source.splitlines()
        findings: list[Vulnerability] = []

        # AST-based detection for Python
        if filename.endswith(".py"):
            try:
                tree = ast.parse(source, filename=filename)
                visitor = _SecretsASTVisitor(lines, filename)
                visitor.visit(tree)
                findings.extend(visitor.findings)
            except SyntaxError:
                pass

        # Regex-based detection for all file types
        for lineno, line in enumerate(lines, start=1):
            # Skip comments that look like documentation
            stripped = line.strip()
            if stripped.startswith("#") and "example" in stripped.lower():
                continue

            for pattern, title in _SECRET_PATTERNS:
                if pattern.search(line):
                    if not any(f.line == lineno for f in findings):
                        findings.append(
                            Vulnerability(
                                rule_id="HARDCODED_SECRET",
                                title=title,
                                severity=Severity.HIGH,
                                file=filename,
                                line=lineno,
                                snippet=stripped,
                                description="A secret value appears to be hardcoded in the source code.",
                                recommendation=(
                                    "Move secrets to environment variables or a "
                                    "secrets manager."
                                ),
                            )
                        )

        return findings
