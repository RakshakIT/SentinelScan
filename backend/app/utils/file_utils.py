from __future__ import annotations

import os
from pathlib import Path

# Extensions we know how to meaningfully scan
SCANNABLE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".html",
    ".htm",
    ".php",
    ".rb",
    ".java",
    ".go",
    ".rs",
    ".c",
    ".cpp",
    ".cs",
    ".yml",
    ".yaml",
    ".json",
    ".xml",
    ".env",
    ".cfg",
    ".ini",
    ".toml",
    ".sh",
    ".bash",
    ".sql",
}

MAX_FILE_SIZE = 1_000_000  # 1 MB


def is_scannable(path: str) -> bool:
    ext = os.path.splitext(path)[1].lower()
    return ext in SCANNABLE_EXTENSIONS


def collect_files(root: str) -> list[Path]:
    """Recursively collect scannable files under *root*."""
    results: list[Path] = []
    root_path = Path(root)
    for path in root_path.rglob("*"):
        if not path.is_file():
            continue
        if path.stat().st_size > MAX_FILE_SIZE:
            continue
        # Skip hidden directories and common non-source directories
        parts = path.relative_to(root_path).parts
        if any(
            p.startswith(".") or p in ("node_modules", "__pycache__", "venv", ".git")
            for p in parts
        ):
            continue
        if is_scannable(str(path)):
            results.append(path)
    return results


def safe_read(path: Path) -> str | None:
    """Read a file, returning None on decode errors."""
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
