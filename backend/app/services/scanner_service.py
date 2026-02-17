from __future__ import annotations

import shutil
import tempfile
import uuid
from pathlib import Path

import httpx

from app.models.schemas import (
    ScanReport,
    ScanSummary,
    Severity,
    Vulnerability,
)
from app.scanners import (
    SQLInjectionScanner,
    SecretsScanner,
    UnsafeFunctionsScanner,
    XSSScanner,
)
from app.utils.file_utils import collect_files, safe_read

# Global in-memory store for scan results
_scan_store: dict[str, ScanReport] = {}

ALL_SCANNERS = [
    SQLInjectionScanner(),
    SecretsScanner(),
    XSSScanner(),
    UnsafeFunctionsScanner(),
]


def _build_summary(vulns: list[Vulnerability]) -> ScanSummary:
    return ScanSummary(
        total=len(vulns),
        high=sum(1 for v in vulns if v.severity == Severity.HIGH),
        medium=sum(1 for v in vulns if v.severity == Severity.MEDIUM),
        low=sum(1 for v in vulns if v.severity == Severity.LOW),
    )


def _scan_directory(directory: str, source_label: str) -> ScanReport:
    scan_id = uuid.uuid4().hex[:12]
    files = collect_files(directory)
    all_vulns: list[Vulnerability] = []

    root = Path(directory)
    for fpath in files:
        content = safe_read(fpath)
        if content is None:
            continue
        relative = str(fpath.relative_to(root))
        for scanner in ALL_SCANNERS:
            all_vulns.extend(scanner.scan(content, relative))

    report = ScanReport(
        scan_id=scan_id,
        source=source_label,
        files_scanned=len(files),
        summary=_build_summary(all_vulns),
        vulnerabilities=all_vulns,
    )
    _scan_store[scan_id] = report
    return report


def scan_uploaded_files(saved_dir: str) -> ScanReport:
    return _scan_directory(saved_dir, source_label="file_upload")


async def scan_github_repo(repo_url: str) -> ScanReport:
    """Clone a public GitHub repo into a temp dir, scan, then clean up."""
    # Convert to an archive download URL to avoid needing git installed
    # Supports https://github.com/owner/repo style URLs
    url = repo_url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]

    archive_url = f"{url}/archive/refs/heads/main.zip"

    tmpdir = tempfile.mkdtemp(prefix="sentinel_")
    extract_dir = tmpdir
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=60) as client:
            # Try main branch, fall back to master
            resp = await client.get(archive_url)
            if resp.status_code != 200:
                archive_url = f"{url}/archive/refs/heads/master.zip"
                resp = await client.get(archive_url)

            if resp.status_code != 200:
                scan_id = uuid.uuid4().hex[:12]
                report = ScanReport(
                    scan_id=scan_id,
                    status="error",
                    source=repo_url,
                )
                _scan_store[scan_id] = report
                return report

            zip_path = Path(tmpdir) / "repo.zip"
            zip_path.write_bytes(resp.content)

            import zipfile

            with zipfile.ZipFile(zip_path) as zf:
                zf.extractall(tmpdir)

            # The archive extracts into a subdirectory like repo-main/
            subdirs = [
                d for d in Path(tmpdir).iterdir() if d.is_dir()
            ]
            if subdirs:
                extract_dir = str(subdirs[0])

        report = _scan_directory(extract_dir, source_label=repo_url)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return report


def get_report(scan_id: str) -> ScanReport | None:
    return _scan_store.get(scan_id)


def list_reports() -> list[ScanReport]:
    return list(_scan_store.values())
