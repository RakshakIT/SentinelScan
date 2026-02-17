from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, File

from app.models.schemas import ScanReport, ScanRequest
from app.services.scanner_service import (
    get_report,
    list_reports,
    scan_github_repo,
    scan_uploaded_files,
)

router = APIRouter(prefix="/api")


@router.post("/scan/upload", response_model=ScanReport)
async def upload_scan(files: list[UploadFile] = File(...)):
    """Upload one or more source files to scan for vulnerabilities."""
    tmpdir = tempfile.mkdtemp(prefix="sentinel_upload_")
    try:
        for f in files:
            dest = Path(tmpdir) / (f.filename or "unknown")
            dest.parent.mkdir(parents=True, exist_ok=True)
            content = await f.read()
            dest.write_bytes(content)

        report = scan_uploaded_files(tmpdir)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return report


@router.post("/scan/repo", response_model=ScanReport)
async def repo_scan(request: ScanRequest):
    """Scan a public GitHub repository by URL."""
    report = await scan_github_repo(request.repo_url)
    if report.status == "error":
        raise HTTPException(
            status_code=400,
            detail="Could not fetch repository. Ensure the URL is a valid public GitHub repo.",
        )
    return report


@router.get("/reports", response_model=list[ScanReport])
async def get_reports():
    """List all scan reports."""
    return list_reports()


@router.get("/reports/{scan_id}", response_model=ScanReport)
async def get_report_by_id(scan_id: str):
    """Get a specific scan report by ID."""
    report = get_report(scan_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@router.get("/health")
async def health():
    return {"status": "ok"}
