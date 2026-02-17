from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


class ScanRequest(BaseModel):
    repo_url: str = Field(..., description="GitHub repository URL to scan")


class Vulnerability(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    file: str
    line: int
    column: int = 0
    snippet: str = ""
    description: str = ""
    recommendation: str = ""


class ScanSummary(BaseModel):
    total: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanReport(BaseModel):
    scan_id: str
    status: str = "completed"
    source: str = ""
    files_scanned: int = 0
    summary: ScanSummary = Field(default_factory=ScanSummary)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: Optional[int] = None
