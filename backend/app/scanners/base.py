from __future__ import annotations

import abc

from app.models.schemas import Vulnerability


class BaseScanner(abc.ABC):
    """Abstract base class for all vulnerability scanners."""

    @abc.abstractmethod
    def scan(self, source: str, filename: str) -> list[Vulnerability]:
        """Scan source code and return a list of findings."""
