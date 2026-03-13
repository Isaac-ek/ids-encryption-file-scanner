from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, List, TypedDict

from utils import logger

Severity = Literal["info", "warn", "error"]


class ReportEntry(TypedDict):
    level: Severity
    message: str


@dataclass
class Reporter:
    """Collects scan messages and prints them to stdout."""

    entries: List[ReportEntry] = field(default_factory=list)

    def info(self, message: str) -> None:
        logger.info(message)
        self.entries.append({"level": "info", "message": message})

    def warn(self, message: str) -> None:
        logger.warn(message)
        self.entries.append({"level": "warn", "message": message})

    def error(self, message: str) -> None:
        logger.error(message)
        self.entries.append({"level": "error", "message": message})

    def as_text(self) -> str:
        return "\n".join(f"[{e['level'].upper()}] {e['message']}" for e in self.entries)

    def as_json(self) -> List[ReportEntry]:
        return self.entries
