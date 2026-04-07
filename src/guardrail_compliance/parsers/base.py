from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Matches lines like:  # guardrail:ignore  or  # guardrail:ignore SOC2-ENC-001, SOC2-LOG-001
_SUPPRESS_RE = re.compile(r"#\s*guardrail:ignore\b[ \t]*([^\n]*)", re.IGNORECASE)


@dataclass(slots=True)
class ResourceBlock:
    """A single infrastructure resource extracted from an IaC file."""

    resource_type: str
    resource_name: str
    raw_text: str
    properties: dict[str, Any]
    file_path: Path
    line_number: int | None = None
    suppressed_rules: set[str] = field(default_factory=set)

    @property
    def suppress_all(self) -> bool:
        return "*" in self.suppressed_rules


def parse_suppressions(raw_text: str) -> set[str]:
    """Extract suppressed rule IDs from inline ``# guardrail:ignore`` comments.

    Returns ``{"*"}`` for a bare ``# guardrail:ignore`` (suppress everything),
    or a set of specific rule IDs like ``{"SOC2-ENC-001", "SOC2-LOG-001"}``.
    """
    suppressed: set[str] = set()
    for match in _SUPPRESS_RE.finditer(raw_text):
        ids = match.group(1).strip()
        if not ids:
            suppressed.add("*")
        else:
            suppressed.update(rule_id.strip() for rule_id in ids.split(",") if rule_id.strip())
    return suppressed


class IaCParser(ABC):
    """Abstract base class for IaC parsers."""

    @abstractmethod
    def parse(self, file_path: Path) -> list[ResourceBlock]:
        raise NotImplementedError

    @abstractmethod
    def supports(self, file_path: Path) -> bool:
        raise NotImplementedError
