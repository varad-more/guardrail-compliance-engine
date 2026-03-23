from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ResourceBlock:
    """A single infrastructure resource extracted from an IaC file."""

    resource_type: str
    resource_name: str
    raw_text: str
    properties: dict[str, Any]
    file_path: Path
    line_number: int | None = None


class IaCParser(ABC):
    """Abstract base class for IaC parsers."""

    @abstractmethod
    def parse(self, file_path: Path) -> list[ResourceBlock]:
        raise NotImplementedError

    @abstractmethod
    def supports(self, file_path: Path) -> bool:
        raise NotImplementedError
