from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from ..core.models import ScanResult


def build_json_report(results: Iterable[ScanResult]) -> list[dict[str, Any]]:
    """Serialise scan results into a JSON-friendly list of dicts."""
    return [_convert(result) for result in results]


def _convert(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return {key: _convert(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {key: _convert(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_convert(item) for item in value]
    return value
