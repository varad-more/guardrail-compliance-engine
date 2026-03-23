from __future__ import annotations

from typing import Any, Iterable

from ..core.models import ScanResult


def build_sarif_report(results: Iterable[ScanResult]) -> dict[str, Any]:
    """Placeholder for the next implementation chunk."""
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [],
    }
