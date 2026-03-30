from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from ..utils.exceptions import ParserError
from .base import IaCParser, ResourceBlock


class CloudFormationParser(IaCParser):
    """Parse AWS CloudFormation templates (JSON and YAML) into resource blocks."""
    def supports(self, file_path: Path) -> bool:
        suffix = file_path.suffix.lower()
        if suffix not in {".json", ".yaml", ".yml"}:
            return False
        try:
            document = self._load_document(file_path)
        except ParserError:
            return False
        return isinstance(document, dict) and "Resources" in document

    def parse(self, file_path: Path) -> list[ResourceBlock]:
        document = self._load_document(file_path)
        resources = document.get("Resources")
        if not isinstance(resources, dict):
            raise ParserError(f"CloudFormation template missing Resources section: {file_path}")

        source_text = file_path.read_text(encoding="utf-8")
        results: list[ResourceBlock] = []
        for logical_id, definition in resources.items():
            if not isinstance(definition, dict):
                continue
            resource_type = definition.get("Type", "Unknown")
            properties = definition.get("Properties", {}) if isinstance(definition.get("Properties", {}), dict) else {}
            line_number = self._find_line_number(source_text, logical_id)
            raw_text = yaml.safe_dump({logical_id: definition}, sort_keys=False).strip()
            results.append(
                ResourceBlock(
                    resource_type=str(resource_type),
                    resource_name=str(logical_id),
                    raw_text=raw_text,
                    properties=properties,
                    file_path=file_path,
                    line_number=line_number,
                )
            )
        return results

    def _load_document(self, file_path: Path) -> dict[str, Any]:
        text = file_path.read_text(encoding="utf-8")
        try:
            if file_path.suffix.lower() == ".json":
                document = json.loads(text)
            else:
                document = yaml.safe_load(text)
        except Exception as exc:  # pragma: no cover - parser error path
            raise ParserError(f"Unable to parse CloudFormation template {file_path}: {exc}") from exc
        if not isinstance(document, dict):
            raise ParserError(f"CloudFormation template must be a mapping: {file_path}")
        return document

    def _find_line_number(self, source_text: str, logical_id: str) -> int | None:
        marker = f"{logical_id}:"
        index = source_text.find(marker)
        if index == -1:
            marker = f'"{logical_id}"'
            index = source_text.find(marker)
        if index == -1:
            return None
        return source_text.count("\n", 0, index) + 1
