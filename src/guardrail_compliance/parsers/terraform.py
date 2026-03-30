from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ..utils.exceptions import ParserError
from .base import IaCParser, ResourceBlock

try:
    import hcl2  # type: ignore
except ImportError:  # pragma: no cover - optional at runtime until deps are installed
    hcl2 = None


class TerraformParser(IaCParser):
    """Terraform parser for raw `.tf` files and basic plan JSON artifacts."""

    RESOURCE_PATTERN = re.compile(
        r'(?m)^\s*resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{'
    )

    def supports(self, file_path: Path) -> bool:
        if file_path.suffix.lower() == ".tf":
            return True
        return file_path.suffix.lower() == ".json" and "plan" in file_path.name.lower()

    def parse(self, file_path: Path) -> list[ResourceBlock]:
        if file_path.suffix.lower() == ".json":
            return self._parse_plan_json(file_path)
        return self._parse_hcl(file_path)

    def _parse_hcl(self, file_path: Path) -> list[ResourceBlock]:
        text = file_path.read_text(encoding="utf-8")
        structured = self._load_hcl_resources(text)
        resources: list[ResourceBlock] = []

        for match in self.RESOURCE_PATTERN.finditer(text):
            resource_type = match.group("type")
            resource_name = match.group("name")
            brace_start = text.find("{", match.start())
            brace_end = self._find_matching_brace(text, brace_start)
            if brace_end is None:
                raise ParserError(f"Unmatched brace while parsing {file_path}")

            raw_block = text[match.start() : brace_end + 1]
            line_number = text.count("\n", 0, match.start()) + 1
            properties = structured.get(
                (resource_type, resource_name),
                self._heuristic_properties(raw_block),
            )
            resources.append(
                ResourceBlock(
                    resource_type=resource_type,
                    resource_name=resource_name,
                    raw_text=raw_block,
                    properties=properties,
                    file_path=file_path,
                    line_number=line_number,
                )
            )

        return resources

    def _parse_plan_json(self, file_path: Path) -> list[ResourceBlock]:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
        resources: list[ResourceBlock] = []

        for resource in payload.get("resource_changes", []):
            change = resource.get("change", {})
            values = change.get("after") or change.get("before") or {}
            resources.append(
                ResourceBlock(
                    resource_type=resource.get("type", "unknown"),
                    resource_name=resource.get("name", resource.get("address", "unnamed")),
                    raw_text=json.dumps(values, indent=2, sort_keys=True),
                    properties=values,
                    file_path=file_path,
                    line_number=None,
                )
            )

        if not resources and payload.get("planned_values", {}).get("root_module"):
            for resource in payload["planned_values"]["root_module"].get("resources", []):
                values = resource.get("values", {})
                resources.append(
                    ResourceBlock(
                        resource_type=resource.get("type", "unknown"),
                        resource_name=resource.get("name", resource.get("address", "unnamed")),
                        raw_text=json.dumps(values, indent=2, sort_keys=True),
                        properties=values,
                        file_path=file_path,
                        line_number=None,
                    )
                )

        return resources

    def _load_hcl_resources(self, text: str) -> dict[tuple[str, str], dict[str, Any]]:
        if hcl2 is None:
            return {}

        try:
            data = hcl2.loads(text)
        except Exception:
            return {}

        structured: dict[tuple[str, str], dict[str, Any]] = {}
        resources = data.get("resource", [])
        iterable = resources if isinstance(resources, list) else [resources]

        for item in iterable:
            if not isinstance(item, dict):
                continue
            for resource_type, named_resources in item.items():
                if not isinstance(named_resources, dict):
                    continue
                for resource_name, properties in named_resources.items():
                    structured[(resource_type, resource_name)] = properties if isinstance(properties, dict) else {}

        return structured

    def _find_matching_brace(self, text: str, brace_start: int) -> int | None:
        depth = 0
        in_string = False
        escape = False

        for index in range(brace_start, len(text)):
            char = text[index]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue

            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index

        return None

    def _heuristic_properties(self, block_text: str) -> dict[str, Any]:
        properties: dict[str, Any] = {}
        nested_blocks: dict[str, list[dict[str, Any]]] = {}
        current_block: str | None = None

        for raw_line in block_text.splitlines()[1:]:
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            if line == "}":
                current_block = None
                continue
            if line.endswith("{") and "=" not in line:
                current_block = line[:-1].strip()
                nested_blocks.setdefault(current_block, []).append({})
                continue
            if "=" not in line:
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            parsed_value = self._parse_scalar(value.rstrip(","))
            if current_block and nested_blocks.get(current_block):
                nested_blocks[current_block][-1][key] = parsed_value
            else:
                properties[key] = parsed_value

        properties.update(nested_blocks)
        return properties

    def _parse_scalar(self, value: str) -> Any:
        lowered = value.lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        if value.startswith('"') and value.endswith('"'):
            return value[1:-1]
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            if not inner:
                return []
            return [self._parse_scalar(part.strip()) for part in inner.split(",")]
        try:
            if "." in value:
                return float(value)
            return int(value)
        except ValueError:
            return value
