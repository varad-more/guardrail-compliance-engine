from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..utils.exceptions import ParserError
from .base import IaCParser, ResourceBlock, parse_suppressions


class KubernetesParser(IaCParser):
    """Parse Kubernetes multi-document YAML manifests into resource blocks."""
    def supports(self, file_path: Path) -> bool:
        if file_path.suffix.lower() not in {".yaml", ".yml"}:
            return False
        try:
            documents = self._load_documents(file_path)
        except ParserError:
            return False
        return any(isinstance(doc, dict) and doc.get("kind") for doc in documents)

    def parse(self, file_path: Path) -> list[ResourceBlock]:
        source_text = file_path.read_text(encoding="utf-8")
        documents = self._load_documents(file_path)
        chunks = self._split_documents(source_text)
        results: list[ResourceBlock] = []

        for index, document in enumerate(documents):
            if not isinstance(document, dict):
                continue
            kind = document.get("kind")
            metadata = document.get("metadata", {}) if isinstance(document.get("metadata"), dict) else {}
            if not kind:
                continue
            name = metadata.get("name", f"unnamed-{index + 1}")
            raw_text = chunks[index] if index < len(chunks) else yaml.safe_dump(document, sort_keys=False).strip()
            line_number = self._find_line_number(source_text, raw_text)
            results.append(
                ResourceBlock(
                    resource_type=str(kind),
                    resource_name=str(name),
                    raw_text=raw_text,
                    properties=document,
                    file_path=file_path,
                    line_number=line_number,
                    suppressed_rules=parse_suppressions(raw_text),
                )
            )
        return results

    def _load_documents(self, file_path: Path) -> list[dict[str, Any]]:
        text = file_path.read_text(encoding="utf-8")
        try:
            documents = list(yaml.safe_load_all(text))
        except Exception as exc:  # pragma: no cover
            raise ParserError(f"Unable to parse Kubernetes manifest {file_path}: {exc}") from exc
        return documents

    def _split_documents(self, source_text: str) -> list[str]:
        parts = [part.strip() for part in source_text.split("---") if part.strip()]
        return parts

    def _find_line_number(self, source_text: str, raw_text: str) -> int | None:
        snippet = raw_text.splitlines()[0] if raw_text else ""
        index = source_text.find(snippet)
        if index == -1:
            return None
        return source_text.count("\n", 0, index) + 1
