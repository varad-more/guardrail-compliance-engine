from __future__ import annotations

from pathlib import Path

from .base import IaCParser, ResourceBlock


class CloudFormationParser(IaCParser):
    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in {".json", ".yaml", ".yml"}

    def parse(self, file_path: Path) -> list[ResourceBlock]:
        raise NotImplementedError("CloudFormation parsing is planned after the Terraform-first MVP.")
