from __future__ import annotations

from pathlib import Path

from .base import IaCParser, ResourceBlock


class KubernetesParser(IaCParser):
    def supports(self, file_path: Path) -> bool:
        return file_path.suffix.lower() in {".yaml", ".yml"}

    def parse(self, file_path: Path) -> list[ResourceBlock]:
        raise NotImplementedError("Kubernetes parsing is planned after the Terraform-first MVP.")
