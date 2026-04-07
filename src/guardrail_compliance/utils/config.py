from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

_CONFIG_FILENAMES = (".guardrail.yaml", ".guardrail.yml")


@dataclass(slots=True)
class EngineConfig:
    region: str = "us-east-1"
    policy_dir: Path = Path("policies")
    selected_policies: list[str] = field(default_factory=list)
    recursive: bool = True
    output_format: str = "console"
    use_bedrock: bool = True
    default_cross_region_profile: str | None = "us.guardrail.v1:0"

    def resolve_policy_dir(self, base_dir: Path | None = None) -> Path:
        if self.policy_dir.is_absolute():
            return self.policy_dir
        return (base_dir or Path.cwd()) / self.policy_dir

    @classmethod
    def from_yaml(cls, path: Path) -> dict[str, Any]:
        """Load a config YAML and return a dict of values (not an EngineConfig).

        Callers merge this with CLI args before constructing EngineConfig.
        """
        if not path.is_file():
            return {}
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            return {}
        return data


def find_config_file(start: Path | None = None) -> Path | None:
    """Walk up from *start* (default CWD) looking for a config file."""
    current = (start or Path.cwd()).resolve()
    for _ in range(20):  # cap depth to avoid infinite walk
        for name in _CONFIG_FILENAMES:
            candidate = current / name
            if candidate.is_file():
                return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None
