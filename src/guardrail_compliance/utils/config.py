from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


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
