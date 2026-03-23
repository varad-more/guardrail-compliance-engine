from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

from .core.engine import ComplianceEngine
from .policies.registry import PolicyRegistry
from .reporting.console import render_scan_results
from .reporting.json_report import build_json_report
from .utils.config import EngineConfig
from .utils.exceptions import GuardrailComplianceError, PolicyValidationError

app = typer.Typer(help="GuardRail Compliance Engine")
policy_app = typer.Typer(help="Policy management commands")
app.add_typer(policy_app, name="policy")
console = Console()


@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, readable=True, help="File or directory to scan."),
    policy: list[str] = typer.Option([], "--policy", help="Policy name to apply. Repeat for multiple policies."),
    format: str = typer.Option("console", "--format", help="Output format: console or json."),
    output: Optional[Path] = typer.Option(None, "--output", help="Optional file to write output into."),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive", help="Recurse into directories."),
    region: str = typer.Option("us-east-1", "--region", help="AWS region for Bedrock calls."),
    policy_dir: Path = typer.Option(Path("policies"), "--policy-dir", help="Directory containing YAML policy files."),
    use_bedrock: bool = typer.Option(True, "--bedrock/--no-bedrock", help="Use Bedrock when policies have guardrail bindings."),
    fail_on_findings: bool = typer.Option(False, "--fail-on-findings/--no-fail-on-findings", help="Exit non-zero when findings fail."),
) -> None:
    try:
        config = EngineConfig(
            region=region,
            policy_dir=policy_dir,
            selected_policies=policy,
            recursive=recursive,
            output_format=format,
            use_bedrock=use_bedrock,
        )
        engine = ComplianceEngine(config)
        if path.is_dir():
            results = asyncio.run(engine.scan_directory(path, recursive=recursive))
        else:
            results = [asyncio.run(engine.scan(path))]

        if format == "json":
            payload = json.dumps(build_json_report(results), indent=2)
            if output:
                output.write_text(payload, encoding="utf-8")
                console.print(f"Wrote JSON report to {output}")
            else:
                console.print(payload)
        else:
            render_scan_results(results, console=console)

        if fail_on_findings and any(result.has_failures for result in results):
            raise typer.Exit(code=1)
    except GuardrailComplianceError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


@policy_app.command("list")
def list_policies(policy_dir: Path = typer.Option(Path("policies"), "--policy-dir")) -> None:
    registry = PolicyRegistry(PolicyRegistry.default().policy_dir if policy_dir == Path("policies") else policy_dir)
    table = Table(title="Policies")
    table.add_column("Name", style="cyan")
    table.add_column("Framework")
    table.add_column("Rules", justify="right")
    table.add_column("Bedrock binding")
    for policy in registry.all():
        binding = policy.guardrail_id or policy.automated_reasoning_policy_arn or "—"
        table.add_row(policy.name, policy.framework, str(len(policy.rules)), binding)
    console.print(table)


@policy_app.command("show")
def show_policy(name: str, policy_dir: Path = typer.Option(Path("policies"), "--policy-dir")) -> None:
    registry = PolicyRegistry(PolicyRegistry.default().policy_dir if policy_dir == Path("policies") else policy_dir)
    policy = registry.get(name)
    console.print(f"[bold]{policy.name}[/bold] ({policy.framework})")
    console.print(policy.description)
    for rule in policy.rules:
        console.print(f"- [bold]{rule.id}[/bold] [{rule.severity}] {rule.title}")
        console.print(f"  {rule.description}")


@policy_app.command("validate")
def validate_policy(path: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    registry = PolicyRegistry(path.parent)
    try:
        registry.load_policy(path)
    except PolicyValidationError as exc:
        console.print(f"[red]Invalid policy:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Policy is valid:[/green] {path}")


@app.command()
def init(target: Path = typer.Argument(Path(".guardrail.yaml"), help="Config file to create.")) -> None:
    if target.exists():
        console.print(f"[yellow]Skipped:[/yellow] {target} already exists")
        raise typer.Exit(code=0)
    template = {
        "region": "us-east-1",
        "policies": ["soc2-basic"],
        "policy_dir": "policies",
        "use_bedrock": True,
    }
    target.write_text(yaml.safe_dump(template, sort_keys=False), encoding="utf-8")
    console.print(f"[green]Created[/green] {target}")


if __name__ == "__main__":  # pragma: no cover
    app()
