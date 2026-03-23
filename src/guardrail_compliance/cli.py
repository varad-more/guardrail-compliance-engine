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
from .core.policy_manager import PolicyManager
from .policies.registry import PolicyRegistry
from .reporting import build_html_report, build_json_report, build_sarif_report, render_scan_results
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
    format: str = typer.Option("console", "--format", help="Output format: console, json, sarif, or html."),
    output: Optional[Path] = typer.Option(None, "--output", help="Optional file to write output into."),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive", help="Recurse into directories."),
    region: str = typer.Option("us-east-1", "--region", help="AWS region for Bedrock calls."),
    policy_dir: Path = typer.Option(Path("policies"), "--policy-dir", help="Directory containing YAML policy files."),
    use_bedrock: bool = typer.Option(True, "--bedrock/--no-bedrock", help="Use Bedrock when policies have guardrail bindings."),
    explain: bool = typer.Option(False, "--explain", help="Show normalized facts and narrative in console output."),
    fail_on_findings: bool = typer.Option(False, "--fail-on-findings/--no-fail-on-findings", help="Exit non-zero when findings fail."),
) -> None:
    results = _run_scan(
        path=path,
        policies=policy,
        format=format,
        recursive=recursive,
        region=region,
        policy_dir=policy_dir,
        use_bedrock=use_bedrock,
    )
    _emit_output(results, format=format, output=output, explain=explain)
    if fail_on_findings and any(result.has_failures for result in results):
        raise typer.Exit(code=1)


@app.command()
def audit(
    path: Path = typer.Argument(..., exists=True, readable=True, help="File or directory to audit."),
    frameworks: str = typer.Option(..., "--frameworks", help="Comma-separated policy names/framework shortcuts."),
    format: str = typer.Option("console", "--format", help="Output format: console, json, sarif, or html."),
    output: Optional[Path] = typer.Option(None, "--output", help="Optional file to write output into."),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive"),
    region: str = typer.Option("us-east-1", "--region"),
    policy_dir: Path = typer.Option(Path("policies"), "--policy-dir"),
    use_bedrock: bool = typer.Option(True, "--bedrock/--no-bedrock"),
) -> None:
    registry = PolicyRegistry(_resolve_policy_dir(policy_dir))
    available = registry.all()
    wanted = [item.strip() for item in frameworks.split(",") if item.strip()]
    selected: list[str] = []
    for target in wanted:
        target_lower = _normalize_name(target)
        for policy in available:
            if _normalize_name(policy.name) == target_lower or _normalize_name(policy.framework).startswith(target_lower):
                selected.append(policy.name)
    selected = sorted(set(selected))
    if not selected:
        console.print(f"[red]No policies matched:[/red] {frameworks}")
        raise typer.Exit(code=1)

    results = _run_scan(
        path=path,
        policies=selected,
        format=format,
        recursive=recursive,
        region=region,
        policy_dir=policy_dir,
        use_bedrock=use_bedrock,
    )
    _emit_output(results, format=format, output=output, explain=False)


@policy_app.command("list")
def list_policies(policy_dir: Path = typer.Option(Path("policies"), "--policy-dir")) -> None:
    registry = PolicyRegistry(_resolve_policy_dir(policy_dir))
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
    registry = PolicyRegistry(_resolve_policy_dir(policy_dir))
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


@policy_app.command("sync")
def sync_policies(
    policy_dir: Path = typer.Option(Path("policies"), "--policy-dir"),
    region: str = typer.Option("us-east-1", "--region"),
) -> None:
    try:
        manager = PolicyManager(region=region)
        mapping = manager.sync_policies(_resolve_policy_dir(policy_dir))
    except GuardrailComplianceError as exc:
        console.print(f"[red]Sync failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if not mapping:
        console.print("[yellow]No policies were synced.[/yellow] Add versioned automated_reasoning_policy_arn values to policy YAML files first.")
        return

    table = Table(title="Synced guardrails")
    table.add_column("Policy", style="cyan")
    table.add_column("Guardrail ID")
    for name, guardrail_id in mapping.items():
        table.add_row(name, guardrail_id)
    console.print(table)


@policy_app.command("ar-list")
def ar_list(region: str = typer.Option("us-east-1", "--region")) -> None:
    manager = PolicyManager(region=region)
    try:
        policies = manager.list_automated_reasoning_policies()
    except GuardrailComplianceError as exc:
        console.print(f"[red]AR list failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if not policies:
        console.print("[yellow]No automated reasoning policies found.[/yellow]")
        return

    table = Table(title="Automated Reasoning Policies")
    table.add_column("Name", style="cyan")
    table.add_column("Version")
    table.add_column("Policy ARN")
    table.add_column("Policy ID")
    for policy in policies:
        table.add_row(policy.name, policy.version, policy.policy_arn, policy.policy_id or "—")
    console.print(table)


@policy_app.command("ar-create")
def ar_create(
    name: str = typer.Option(..., "--name", help="Automated Reasoning policy name."),
    description: str = typer.Option("", "--description", help="Optional policy description."),
    source_file: Optional[Path] = typer.Option(None, "--source-file", exists=True, readable=True, help="Optional source file (txt/pdf) to ingest immediately."),
    region: str = typer.Option("us-east-1", "--region"),
) -> None:
    manager = PolicyManager(region=region)
    try:
        policy_arn = manager.create_automated_reasoning_policy(name=name, description=description or None)
    except GuardrailComplianceError as exc:
        console.print(f"[red]AR create failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]Created AR policy:[/green] {policy_arn}")

    if source_file:
        try:
            workflow_id = manager.start_automated_reasoning_ingest_build_from_file(
                policy_arn=policy_arn,
                source_file=source_file,
            )
        except GuardrailComplianceError as exc:
            console.print(f"[red]Build workflow start failed:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        console.print(f"[green]Started ingest build workflow:[/green] {workflow_id}")


@policy_app.command("ar-build-status")
def ar_build_status(
    policy_arn: str = typer.Option(..., "--policy-arn"),
    workflow_id: str = typer.Option(..., "--workflow-id"),
    region: str = typer.Option("us-east-1", "--region"),
) -> None:
    manager = PolicyManager(region=region)
    try:
        data = manager.get_automated_reasoning_policy_build_workflow(policy_arn=policy_arn, workflow_id=workflow_id)
    except GuardrailComplianceError as exc:
        console.print(f"[red]Build workflow lookup failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="Automated Reasoning Build Workflow")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    for key in ["policyArn", "buildWorkflowId", "status", "buildWorkflowType", "createdAt", "updatedAt"]:
        if key in data and data[key] is not None:
            table.add_row(key, str(data[key]))
    console.print(table)


@policy_app.command("ar-version")
def ar_version(
    policy_arn: str = typer.Option(..., "--policy-arn"),
    definition_hash: Optional[str] = typer.Option(None, "--definition-hash", help="Optional definition hash; if omitted, latest hash is fetched first."),
    region: str = typer.Option("us-east-1", "--region"),
) -> None:
    manager = PolicyManager(region=region)
    try:
        if definition_hash:
            version = manager.create_automated_reasoning_policy_version(policy_arn=policy_arn, definition_hash=definition_hash)
        else:
            version = manager.create_automated_reasoning_policy_version_from_latest(policy_arn=policy_arn)
    except GuardrailComplianceError as exc:
        console.print(f"[red]AR version creation failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(f"[green]Created policy version:[/green] {version}")


@policy_app.command("ar-export")
def ar_export(
    policy_version_arn: str = typer.Option(..., "--policy-version-arn", help="Versioned policy ARN ending with :<version>."),
    output: Optional[Path] = typer.Option(None, "--output", help="Optional JSON output path."),
    region: str = typer.Option("us-east-1", "--region"),
) -> None:
    manager = PolicyManager(region=region)
    try:
        definition = manager.export_automated_reasoning_policy_version(policy_version_arn)
    except GuardrailComplianceError as exc:
        console.print(f"[red]AR export failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    payload = json.dumps(definition, indent=2)
    if output:
        output.write_text(payload, encoding="utf-8")
        console.print(f"Wrote exported policy definition to {output}")
    else:
        typer.echo(payload)


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


def _run_scan(
    *,
    path: Path,
    policies: list[str],
    format: str,
    recursive: bool,
    region: str,
    policy_dir: Path,
    use_bedrock: bool,
):
    try:
        config = EngineConfig(
            region=region,
            policy_dir=_resolve_policy_dir(policy_dir),
            selected_policies=policies,
            recursive=recursive,
            output_format=format,
            use_bedrock=use_bedrock,
        )
        engine = ComplianceEngine(config)
        if path.is_dir():
            return asyncio.run(engine.scan_directory(path, recursive=recursive))
        return [asyncio.run(engine.scan(path))]
    except GuardrailComplianceError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


def _emit_output(results, *, format: str, output: Optional[Path], explain: bool) -> None:
    if format == "json":
        payload = json.dumps(build_json_report(results), indent=2)
    elif format == "sarif":
        payload = json.dumps(build_sarif_report(results), indent=2)
    elif format == "html":
        payload = build_html_report(results)
    elif format == "console":
        render_scan_results(results, console=console, explain=explain)
        return
    else:
        console.print(f"[red]Unsupported format:[/red] {format}")
        raise typer.Exit(code=1)

    if output:
        output.write_text(payload, encoding="utf-8")
        console.print(f"Wrote {format.upper()} report to {output}")
    else:
        typer.echo(payload)


def _resolve_policy_dir(policy_dir: Path) -> Path:
    if policy_dir == Path("policies"):
        return PolicyRegistry.default().policy_dir
    return policy_dir


def _normalize_name(value: str) -> str:
    return "".join(ch for ch in value.lower() if ch.isalnum())


if __name__ == "__main__":  # pragma: no cover
    app()
