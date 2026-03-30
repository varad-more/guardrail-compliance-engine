"""Command-line interface for the GuardRail Compliance Engine."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

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
from .utils.logging_config import setup_logging

app = typer.Typer(help="GuardRail Compliance Engine")
policy_app = typer.Typer(help="Policy management commands")
app.add_typer(policy_app, name="policy")
console = Console()


# -----------------------------------------------------------------------
# Core scan / audit commands
# -----------------------------------------------------------------------

@app.command()
def scan(
    path: Path = typer.Argument(..., exists=True, readable=True, help="File or directory to scan."),
    policy: list[str] = typer.Option([], "--policy", help="Policy name to apply. Repeat for multiple."),
    format: str = typer.Option("console", "--format", help="Output format: console, json, sarif, or html."),
    output: Path | None = typer.Option(None, "--output", help="Write output to a file."),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive", help="Recurse into directories."),
    region: str = typer.Option("us-east-1", "--region", help="AWS region for Bedrock calls."),
    policy_dir: Path = typer.Option(Path("policies"), "--policy-dir", help="Directory with YAML policy files."),
    use_bedrock: bool = typer.Option(True, "--bedrock/--no-bedrock", help="Use Bedrock for guardrail-bound policies."),
    explain: bool = typer.Option(False, "--explain", help="Show normalised facts in console output."),
    fail_on_findings: bool = typer.Option(False, "--fail-on-findings/--no-fail-on-findings", help="Exit non-zero on failures."),
    log_level: str = typer.Option("WARNING", "--log-level", help="Logging level: DEBUG, INFO, WARNING, ERROR."),
) -> None:
    """Scan IaC files against configured compliance policies."""
    setup_logging(log_level)
    results = _run_scan(path=path, policies=policy, format=format, recursive=recursive,
                        region=region, policy_dir=policy_dir, use_bedrock=use_bedrock)
    _emit_output(results, format=format, output=output, explain=explain)
    if fail_on_findings and any(r.has_failures for r in results):
        raise typer.Exit(code=1)


@app.command()
def audit(
    path: Path = typer.Argument(..., exists=True, readable=True, help="File or directory to audit."),
    frameworks: str = typer.Option(..., "--frameworks", help="Comma-separated policy names or framework shortcuts."),
    format: str = typer.Option("console", "--format", help="Output format: console, json, sarif, or html."),
    output: Path | None = typer.Option(None, "--output", help="Write output to a file."),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive"),
    region: str = typer.Option("us-east-1", "--region"),
    policy_dir: Path = typer.Option(Path("policies"), "--policy-dir"),
    use_bedrock: bool = typer.Option(True, "--bedrock/--no-bedrock"),
    log_level: str = typer.Option("WARNING", "--log-level", help="Logging level: DEBUG, INFO, WARNING, ERROR."),
) -> None:
    """Run a multi-framework compliance audit."""
    setup_logging(log_level)
    registry = PolicyRegistry(_resolve_policy_dir(policy_dir))
    wanted = [t.strip() for t in frameworks.split(",") if t.strip()]
    selected: list[str] = []
    for target in wanted:
        norm = _normalize_name(target)
        for p in registry.all():
            if _normalize_name(p.name) == norm or _normalize_name(p.framework).startswith(norm):
                selected.append(p.name)
    selected = sorted(set(selected))

    if not selected:
        console.print(f"[red]No policies matched:[/red] {frameworks}")
        raise typer.Exit(code=1)

    results = _run_scan(path=path, policies=selected, format=format, recursive=recursive,
                        region=region, policy_dir=policy_dir, use_bedrock=use_bedrock)
    _emit_output(results, format=format, output=output, explain=False)


@app.command()
def init(target: Path = typer.Argument(Path(".guardrail.yaml"), help="Config file to create.")) -> None:
    """Scaffold a starter .guardrail.yaml config file."""
    if target.exists():
        console.print(f"[yellow]Skipped:[/yellow] {target} already exists")
        raise typer.Exit(code=0)
    template = {"region": "us-east-1", "policies": ["soc2-basic"], "policy_dir": "policies", "use_bedrock": True}
    target.write_text(yaml.safe_dump(template, sort_keys=False), encoding="utf-8")
    console.print(f"[green]Created[/green] {target}")


# -----------------------------------------------------------------------
# Policy management sub-commands
# -----------------------------------------------------------------------

@policy_app.command("list")
def list_policies(policy_dir: Path = typer.Option(Path("policies"), "--policy-dir")) -> None:
    """List all available policies and their Bedrock bindings."""
    registry = PolicyRegistry(_resolve_policy_dir(policy_dir))
    table = Table(title="Policies")
    table.add_column("Name", style="cyan")
    table.add_column("Framework")
    table.add_column("Rules", justify="right")
    table.add_column("Bedrock binding")
    for p in registry.all():
        table.add_row(p.name, p.framework, str(len(p.rules)), p.guardrail_id or p.automated_reasoning_policy_arn or "—")
    console.print(table)


@policy_app.command("show")
def show_policy(name: str, policy_dir: Path = typer.Option(Path("policies"), "--policy-dir")) -> None:
    """Display details for a single policy."""
    policy = PolicyRegistry(_resolve_policy_dir(policy_dir)).get(name)
    console.print(f"[bold]{policy.name}[/bold] ({policy.framework})")
    console.print(policy.description)
    for rule in policy.rules:
        console.print(f"- [bold]{rule.id}[/bold] [{rule.severity}] {rule.title}")
        console.print(f"  {rule.description}")


@policy_app.command("validate")
def validate_policy(path: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """Validate a single policy YAML file."""
    try:
        PolicyRegistry(path.parent).load_policy(path)
    except PolicyValidationError as exc:
        console.print(f"[red]Invalid policy:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Policy is valid:[/green] {path}")


@policy_app.command("sync")
def sync_policies(
    policy_dir: Path = typer.Option(Path("policies"), "--policy-dir"),
    region: str = typer.Option("us-east-1", "--region"),
) -> None:
    """Sync local policy definitions to Bedrock guardrails."""
    try:
        mapping = PolicyManager(region=region).sync_policies(_resolve_policy_dir(policy_dir))
    except GuardrailComplianceError as exc:
        console.print(f"[red]Sync failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if not mapping:
        console.print("[yellow]No policies synced.[/yellow] Add automated_reasoning_policy_arn to your YAML files first.")
        return

    table = Table(title="Synced guardrails")
    table.add_column("Policy", style="cyan")
    table.add_column("Guardrail ID")
    for name, gid in mapping.items():
        table.add_row(name, gid)
    console.print(table)


# -----------------------------------------------------------------------
# Automated Reasoning (AR) lifecycle sub-commands
# -----------------------------------------------------------------------

@policy_app.command("ar-list")
def ar_list(region: str = typer.Option("us-east-1", "--region")) -> None:
    """List Automated Reasoning policies in the account."""
    try:
        policies = PolicyManager(region=region).list_automated_reasoning_policies()
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
    for p in policies:
        table.add_row(p.name, p.version, p.policy_arn, p.policy_id or "—")
    console.print(table)


@policy_app.command("ar-create")
def ar_create(
    name: str = typer.Option(..., "--name", help="Automated Reasoning policy name."),
    description: str = typer.Option("", "--description", help="Optional policy description."),
    source_file: Path | None = typer.Option(None, "--source-file", exists=True, readable=True, help="Source file (txt/pdf) to ingest."),
    region: str = typer.Option("us-east-1", "--region"),
) -> None:
    """Create a new Automated Reasoning policy and optionally start an ingest build."""
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
                policy_arn=policy_arn, source_file=source_file)
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
    """Check the status of an AR ingest build workflow."""
    try:
        data = PolicyManager(region=region).get_automated_reasoning_policy_build_workflow(
            policy_arn=policy_arn, workflow_id=workflow_id)
    except GuardrailComplianceError as exc:
        console.print(f"[red]Build workflow lookup failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title="Automated Reasoning Build Workflow")
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    for key in ("policyArn", "buildWorkflowId", "status", "buildWorkflowType", "createdAt", "updatedAt"):
        if data.get(key) is not None:
            table.add_row(key, str(data[key]))
    console.print(table)


@policy_app.command("ar-version")
def ar_version(
    policy_arn: str = typer.Option(..., "--policy-arn"),
    definition_hash: str | None = typer.Option(None, "--definition-hash", help="Definition hash; if omitted, latest is fetched."),
    region: str = typer.Option("us-east-1", "--region"),
) -> None:
    """Create a new versioned snapshot of an AR policy."""
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
    output: Path | None = typer.Option(None, "--output", help="Optional JSON output path."),
    region: str = typer.Option("us-east-1", "--region"),
) -> None:
    """Export a versioned AR policy definition as JSON."""
    try:
        definition = PolicyManager(region=region).export_automated_reasoning_policy_version(policy_version_arn)
    except GuardrailComplianceError as exc:
        console.print(f"[red]AR export failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    payload = json.dumps(definition, indent=2)
    if output:
        output.write_text(payload, encoding="utf-8")
        console.print(f"Wrote exported policy definition to {output}")
    else:
        typer.echo(payload)


# -----------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------

def _run_scan(*, path: Path, policies: list[str], format: str, recursive: bool,
              region: str, policy_dir: Path, use_bedrock: bool) -> list:
    """Build an engine and run a scan (single file or directory)."""
    try:
        config = EngineConfig(
            region=region, policy_dir=_resolve_policy_dir(policy_dir),
            selected_policies=policies, recursive=recursive,
            output_format=format, use_bedrock=use_bedrock,
        )
        engine = ComplianceEngine(config)
        if path.is_dir():
            return asyncio.run(engine.scan_directory(path, recursive=recursive))
        return [asyncio.run(engine.scan(path))]
    except GuardrailComplianceError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


# Format dispatch: each entry returns a string payload (except console which prints directly).
_FORMAT_BUILDERS = {
    "json": lambda results: json.dumps(build_json_report(results), indent=2),
    "sarif": lambda results: json.dumps(build_sarif_report(results), indent=2),
    "html": lambda results: build_html_report(results),
}


def _emit_output(results: list, *, format: str, output: Path | None, explain: bool) -> None:
    """Render scan results in the requested format."""
    if format == "console":
        render_scan_results(results, console=console, explain=explain)
        return

    builder = _FORMAT_BUILDERS.get(format)
    if not builder:
        console.print(f"[red]Unsupported format:[/red] {format}")
        raise typer.Exit(code=1)

    payload = builder(results)
    if output:
        output.write_text(payload, encoding="utf-8")
        console.print(f"Wrote {format.upper()} report to {output}")
    else:
        typer.echo(payload)


def _resolve_policy_dir(policy_dir: Path) -> Path:
    """Resolve a policy directory, falling back to bundled policies for the default."""
    if policy_dir == Path("policies"):
        return PolicyRegistry.default().policy_dir
    return policy_dir


def _normalize_name(value: str) -> str:
    """Strip non-alphanumeric characters and lowercase for fuzzy matching."""
    return "".join(ch for ch in value.lower() if ch.isalnum())


if __name__ == "__main__":  # pragma: no cover
    app()
