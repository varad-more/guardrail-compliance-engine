from __future__ import annotations

from collections import Counter
from typing import Iterable

from rich.console import Console
from rich.panel import Panel
from rich.pretty import Pretty
from rich.text import Text
from rich.tree import Tree

from ..core.models import ScanResult

STATUS_STYLES = {
    "PASS": "green",
    "FAIL": "red",
    "WARN": "yellow",
}


def render_scan_results(
    results: Iterable[ScanResult],
    console: Console | None = None,
    *,
    explain: bool = False,
) -> None:
    console = console or Console()
    results = list(results)
    console.print(
        Panel.fit(
            "[bold]GuardRail Compliance Engine[/bold]\nTerraform-first MVP with Bedrock integration hooks",
            border_style="cyan",
        )
    )

    totals = Counter()
    for result in results:
        tree = Tree(f"[bold]{result.file_path}[/bold] ({result.parser})")
        for resource in result.resources:
            resource_node = tree.add(f"{resource.resource_type}.{resource.resource_name}")
            if explain:
                resource_node.add(f"[dim]Normalized narrative:[/dim]\n{resource.normalized_text}")
                resource_node.add(Pretty(resource.normalized_facts, expand_all=True))
            for finding in resource.findings:
                status_style = STATUS_STYLES.get(finding.status, "white")
                resource_node.add(
                    Text.assemble(
                        (f"{finding.status:>4}", status_style),
                        (f"  {finding.rule_id}  ", "bold"),
                        (finding.title, "white"),
                        (f" — {finding.message}", "dim"),
                    )
                )
                totals[finding.status] += 1
        console.print(tree)

    summary = Text()
    summary.append(f"Files scanned: {len(results)}\n", style="bold")
    summary.append(f"Passed checks: {totals.get('PASS', 0)}\n", style="green")
    summary.append(f"Failed checks: {totals.get('FAIL', 0)}\n", style="red")
    summary.append(f"Warnings: {totals.get('WARN', 0)}", style="yellow")
    console.print(Panel(summary, title="Summary", border_style="magenta"))
