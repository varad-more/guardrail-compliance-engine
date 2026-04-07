from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.pretty import Pretty
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from ..core.models import ScanResult

STATUS_STYLES = {
    "PASS": "green",
    "FAIL": "red",
    "WARN": "yellow",
}

_BAR_FULL = "█"
_BAR_EMPTY = "░"
_BAR_WIDTH = 20


def render_scan_results(
    results: Iterable[ScanResult],
    console: Console | None = None,
    *,
    explain: bool = False,
) -> None:
    """Print scan results as a Rich tree with charts and a summary dashboard."""
    console = console or Console()
    results = list(results)

    console.print(
        Panel.fit(
            "[bold]GuardRail Compliance Engine[/bold]",
            border_style="cyan",
        )
    )

    totals: Counter[str] = Counter()
    sev_fails: Counter[str] = Counter()
    rule_fails: Counter[str] = Counter()

    for result in results:
        tree = Tree(f"[bold]{result.file_path}[/bold] ([dim]{result.parser}[/dim])")
        for resource in result.resources:
            resource_node = tree.add(f"[cyan]{resource.resource_type}[/cyan].[white]{resource.resource_name}[/white]")
            if explain:
                resource_node.add(f"[dim]Normalized narrative:[/dim]\n{resource.normalized_text}")
                resource_node.add(Pretty(resource.normalized_facts, expand_all=True))
            for finding in resource.findings:
                status_style = STATUS_STYLES.get(finding.status, "white")
                finding_node = resource_node.add(
                    Text.assemble(
                        (f"{finding.status:>4}", status_style),
                        ("  ", ""),
                        (finding.rule_id, "bold"),
                        ("  ", ""),
                        (finding.title, "white"),
                        (f" — {finding.message}", "dim"),
                    )
                )
                if finding.status == "FAIL" and finding.remediation_snippet:
                    finding_node.add(
                        Panel(finding.remediation_snippet, title="[dim]Suggested fix[/dim]",
                              border_style="green", expand=False)
                    )
                totals[finding.status] += 1
                if finding.status == "FAIL":
                    sev_fails[finding.severity] += 1
                    rule_fails[f"{finding.rule_id}: {finding.title}"] += 1
        console.print(tree)

    # -----------------------------------------------------------------------
    # Dashboard: summary stats + severity bar chart + top failing rules
    # -----------------------------------------------------------------------
    _render_dashboard(console, results, totals, sev_fails, rule_fails)


def _render_dashboard(
    console: Console,
    results: list[ScanResult],
    totals: Counter[str],
    sev_fails: Counter[str],
    rule_fails: Counter[str],
) -> None:
    pass_count = totals.get("PASS", 0)
    fail_count = totals.get("FAIL", 0)
    warn_count = totals.get("WARN", 0)
    grand_total = max(pass_count + fail_count + warn_count, 1)
    score = round((pass_count / grand_total) * 100)
    score_color = "green" if score >= 80 else ("yellow" if score >= 50 else "red")

    # --- Score panel ---
    score_text = Text()
    score_text.append(f"  {score}%  ", style=f"bold {score_color}")
    score_text.append("compliance\n\n", style="dim")
    score_text.append(f"Files:    {len(results)}\n", style="bold")
    score_text.append(f"Passed:   {pass_count}\n", style="green")
    score_text.append(f"Failed:   {fail_count}\n", style="red")
    score_text.append(f"Warnings: {warn_count}", style="yellow")

    # --- Severity bar chart ---
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    sev_colors = {
        "CRITICAL": "bright_red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFORMATIONAL": "blue",
    }
    max_sev = max(sev_fails.values(), default=1)
    sev_chart = Text()
    sev_chart.append("Failures by severity\n\n", style="bold dim")
    if sev_fails:
        for sev in sev_order:
            count = sev_fails.get(sev, 0)
            if count == 0:
                continue
            filled = round((count / max_sev) * _BAR_WIDTH)
            bar = _BAR_FULL * filled + _BAR_EMPTY * (_BAR_WIDTH - filled)
            sev_chart.append(f"{sev[:6]:>6}  ", style=sev_colors.get(sev, "white"))
            sev_chart.append(bar, style=sev_colors.get(sev, "white"))
            sev_chart.append(f"  {count}\n", style="dim")
    else:
        sev_chart.append("No failures.", style="green")

    # --- Top 5 failing rules table ---
    top = rule_fails.most_common(5)
    rules_text = Text()
    rules_text.append("Top failing rules\n\n", style="bold dim")
    if top:
        max_count = top[0][1]
        for i, (label, count) in enumerate(top, 1):
            rule_id, _, _ = label.partition(": ")
            filled = round((count / max_count) * _BAR_WIDTH)
            bar = _BAR_FULL * filled + _BAR_EMPTY * (_BAR_WIDTH - filled)
            rules_text.append(f"#{i} ", style="dim")
            rules_text.append(f"{rule_id:<18}", style="cyan bold")
            rules_text.append(bar, style="red")
            rules_text.append(f"  {count}\n", style="dim")
    else:
        rules_text.append("No failures.", style="green")

    # --- Per-file table ---
    file_table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 1))
    file_table.add_column("", width=2)
    file_table.add_column("File", no_wrap=False)
    file_table.add_column("Res", justify="right", width=4)
    file_table.add_column("Pass", justify="right", style="green", width=5)
    file_table.add_column("Fail", justify="right", style="red", width=5)
    file_table.add_column("Warn", justify="right", style="yellow", width=5)
    file_table.add_column("Score", justify="right", width=6)

    for scan in results:
        fp = sum(1 for r in scan.resources for f in r.findings if f.status == "PASS")
        ff = sum(1 for r in scan.resources for f in r.findings if f.status == "FAIL")
        fw = sum(1 for r in scan.resources for f in r.findings if f.status == "WARN")
        ft = max(fp + ff + fw, 1)
        fs = round((fp / ft) * 100)
        icon = "[green]✓[/green]" if ff == 0 else "[red]✗[/red]"
        sc_style = "green" if fs >= 80 else ("yellow" if fs >= 50 else "red")
        file_table.add_row(icon, str(scan.file_path), str(len(scan.resources)),
                           str(fp), str(ff), str(fw), f"[{sc_style}]{fs}%[/{sc_style}]")

    console.print()
    console.print(
        Columns([
            Panel(score_text, title="[bold]Summary[/bold]", border_style="magenta", padding=(1, 2)),
            Panel(sev_chart, title="[bold]Severity[/bold]", border_style="red", padding=(1, 2)),
            Panel(rules_text, title="[bold]Top Rules[/bold]", border_style="yellow", padding=(1, 2)),
        ], equal=False, expand=False)
    )
    console.print(Panel(file_table, title="[bold]Files[/bold]", border_style="blue"))
