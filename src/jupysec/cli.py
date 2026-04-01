"""CLI entry point for jupysec."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from jupysec import __version__
from jupysec.core.finding import SEVERITY_ORDER, ScanResult, Severity
from jupysec.core.profile import Mode, ScanProfile
from jupysec.core.registry import discover_checks
from jupysec.core.target import Target

app = typer.Typer(
    name="jupysec",
    help="Security assessment tool for JupyterHub deployments.",
    no_args_is_help=True,
)
console = Console()


def _severity_style(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "dark_orange",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }.get(severity, "")


def _print_results(result: ScanResult) -> None:
    console.print()
    console.rule("[bold]jupysec scan results[/bold]")
    console.print(f"  Mode: {result.mode}")
    if result.target_url:
        console.print(f"  Target: {result.target_url}")
    console.print(
        f"  Checks: {result.checks_run} run, "
        f"[green]{result.checks_passed} passed[/green], "
        f"[red]{result.checks_failed} findings[/red], "
        f"{result.checks_errored} errors"
    )
    console.print()

    if not result.findings:
        console.print("[bold green]All checks passed. No findings.[/bold green]")
    else:
        table = Table(show_header=True, header_style="bold")
        table.add_column("Severity", width=10)
        table.add_column("Check", width=28)
        table.add_column("Title", min_width=30)
        table.add_column("Component", width=14)

        for f in result.findings:
            style = _severity_style(f.severity)
            table.add_row(
                f.severity.value.upper(),
                f.check_id,
                f.title,
                f.target_component,
                style=style,
            )
        console.print(table)

        console.print()
        for f in result.findings:
            style = _severity_style(f.severity)
            console.print(f"[{style}][{f.severity.value.upper()}][/{style}] {f.title}")
            console.print(f"  {f.description}")
            if f.evidence:
                console.print(f"  Evidence: {f.evidence}", style="dim")
            if f.remediation:
                console.print(f"  Remediation: {f.remediation}", style="green")
            console.print()

    # Benchmark scoring
    from jupysec.knowledge.benchmark import get_benchmark_results

    finding_check_ids = {f.check_id for f in result.findings}
    checks_run_ids = finding_check_ids | {
        c.id for c in discover_checks()
    }
    bench = get_benchmark_results(finding_check_ids, checks_run_ids)

    console.print()
    console.rule("[bold]JupyterHub Security Benchmark[/bold]")
    bench_table = Table(show_header=True, header_style="bold")
    bench_table.add_column("ID", width=10)
    bench_table.add_column("Status", width=8)
    bench_table.add_column("Title", min_width=35)

    status_styles = {"pass": "green", "fail": "red", "warn": "yellow", "skip": "dim"}
    for item in bench:
        style = status_styles.get(item["status"], "")
        bench_table.add_row(item["id"], item["status"].upper(), item["title"], style=style)

    console.print(bench_table)
    passed = sum(1 for i in bench if i["status"] == "pass")
    total = sum(1 for i in bench if i["status"] != "skip")
    if total > 0:
        console.print(f"\n  Score: {passed}/{total} ({100 * passed // total}%)")


@app.command()
def scan(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="JupyterHub URL"),
    token: Optional[str] = typer.Option(None, "--token", help="API token"),
    config: Optional[Path] = typer.Option(None, "--config", "-c", help="jupyterhub_config.py path"),
    kubeconfig: Optional[Path] = typer.Option(None, "--kubeconfig", help="Kubeconfig path"),
    namespace: Optional[str] = typer.Option(None, "--namespace", "-n", help="Kubernetes namespace"),
    mode: Mode = typer.Option(Mode.EXTERNAL, "--mode", "-m", help="Scan mode"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option("text", "--format", "-f", help="Output format: text, json, html, sarif"),
    no_verify_ssl: bool = typer.Option(False, "--no-verify-ssl", help="Skip TLS verification"),
    concurrency: int = typer.Option(10, "--concurrency", help="Max concurrent checks"),
) -> None:
    """Run a security scan against a JupyterHub deployment."""
    if not target and not config and not kubeconfig:
        console.print("[red]Error:[/red] Provide --target (external) and/or --config/--kubeconfig (internal)")
        raise typer.Exit(1)

    scan_target = Target(
        url=target,
        token=token,
        config_path=config,
        kubeconfig=kubeconfig,
        namespace=namespace,
        verify_ssl=not no_verify_ssl,
    )

    profile = ScanProfile(mode=mode, concurrency=concurrency)

    from jupysec.core.engine import run_scan

    result = asyncio.run(run_scan(scan_target, profile))

    if format == "json" or (output and output.suffix == ".json"):
        from jupysec.output.reporter import to_json, write_json

        if output:
            write_json(result, output)
            console.print(f"Results written to {output}")
        else:
            console.print_json(to_json(result))

    elif format == "html" or (output and output.suffix == ".html"):
        from jupysec.output.html_report import to_html, write_html

        if output:
            write_html(result, output)
            console.print(f"HTML report written to {output}")
        else:
            console.print(to_html(result))

    elif format == "sarif" or (output and output.suffix == ".sarif"):
        from jupysec.output.reporter import to_sarif, write_sarif

        if output:
            write_sarif(result, output)
            console.print(f"SARIF report written to {output}")
        else:
            console.print(to_sarif(result))

    else:
        _print_results(result)
        if output:
            from jupysec.output.reporter import write_json

            write_json(result, output)
            console.print(f"JSON results also written to {output}")

    crit_high = sum(
        1 for f in result.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    )
    if crit_high > 0:
        raise typer.Exit(1)


@app.command()
def checks(
    mode: Optional[Mode] = typer.Option(None, "--mode", "-m", help="Filter by mode"),
    category: Optional[str] = typer.Option(None, "--category", help="Filter by category"),
) -> None:
    """List all available security checks."""
    all_checks = discover_checks()

    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", min_width=28)
    table.add_column("Severity", width=10)
    table.add_column("Mode", width=10)
    table.add_column("Title", min_width=30)

    for c in all_checks:
        if mode and c.mode != mode.value and c.mode != "both":
            continue
        if category and c.category.value != category:
            continue
        style = _severity_style(c.severity)
        table.add_row(c.id, c.severity.value.upper(), c.mode, c.title, style=style)

    console.print(table)
    console.print(f"\n{len(all_checks)} checks available")


@app.command()
def benchmark(
    action: str = typer.Argument("list", help="'list' all items or 'show <id>' for details"),
    item_id: Optional[str] = typer.Argument(None, help="Benchmark item ID to show"),
) -> None:
    """List or show JupyterHub Security Benchmark items."""
    from jupysec.knowledge.benchmark import JUPYTERHUB_BENCHMARK

    if action == "show" and item_id:
        for item in JUPYTERHUB_BENCHMARK:
            if item.id == item_id:
                console.print(f"[bold]{item.id}[/bold] {item.title}")
                console.print(f"  Section: {item.section}")
                console.print(f"  Level: {item.level}")
                console.print(f"  Description: {item.description}")
                console.print(f"  Check IDs: {', '.join(item.check_ids)}")
                return
        console.print(f"[red]Benchmark item '{item_id}' not found.[/red]")
        raise typer.Exit(1)

    table = Table(show_header=True, header_style="bold")
    table.add_column("ID", width=10)
    table.add_column("Level", width=6)
    table.add_column("Section", width=26)
    table.add_column("Title", min_width=30)

    current_section = ""
    for item in JUPYTERHUB_BENCHMARK:
        if item.section != current_section:
            current_section = item.section
        table.add_row(item.id, str(item.level), item.section, item.title)

    console.print(table)
    console.print(f"\n{len(JUPYTERHUB_BENCHMARK)} benchmark items")


@app.command()
def report(
    input_file: Path = typer.Option(..., "--input", "-i", help="Input JSON results file"),
    fmt: str = typer.Option("html", "--format", "-f", help="Output format: html, sarif, json"),
    output: Path = typer.Option(..., "--output", "-o", help="Output file path"),
) -> None:
    """Generate a report from a previous scan's JSON output."""
    import json as json_mod

    raw = input_file.read_text(encoding="utf-8")
    result = ScanResult.model_validate_json(raw)

    if fmt == "html":
        from jupysec.output.html_report import write_html
        write_html(result, output)
    elif fmt == "sarif":
        from jupysec.output.reporter import write_sarif
        write_sarif(result, output)
    elif fmt == "json":
        from jupysec.output.reporter import write_json
        write_json(result, output)
    else:
        console.print(f"[red]Unknown format: {fmt}[/red]")
        raise typer.Exit(1)

    console.print(f"Report written to {output}")


@app.command()
def version() -> None:
    """Show jupysec version."""
    console.print(f"jupysec {__version__}")


if __name__ == "__main__":
    app()
