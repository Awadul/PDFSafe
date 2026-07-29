"""PDFSafe command line interface.

Examples::

    pdfsafe scan suspicious.pdf --ai
    pdfsafe scan ./inbox --json > results.json
    pdfsafe rules
    pdfsafe config
    pdfsafe keygen
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console
from rich.table import Table

from pdfsafe.local.sandbox import install_freeze_support

# Must run before anything imports multiprocessing machinery. In a frozen build
# the parser sandbox re-launches this executable to spawn a child; without the
# guard installed first, the child re-runs the CLI instead of the worker body.
install_freeze_support()

from pdfsafe import __version__  # noqa: E402
from pdfsafe.analysis.pipeline import analyze_file  # noqa: E402
from pdfsafe.enums import Severity, Verdict  # noqa: E402

app = typer.Typer(
    name="pdfsafe",
    help="Analyse PDF files for malicious content.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
error_console = Console(stderr=True)

VERDICT_COLORS: dict[str, str] = {
    Verdict.CLEAN.value: "green",
    Verdict.LOW_RISK.value: "bright_green",
    Verdict.SUSPICIOUS.value: "yellow",
    Verdict.MALICIOUS.value: "red",
    Verdict.UNKNOWN.value: "dim",
}

SEVERITY_COLORS: dict[str, str] = {
    Severity.CRITICAL.value: "bold red",
    Severity.HIGH.value: "red",
    Severity.MEDIUM.value: "yellow",
    Severity.LOW.value: "cyan",
    Severity.INFO.value: "dim",
}

#: Exit codes, so the CLI can gate a CI pipeline.
EXIT_CLEAN = 0
EXIT_SUSPICIOUS = 1
EXIT_MALICIOUS = 2
EXIT_ERROR = 3


@app.command()
def scan(
    target: Annotated[Path, typer.Argument(help="A PDF file or a directory of PDFs.")],
    ai: Annotated[
        bool, typer.Option("--ai", help="Force AI review regardless of the score gate.")
    ] = False,
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Skip AI review entirely.")] = False,
    as_json: Annotated[bool, typer.Option("--json", help="Emit machine-readable JSON.")] = False,
    verbose: Annotated[bool, typer.Option("-v", "--verbose", help="Show every indicator.")] = False,
    recursive: Annotated[
        bool, typer.Option("-r", "--recursive", help="Search subdirectories recursively.")
    ] = True,
) -> None:
    """Analyse a file or directory and print the verdict."""
    from pdfsafe.ai.triage import triage
    from pdfsafe.config import get_settings

    settings = get_settings()
    targets = _collect(target, recursive=recursive)
    if not targets:
        error_console.print(f"[red]No PDF files found at {target}[/red]")
        raise typer.Exit(EXIT_ERROR)

    results: list[dict[str, Any]] = []
    worst = Verdict.CLEAN

    for path in targets:
        try:
            analysis = analyze_file(path)
        except Exception as exc:
            error_console.print(f"[red]{path.name}: {exc}[/red]")
            results.append({"file": str(path), "error": str(exc)})
            worst = Verdict.UNKNOWN
            continue

        if no_ai:
            decision_verdict = analysis.outcome.verdict
            score = analysis.outcome.score
            decided_by = "heuristics"
            summary = ""
            ai_used = False
        else:
            decision = triage(analysis.result, analysis.outcome, settings=settings, force_ai=ai)
            decision_verdict = decision.verdict
            score = decision.risk_score
            decided_by = decision.decided_by.value
            summary = decision.summary
            ai_used = decision.used_ai

        from pdfsafe.enums import worst_verdict

        worst = worst_verdict(worst, decision_verdict)

        payload = {
            "file": str(path),
            "sha256": analysis.result.sha256,
            "size": analysis.result.file_size,
            "verdict": decision_verdict.value,
            "risk_score": score,
            "decided_by": decided_by,
            "used_ai": ai_used,
            "summary": summary,
            "indicators": [i.model_dump(mode="json") for i in analysis.outcome.indicators],
        }
        results.append(payload)

        if not as_json:
            _print_result(path, payload, analysis, verbose=verbose)

    if as_json:
        console.print_json(json.dumps(results, default=str))

    raise typer.Exit(_exit_code(worst))


@app.command()
def rules() -> None:
    """List the registered heuristic rules and YARA rule files."""
    from pdfsafe.analysis.heuristics import registered_rules
    from pdfsafe.analysis.yara_engine import BUNDLED_RULES_DIR, get_rules

    table = Table(title="Heuristic rules", show_header=True, header_style="bold")
    table.add_column("#", justify="right", style="dim")
    table.add_column("Rule")
    for index, name in enumerate(registered_rules(), start=1):
        table.add_row(str(index), name)
    console.print(table)

    console.print(f"\n[bold]YARA rules directory:[/bold] {BUNDLED_RULES_DIR}")
    console.print(f"[bold]YARA compiled:[/bold] {'yes' if get_rules() is not None else 'no'}")


@app.command()
def config() -> None:
    """Print the effective configuration with secrets masked."""
    from pdfsafe.config import get_settings

    settings = get_settings()
    table = Table(show_header=True, header_style="bold")
    table.add_column("Setting")
    table.add_column("Value")
    for key, value in sorted(settings.model_dump().items()):
        rendered = "***" if "key" in key and value else str(value)
        table.add_row(key, rendered)
    console.print(table)


@app.command()
def version() -> None:
    """Print the PDFSafe version."""
    console.print(f"PDFSafe {__version__}")


@app.command("watch")
def watch(
    target: Annotated[
        Path | None, typer.Argument(help="Folder to monitor for new PDFs. Defaults to Downloads.")
    ] = None,
    ai: Annotated[
        bool, typer.Option("--ai", help="Force AI review regardless of the score gate.")
    ] = False,
    no_ai: Annotated[bool, typer.Option("--no-ai", help="Skip AI review entirely.")] = False,
    poll: Annotated[int, typer.Option("--poll", help="Polling interval in seconds.")] = 5,
    recursive: Annotated[
        bool, typer.Option("-r", "--recursive", help="Watch subdirectories recursively.")
    ] = False,
) -> None:
    """Continuously monitor a folder for new PDF files and scan them in real time."""
    import time

    from pdfsafe.config import get_settings
    from pdfsafe.local.engine import LocalScanEngine, ScanEvent, ScanEventKind
    from pdfsafe.local.watcher import FolderWatcher

    if poll < 1:
        error_console.print("[red]Poll interval must be at least 1 second.[/red]")
        raise typer.Exit(EXIT_ERROR)

    base_settings = get_settings()
    watch_target = target.resolve() if target else base_settings.watch_dir
    if not watch_target.is_dir():
        error_console.print(f"[red]Directory not found: {watch_target}[/red]")
        raise typer.Exit(EXIT_ERROR)

    ai_enabled = True if ai else (False if no_ai else base_settings.ai_enabled)
    ai_always_escalate = True if ai else base_settings.ai_always_escalate

    settings = base_settings.model_copy(
        update={
            "watch_folders": [str(watch_target)],
            "watch_poll_seconds": poll,
            "watch_enabled": True,
            "watch_recursive": recursive,
            "ai_enabled": ai_enabled,
            "ai_always_escalate": ai_always_escalate,
        }
    )

    provider_name = settings.ai_provider.value.upper()
    console.print("\n[bold green]PDFSafe File Watcher Active[/bold green]")
    console.print(f"  [bold]Monitoring Folder:[/bold] [cyan]{watch_target}[/cyan]")
    console.print(
        f"  [bold]Poll Interval:[/bold] {poll}s (Recursive: {'YES' if recursive else 'NO'})"
    )
    ai_colour = "green" if settings.ai_enabled else "red"
    ai_state = "ENABLED" if settings.ai_enabled else "DISABLED"
    console.print(f"  [bold]AI Review ({provider_name}):[/bold] [{ai_colour}]{ai_state}[/]")
    console.print(
        "  [dim]Drop any PDF into this folder to scan it. Press Ctrl+C to stop.[/dim]\n"
    )

    def on_event(event: ScanEvent) -> None:
        if event.kind is ScanEventKind.COMPLETED and event.verdict:
            verdict_str = event.verdict.value.upper()
            colour = VERDICT_COLORS.get(event.verdict.value, "white")
            console.print(
                f"\n[bold]{event.filename}[/bold]  "
                f"[{colour}]{verdict_str}[/{colour}]  "
                f"score [bold]{event.risk_score}[/bold]/100"
            )
            if event.message:
                console.print(f"  {event.message}")
        elif event.kind in {ScanEventKind.STARTED, ScanEventKind.PARSING}:
            console.print(f"[dim]Scanning {event.filename}...[/dim]")
        elif event.kind in {ScanEventKind.FAILED, ScanEventKind.REJECTED}:
            error_console.print(
                f"\n[red]Failed scanning {event.filename or 'file'}: {event.message}[/red]"
            )

    engine = LocalScanEngine(settings=settings)
    engine.subscribe(on_event)
    engine.start()

    watcher = FolderWatcher(engine=engine, settings=settings)
    watcher.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopping watcher...[/yellow]")
        watcher.stop()
        engine.stop()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _collect(target: Path, *, recursive: bool = True) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        pattern = "*.pdf"
        files = target.rglob(pattern) if recursive else target.glob(pattern)
        return sorted(p for p in files if p.is_file())
    return []


def _print_result(path: Path, payload: dict[str, Any], analysis: Any, *, verbose: bool) -> None:
    verdict = str(payload["verdict"])
    colour = VERDICT_COLORS.get(verdict, "white")

    console.print(
        f"\n[bold]{path.name}[/bold]  "
        f"[{colour}]{verdict.upper()}[/{colour}]  "
        f"score [bold]{payload['risk_score']}[/bold]/100  "
        f"[dim]({payload['decided_by']}{', ai' if payload['used_ai'] else ''})[/dim]"
    )
    if payload["summary"]:
        console.print(f"  {payload['summary']}")

    indicators = analysis.outcome.indicators
    shown = indicators if verbose else analysis.outcome.top_indicators(5)
    for indicator in shown:
        style = SEVERITY_COLORS.get(indicator.severity.value, "white")
        console.print(
            f"  [{style}]{indicator.severity.value.upper():>8}[/{style}] "
            f"{indicator.title} [dim]({indicator.code}, w{indicator.weight})[/dim]"
        )
    if not verbose and len(indicators) > len(shown):
        console.print(f"  [dim]... {len(indicators) - len(shown)} more (use -v)[/dim]")


def _exit_code(verdict: Verdict) -> int:
    if verdict is Verdict.MALICIOUS:
        return EXIT_MALICIOUS
    if verdict in {Verdict.SUSPICIOUS, Verdict.UNKNOWN}:
        return EXIT_SUSPICIOUS
    return EXIT_CLEAN


def main() -> None:  # pragma: no cover
    try:
        app()
    except KeyboardInterrupt:
        error_console.print("[yellow]Interrupted[/yellow]")
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":  # pragma: no cover
    main()
