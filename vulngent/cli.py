from __future__ import annotations

import asyncio

import typer
from rich.console import Console as RichConsole
from rich.markup import escape
from rich.table import Table

from vulngent.db.session import get_session, init_db

app = typer.Typer(help="vulngent: an agentic vulnerability remediation ledger.")
console = RichConsole()


@app.command()
def initdb() -> None:
    """Create the database tables (safe to re-run)."""
    init_db()
    console.print("[green]Database ready.[/green]")


@app.command(name="import")
def import_cmd(path: str) -> None:
    """Import vulnerabilities from a normalized JSON or CSV file."""
    from vulngent.ingestion.importer import import_file

    init_db()
    with get_session() as session:
        result = import_file(session, path)
    console.print(f"[green]Imported {result.created} vulnerabilities.[/green]")
    if result.skipped_duplicate:
        console.print(f"[yellow]Skipped {len(result.skipped_duplicate)} duplicates: {', '.join(result.skipped_duplicate)}[/yellow]")


@app.command(name="list")
def list_cmd(status: str = "open") -> None:
    """List vulnerabilities by status (open, in_progress, remediated, risk_accepted, false_positive)."""
    from vulngent.db import repository as repo
    from vulngent.db.models import VulnStatus

    init_db()
    try:
        status_enum = VulnStatus(status)
    except ValueError:
        console.print(f"[red]Invalid status '{status}'. Must be one of {[s.value for s in VulnStatus]}[/red]")
        raise typer.Exit(1)

    table = Table(title=f"Vulnerabilities ({status})")
    for col in ("id", "external_id", "title", "severity", "priority", "reachability", "asset", "overdue"):
        table.add_column(col)

    with get_session() as session:
        vulns = repo.list_vulnerabilities(session, status=status_enum)
        for v in vulns:
            days_late = repo.days_overdue(v)
            table.add_row(
                str(v.id),
                escape(v.external_id),
                escape(v.title[:60]),
                v.severity.value,
                str(v.priority_score),
                v.reachability.value,
                v.asset.name if v.asset else "-",
                f"[red]{days_late}d[/red]" if days_late else "-",
            )
    console.print(table)


@app.command()
def show(vuln_id: int) -> None:
    """Show full detail for one vulnerability."""
    from vulngent.agents.tools import get_vulnerability_detail

    init_db()
    console.print_json(get_vulnerability_detail(vuln_id))


@app.command()
def report(
    format: str = typer.Option("md", "--format", "-f", help="Output format: md, txt, pdf, or docx."),
    output: str = typer.Option(None, "--output", "-o", help="File path to write the report to (required for pdf/docx)."),
) -> None:
    """Print or export the current ledger status report."""
    from vulngent.report_data import collect_report_data
    from vulngent.reporting import SUPPORTED_FORMATS, render_report

    fmt = format.lower()
    if fmt not in SUPPORTED_FORMATS:
        console.print(f"[red]Invalid format '{format}'. Must be one of {SUPPORTED_FORMATS}[/red]")
        raise typer.Exit(1)
    if fmt in ("pdf", "docx") and not output:
        console.print(f"[red]--output PATH is required for --format {fmt}[/red]")
        raise typer.Exit(1)

    init_db()
    with get_session() as session:
        data = collect_report_data(session)
    rendered = render_report(data, fmt)

    if output:
        mode = "wb" if isinstance(rendered, bytes) else "w"
        with open(output, mode) as f:
            f.write(rendered)
        console.print(f"[green]Report written to {output}[/green]")
    else:
        console.print(rendered, markup=False)


@app.command("run-cycle")
def run_cycle(model: str = typer.Option(None, help="Override the OpenRouter model id.")) -> None:
    """Run one full triage -> outreach -> tracking cycle with the agent team."""
    from autogen_agentchat.ui import Console as AgentConsole

    from vulngent.agents.team import build_team

    init_db()

    async def _run() -> None:
        team = build_team(model=model)
        task = (
            "Run a full remediation-tracking cycle over currently open and in-progress "
            "vulnerabilities: triage and prioritize, reach out to stakeholders as needed, "
            "then update the ledger and produce a status report."
        )
        await AgentConsole(team.run_stream(task=task))

    asyncio.run(_run())


if __name__ == "__main__":
    app()
