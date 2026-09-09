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
def import_cmd(
    path: str,
    repo: str = typer.Option(
        None, "--repo", "-r", help="GitHub repo to attach to every imported vuln's asset: 'owner/repo' or a github.com URL. Overrides repo_full_name in the file."
    ),
) -> None:
    """Import vulnerabilities from a normalized JSON or CSV file."""
    from vulngent.ingestion.importer import import_file
    from vulngent.integrations.github_client import parse_repo_full_name

    repo_full_name = None
    if repo:
        try:
            repo_full_name = parse_repo_full_name(repo)
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1)

    init_db()
    with get_session() as session:
        result = import_file(session, path, repo_full_name=repo_full_name)
    console.print(f"[green]Imported {result.created} vulnerabilities.[/green]")
    if repo_full_name:
        console.print(f"[green]Linked to GitHub repo {repo_full_name}.[/green]")
    if result.skipped_duplicate:
        console.print(f"[yellow]Skipped {len(result.skipped_duplicate)} duplicates: {', '.join(result.skipped_duplicate)}[/yellow]")


@app.command(name="link-repo")
def link_repo_cmd(asset_name: str, repo: str) -> None:
    """Point an existing asset at a GitHub repo ('owner/repo' or a github.com URL),
    so github-issue/github-sync and the Tracker agent can find it."""
    from vulngent.db import repository as repo_module
    from vulngent.integrations.github_client import parse_repo_full_name

    try:
        repo_full_name = parse_repo_full_name(repo)
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1)

    init_db()
    with get_session() as session:
        asset = repo_module.find_asset_by_name(session, asset_name)
        if not asset:
            console.print(f"[red]No asset named '{asset_name}'. Run 'vulngent list' to see known assets.[/red]")
            raise typer.Exit(1)
        repo_module.set_asset_repo(session, asset, repo_full_name)
    console.print(f"[green]Asset '{asset_name}' linked to {repo_full_name}.[/green]")


@app.command(name="github-issue")
def github_issue_cmd(
    vuln_id: int, repo: str = typer.Option(None, "--repo", "-r", help="Override the asset's linked repo.")
) -> None:
    """File a GitHub issue for one vulnerability."""
    from vulngent.agents.tools import create_github_issue_for_vuln
    from vulngent.integrations.github_client import parse_repo_full_name

    repo_full_name = ""
    if repo:
        try:
            repo_full_name = parse_repo_full_name(repo)
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(1)

    init_db()
    result = create_github_issue_for_vuln(vuln_id, repo_full_name)
    style = "red" if result.startswith("ERROR") else "green"
    console.print(f"[{style}]{result}[/{style}]")


@app.command(name="github-link")
def github_link_cmd(vuln_id: int) -> None:
    """Search the vulnerability's linked GitHub repo for PRs/commits referencing it and
    link any newly found ones into the ledger."""
    from vulngent.agents.tools import link_github_prs_and_commits

    init_db()
    result = link_github_prs_and_commits(vuln_id)
    style = "red" if result.startswith("ERROR") else "green"
    console.print(f"[{style}]{result}[/{style}]")


@app.command(name="scan")
def scan_cmd(
    repo_url: str = typer.Argument(..., help="URL of the GitHub repository to scan."),
    scanners: str = typer.Option("all", "--scanners", "-s", help="Comma-separated list of scanners to run: sast, sca, secrets, all."),
) -> None:
    """Clone a GitHub repo, scan it for vulnerabilities, and import the findings."""
    from vulngent.scanning import ScanError, run_scan_pipeline

    try:
        run_scan_pipeline(repo_url, scanners)
    except ScanError as exc:
        console.print(f"[red]Scan failed: {exc}[/red]")
        raise typer.Exit(1)


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
