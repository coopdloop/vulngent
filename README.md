# vulngent

An agentic vulnerability remediation ledger for security teams: tracks vulns,
remediation steps, stakeholder outreach, commitments, and links to GitHub PRs/commits
and Jira tickets — all in one place, with a multi-agent team that can triage, chase
stakeholders, and keep the ledger current on its own.

## Architecture

- **Orchestration:** [Microsoft AutoGen](https://github.com/microsoft/autogen)
  (`autogen-agentchat`), three `AssistantAgent`s in a `RoundRobinGroupChat`:
  - **Triage agent** — prioritizes open vulns, asks the analyst to help resolve
    reachability when it's unclear, flags low-hanging fruit (high severity + reachable +
    no remediation started yet).
  - **Outreach agent** — messages stakeholders (Slack/email), records commitments and
    replies, follows up on commitments coming due.
  - **Tracker agent** — links GitHub PRs/commits, syncs Jira tickets, keeps remediation
    steps and vuln status current, produces the status report.
- **LLM backend:** Claude via [OpenRouter](https://openrouter.ai) (OpenAI-compatible
  endpoint), configured in `vulngent/agents/model_client.py`. Swap `OPENROUTER_MODEL` to
  point at any Claude (or other) model OpenRouter serves.
- **Storage:** SQLAlchemy ORM (`vulngent/db/models.py`), SQLite by default
  (`DATABASE_URL`), works against Postgres etc. unchanged. Core tables: `Vulnerability`,
  `Asset`, `Stakeholder`, `RemediationStep`, `CommunicationLog`, `Commitment`,
  `ExternalReference` (PRs/commits/Jira tickets), `TimelineEvent` (full audit trail per
  vuln).
- **Integrations:** GitHub (`PyGithub`), Slack (`slack_sdk`), email (`smtplib`), Jira
  (`jira`) — each in `vulngent/integrations/`, each independently optional. A tool call
  against an unconfigured integration returns a plain `ERROR: ...` string instead of
  crashing the agent loop.
- **Tools:** `vulngent/agents/tools.py` — plain typed Python functions wrapping the
  repository + integrations, handed to the agents as-is (AutoGen builds the tool schema
  from type hints + docstring).

## Setup

```bash
uv sync
cp .env.example .env   # fill in OPENROUTER_API_KEY at minimum; everything else optional
uv run vulngent initdb
```

## Usage

```bash
# Import vulnerabilities from a normalized JSON/CSV export (see sample_data/ for shape)
uv run vulngent import sample_data/sample_vulns.json

# List / inspect the ledger
uv run vulngent list --status open
uv run vulngent show 1
uv run vulngent report

# Point vulns at a GitHub repo (accepts 'owner/repo' or a github.com/git URL)
uv run vulngent import sample_data/sample_vulns.json --repo https://github.com/you/your-repo
uv run vulngent link-repo billing-service https://github.com/you/your-repo  # or for an existing asset

# File a GitHub issue / pick up PRs+commits referencing a vuln (needs GITHUB_TOKEN)
uv run vulngent github-issue 1
uv run vulngent github-link 1

# Run one full agent cycle: triage -> outreach -> tracking
uv run vulngent run-cycle
```

`vulngent run-cycle` streams the agents' conversation and tool calls to the terminal. The
triage agent may pause and ask you (the analyst) a direct question when it needs help
confirming reachability — answer at the `your answer>` prompt.

## Bringing in your own vuln data

`vulngent import` expects a normalized JSON list or CSV with these fields (see
`vulngent/ingestion/schema.py` and `sample_data/sample_vulns.json`):

`external_id, title, description, severity, cvss_score, asset_name, repo_full_name,
asset_criticality, owner_name, owner_email, owner_slack_id, owner_github_username`

For a specific scanner (Snyk, Trivy, Nessus, etc.), write a small script that maps its
native export to this shape — that's the intended integration point rather than parsing
every scanner format inline.

## Priority scoring

`vulngent/db/repository.py::compute_priority_score` is a transparent, additive score
(severity + CVSS + asset criticality + reachability + age) — meant to surface obvious
low-hanging fruit and give the triage agent (and you) a starting point, not a substitute
for real risk modeling. The rationale string is stored alongside every score.

## Tests

```bash
uv run pytest
```

Covers the repository layer (priority scoring, commitments, timeline) and the importer.
Agent/integration code is exercised by construction (`build_team()`) and by the tool
functions directly against a live DB — hitting real Slack/GitHub/Jira/OpenRouter needs
credentials, so those paths aren't covered by the automated suite.
