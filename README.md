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

## Authentication (Sign in with Google / Microsoft)

Auth is **optional and off by default** — with no provider client id set, the chat UI
stays fully open (local-dev friendly). Set a Google and/or Microsoft client id and the
app requires sign-in: a login screen gates the UI, a clickable profile card appears
bottom-left in the sidebar (opens a **Profile** page), and user avatars show on chat
messages. Chat threads become per-user (legacy threads with no owner stay visible to
everyone). Both providers can be enabled at once; the login screen shows a button for
each configured provider.

### Create the Google OAuth client ID

In the [Google Cloud Console](https://console.cloud.google.com/apis/credentials):

1. **APIs & Services → OAuth consent screen** — configure it once:
   - User type: **External** (or **Internal** for a Workspace-only app)
   - App name, user support email, developer contact email
   - Scopes: the defaults (`openid`, `email`, `profile`) are all this needs
   - Add yourself under **Test users** while the app is in "Testing"
2. **APIs & Services → Credentials → Create credentials → OAuth client ID**:
   - **Application type:** `Web application`
   - **Name:** anything, e.g. `vulngent web`
   - **Authorized JavaScript origins** (exact scheme+host+port, no path):
     - `http://localhost:7860`
     - `http://127.0.0.1:7860`
     - your production origin, e.g. `https://vulngent.example.com`
   - **Authorized redirect URIs:** *none required* — this app uses Google Identity
     Services (the ID-token button), not the redirect/code flow.
3. Copy the **Client ID** (looks like `1234567890-abc123.apps.googleusercontent.com`).
   The **client secret is not used** by this flow, so you can ignore it.

### Configure vulngent

Set these in `.env` (or via the in-app **Settings → Authentication**):

```bash
GOOGLE_CLIENT_ID=1234567890-abc123.apps.googleusercontent.com
GOOGLE_ALLOWED_DOMAIN=example.com   # optional: restrict to one Workspace domain
SESSION_SECRET=<long-random-string>  # optional but recommended so logins survive restarts
```

Then apply the schema migration (adds the `users` table + `chat_threads.owner_id`,
no data loss) and start the server:

```bash
uv run vulngent migrate
uv run vulngent chat
```

**Summary of what to enter in the Google Cloud Console:**

| Field | Value |
| --- | --- |
| Application type | Web application |
| Authorized JavaScript origins | `http://localhost:7860`, `http://127.0.0.1:7860`, prod origin |
| Authorized redirect URIs | (none needed) |
| Scopes | `openid`, `email`, `profile` (defaults) |

### Create the Microsoft (Azure / Entra ID) app registration

In the [Azure Portal](https://portal.azure.com) → **Microsoft Entra ID → App registrations → New registration**:

1. **Name:** anything, e.g. `vulngent web`.
2. **Supported account types:** pick what matches your `MICROSOFT_TENANT`:
   - *Accounts in any organizational directory and personal Microsoft accounts* → `common`
   - *Accounts in any organizational directory* → `organizations`
   - *Personal Microsoft accounts only* → `consumers`
   - *This organizational directory only* → your specific tenant id
3. **Redirect URI:** platform **Single-page application (SPA)**, value = your app origin
   (`http://localhost:7860`, and your prod origin). MSAL.js uses the SPA/PKCE flow, so
   register it as SPA — not Web — and **no client secret is needed**.
4. After creating, copy the **Application (client) ID** from the Overview page.
5. Under **Token configuration**, the default `openid`/`profile`/`email` scopes are enough;
   the returned ID token's `email`/`preferred_username` and `name` claims are used.

| Field | Value |
| --- | --- |
| Platform | Single-page application (SPA) |
| Redirect URIs | `http://localhost:7860`, `http://127.0.0.1:7860`, prod origin |
| Client secret | (none needed) |
| Supported account types | must match `MICROSOFT_TENANT` |

Then set in `.env` (or in-app Settings):

```bash
MICROSOFT_CLIENT_ID=00000000-0000-0000-0000-000000000000
MICROSOFT_TENANT=common   # or organizations / consumers / a tenant id
```

> **Note on profile photos:** Google only returns a `picture` for some accounts and
> Microsoft ID tokens never include one, so the UI falls back to the user's initials
> when no photo is available (this is why an empty `picture` still renders a clean
> avatar rather than a broken image).

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
