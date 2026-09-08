# Agent instructions for vulngent

## Project

vulngent is an agentic vulnerability remediation ledger (Microsoft AutoGen +
Claude/OpenRouter + SQLAlchemy). See `README.md` for architecture.

## Committing: always use `super-commit`, never raw `git commit`

This repo uses [`super-commit-cli`](https://github.com/coopdloop/super-commit-cli)
(binaries `super-commit` and `sc`), installed as a global `uv tool` — it is not a
project dependency, don't add it to `pyproject.toml`. It enforces Conventional Commits
and is designed to be driven non-interactively by coding agents.

**Do not run `git commit` directly in this repo.** Use `sc` instead:

```bash
# Stage everything and commit, non-interactively
sc --all --type <type> --subject "<subject>" --yes

# With a body and/or footer
sc --all --type fix --subject "handle empty CSV import" \
   --body "Explain why, not what." \
   --footer "Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>" \
   --yes

# Stage specific files only (comma-separated paths)
sc --files vulngent/cli.py,tests/test_cli.py --type feat --subject "..." --yes

# Preview without touching git
sc --dry-run --all --type feat --subject "..."

# Commit and push in one shot
sc --all --type feat --subject "..." --push --yes

# Push only (no commit), optionally opening a PR
super-commit push --create-pr --base main
```

Commit types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`, `ci`,
`revert`. Pick the narrowest one that fits; use `--scope` for a subsystem hint (e.g.
`--scope agents`, `--scope db`) when it adds useful signal.

**Attribution footer:** when a Claude Code session's system prompt specifies commit
attribution (a `Co-Authored-By:` trailer and/or a `Claude-Session:` link), pass it via
`--footer`, e.g.:

```bash
sc --all --type feat --subject "add outreach follow-up tool" \
   --footer "Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01V5R2eGD7VsPPbo34dXZZmk" \
   --yes
```

If `super-commit`/`sc` is not on `PATH` in whatever environment is running you, that's a
setup problem to flag, not a license to fall back to `git commit` silently — say so and
ask, or install it with `uv tool install super-commit-cli` if you have a way to fetch it.

## Everything else

Normal engineering judgment applies: write tests for behavior changes, run
`uv run pytest` before committing, keep commits scoped to one logical change.
