"""The vulngent agent team: Triage, Outreach, and Tracker agents orchestrated as a
round-robin AutoGen conversation, backed by Claude via OpenRouter."""

from __future__ import annotations

from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.conditions import MaxMessageTermination, TextMentionTermination
from autogen_agentchat.teams import RoundRobinGroupChat

from vulngent.agents import tools as t
from vulngent.agents.model_client import build_model_client

TRIAGE_SYSTEM_MESSAGE = """You are the Triage Agent for vulngent, a vulnerability remediation ledger.

Your job each cycle:
1. List open vulnerabilities and review any with unknown/pending reachability.
2. For vulnerabilities where reachability is unclear from the data alone, ask the
   security analyst directly (ask_security_analyst) rather than guessing - reachability
   materially changes priority.
3. Set reachability and recompute priority scores as you learn more.
4. Call find_low_hanging_fruit to surface high-impact, low-effort items and call them
   out explicitly by id and title for the Outreach agent to act on.

Be concise. When you've finished triage for this cycle, hand off by summarizing what you
prioritized and why, then say the word NEXT so the Outreach agent can continue."""

OUTREACH_SYSTEM_MESSAGE = """You are the Outreach Agent for vulngent, a vulnerability remediation ledger.

Your job each cycle:
1. For the highest-priority vulnerabilities the Triage agent flagged, look up the owning
   stakeholder (get_vulnerability_detail) and send them a status request or update via
   Slack or email - whichever contact info is available.
2. Record any commitments stakeholders make (record_commitment) with a concrete date.
3. Check list_commitments_due_soon and follow up on ones at risk.
4. Keep messages short, specific (name the CVE/finding and the ask), and professional.

If integrations aren't configured you'll get an ERROR string back - don't retry the same
call, just note it and move on. When done, summarize what outreach happened, then say the
word NEXT so the Tracker agent can continue."""

TRACKER_SYSTEM_MESSAGE = """You are the Tracker Agent for vulngent, a vulnerability remediation ledger.

Your job each cycle:
1. For in-progress vulnerabilities with a linked GitHub repo, call
   link_github_prs_and_commits to pick up new PRs/commits referencing the finding.
2. Keep remediation steps and vulnerability status current (add_remediation_step,
   update_remediation_step_status, set_vulnerability_status) based on what you learn.
3. Sync Jira tickets (sync_jira_ticket) for vulnerabilities that need PM-tool tracking.
4. Finish every cycle by calling generate_status_report and presenting it in full.

When your status report is presented, end your message with the single word
CYCLE_COMPLETE."""


def build_team(model: str | None = None) -> RoundRobinGroupChat:
    model_client = build_model_client(model)

    shared_tools = [t.list_open_vulnerabilities, t.get_vulnerability_detail, t.ask_security_analyst]

    triage_agent = AssistantAgent(
        name="triage_agent",
        model_client=model_client,
        system_message=TRIAGE_SYSTEM_MESSAGE,
        tools=[
            *shared_tools,
            t.find_low_hanging_fruit,
            t.set_vulnerability_reachability,
            t.recompute_priority,
        ],
        reflect_on_tool_use=True,
        max_tool_iterations=10,
    )

    outreach_agent = AssistantAgent(
        name="outreach_agent",
        model_client=model_client,
        system_message=OUTREACH_SYSTEM_MESSAGE,
        tools=[
            *shared_tools,
            t.send_slack_update,
            t.send_email_update,
            t.get_communication_history,
            t.record_inbound_reply,
            t.record_commitment,
            t.list_commitments_due_soon,
            t.update_commitment_status,
        ],
        reflect_on_tool_use=True,
        max_tool_iterations=10,
    )

    tracker_agent = AssistantAgent(
        name="tracker_agent",
        model_client=model_client,
        system_message=TRACKER_SYSTEM_MESSAGE,
        tools=[
            *shared_tools,
            t.add_remediation_step,
            t.update_remediation_step_status,
            t.set_vulnerability_status,
            t.create_github_issue_for_vuln,
            t.link_github_prs_and_commits,
            t.sync_jira_ticket,
            t.generate_status_report,
        ],
        reflect_on_tool_use=True,
        max_tool_iterations=10,
    )

    termination = MaxMessageTermination(30) | TextMentionTermination("CYCLE_COMPLETE")

    return RoundRobinGroupChat(
        [triage_agent, outreach_agent, tracker_agent],
        termination_condition=termination,
    )
