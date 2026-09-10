from __future__ import annotations

from textwrap import dedent

from autogen_agentchat.agents import AssistantAgent

from vulngent.agents import tools as agent_tools
from vulngent.agents.model_client import build_model_client
from vulngent.chat.planner import plan_write_action

WRITE_TOOL_NAMES = [
    "create_github_issue_for_vuln",
    "send_slack_update",
    "send_email_update",
    "record_inbound_reply",
    "record_commitment",
    "update_commitment_status",
    "add_remediation_step",
    "update_remediation_step_status",
    "set_vulnerability_status",
    "link_github_prs_and_commits",
    "sync_jira_ticket",
]

SYSTEM_PROMPT = dedent(
    """
    You are the vulngent conversational analyst. Answer the user's questions about the vulnerability
    ledger by calling the available read-only tools whenever you need data. Do not hallucinate or guess
    values that have not been returned from a tool. Always describe which tool you used when quoting data.

    When you need to trigger a workflow with side effects, call `plan_write_action` with the tool name
    (one of: {write_tools}) plus the same arguments you would eventually pass to that tool, and a short
    summary of the plan. After that, explicitly describe the plan back to the analyst and end your response
    asking for confirmation with "Do you want to proceed? [Yes/No]". Wait for the analyst's confirmation
    before repeating the tool call again.

    If a shareable report artifact would help the analyst (e.g. a leadership update, a status summary they
    want to circulate, or when they ask for a report), call `suggest_report` with a format (md, pdf, or
    docx) and a short reason. The UI shows a one-click generate button, so prefer suggesting a report over
    pasting a long report into the chat.

    Keep replies concise and friendly, and output Markdown so the UI can render it nicely.

    Structure every substantive reply into labeled sections. Wrap each section like this:
      [SECTION:key] ...markdown content... [/SECTION]
    Use short snake_case keys that describe the content (e.g. summary, findings, top_risks,
    next_steps, plan, details). Pick keys that fit the reply; 2-5 sections is typical. The UI
    uses these markers to let the analyst highlight a section and ask follow-ups about it, so
    keep each section self-contained. Never mention the markers themselves in the prose.
    """
).strip().format(write_tools=", ".join(WRITE_TOOL_NAMES))

READ_ONLY_TOOLS = [
    agent_tools.list_open_vulnerabilities,
    agent_tools.find_low_hanging_fruit,
    agent_tools.get_vulnerability_detail,
    agent_tools.list_commitments_due_soon,
    agent_tools.list_overdue_vulnerabilities,
    agent_tools.list_assets,
    agent_tools.list_vulnerabilities_by_filter,
    agent_tools.get_asset_summary,
    agent_tools.generate_status_report,
    agent_tools.suggest_report,
    plan_write_action,
]


class ConversationalAgent:
    def __init__(self, model: str | None = None):
        from vulngent.config import get_settings

        self.model_name = model or get_settings().openrouter_model
        self._agent = AssistantAgent(
            name="vulngent_conversational",
            model_client=build_model_client(model),
            system_message=SYSTEM_PROMPT,
            tools=READ_ONLY_TOOLS,
            reflect_on_tool_use=True,
            max_tool_iterations=4,
        )

    async def run(self, task: str):
        return await self._agent.run(task=task, output_task_messages=False)

    def run_stream(self, task: str | None = None, *, output_task_messages: bool = True):
        return self._agent.run_stream(task=task, output_task_messages=output_task_messages)
