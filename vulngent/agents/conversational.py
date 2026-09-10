from __future__ import annotations

from textwrap import dedent

from autogen_agentchat.agents import AssistantAgent

from vulngent.agents import tools as agent_tools
from vulngent.agents.model_client import build_model_client
from vulngent.chat.confirmation import ConfirmationManager

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
]

SECTION_FORMAT_INSTRUCTION = (
    "Structure your reply into labeled sections so the UI can highlight them. Wrap each section exactly like:\n"
    "[SECTION:key] ...markdown content... [/SECTION]\n"
    "Use 2-5 short snake_case keys that fit the reply (e.g. summary, findings, top_risks, next_steps, plan, details). "
    "Keep each section self-contained. Do not mention the markers in the prose."
)


class SectionedModelClient:
    """Wraps a model client to append the section-format system instruction to the current turn.

    AssistantAgent in autogen 0.7.5 builds llm_messages as system_messages + memory context;
    there is no supported hook for a per-turn extra system message that stays memory-aware,
    so we inject at the client boundary where the message list is already final."""

    def __init__(self, inner):
        self._inner = inner

    def _inject(self, messages):
        from autogen_core.models import SystemMessage

        # Don't stack duplicates on retries within the same turn.
        if any(isinstance(m, SystemMessage) and SECTION_FORMAT_INSTRUCTION[:40] in m.content for m in messages):
            return messages
        return list(messages) + [SystemMessage(content=SECTION_FORMAT_INSTRUCTION)]

    async def create(self, messages, **kwargs):
        return await self._inner.create(self._inject(messages), **kwargs)

    def create_stream(self, messages, **kwargs):
        return self._inner.create_stream(self._inject(messages), **kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _make_planner(confirmation_manager: ConfirmationManager):
    """Bind plan_write_action to this session's ConfirmationManager.

    The static-contextvar approach broke down under AutoGen's task/generator
    layering: the manager set by use_confirmation_manager was visible to the
    websocket handler coroutine but not to the tool-execution task AutoGen
    spawned separately, so plan_write_action saw a None manager and returned
    a silent error the model echoed back. Binding per-session via closure is
    explicit and context-free."""

    def plan_write_action(tool_name: str, arguments: dict | None = None, summary: str | None = None) -> str:
        """Record a planned side-effecting action and return its details for the analyst's confirmation."""
        import json

        args = dict(arguments) if arguments else {}
        confirmation_manager.set_pending_action(tool_name, args, summary)
        payload = {
            "status": "pending_confirmation",
            "tool_name": tool_name,
            "arguments": args,
            "summary": summary or "",
        }
        return json.dumps(payload)

    plan_write_action.__name__ = "plan_write_action"
    plan_write_action.__module__ = "vulngent.agents.conversational"
    return plan_write_action


class ConversationalAgent:
    def __init__(self, model: str | None = None, confirmation_manager: ConfirmationManager | None = None):
        from vulngent.config import get_settings

        self.model_name = model or get_settings().openrouter_model
        self._confirmation_manager = confirmation_manager or ConfirmationManager()
        planner = _make_planner(self._confirmation_manager)
        self._agent = AssistantAgent(
            name="vulngent_conversational",
            model_client=SectionedModelClient(build_model_client(model)),
            system_message=SYSTEM_PROMPT,
            tools=[*READ_ONLY_TOOLS, planner],
            reflect_on_tool_use=True,
            max_tool_iterations=4,
        )

    async def run(self, task: str):
        return await self._agent.run(task=task, output_task_messages=False)

    def run_stream(self, task: str | None = None, *, output_task_messages: bool = True):
        return self._agent.run_stream(task=task, output_task_messages=output_task_messages)
