# `vulngent chat`: Specification

## 1. Overview

`vulngent chat` introduces an interactive, conversational web interface for the vulngent ledger. Instead of using discrete CLI commands, analysts can "talk" to a specialized vulngent agent to ask questions, get summaries, and initiate actions.

The core of this feature is a Retrieval-Augmented Generation (RAG) system where the agent uses its knowledge of the database schema and a suite of safe, read-only query tools to answer natural language questions about the vulnerability landscape. It combines this with the ability to use its existing "write" tools (e.g., file tickets, send notifications) on command, turning the chat into a powerful interactive control plane.

## 2. Goals & Non-Goals

### Goals

*   **Conversational Q&A:** Enable users to ask natural language questions (e.g., "How many critical vulns are open?", "Who owns the asset with the most overdue findings?", "Show me the details for CVE-2026-12345") and receive synthesized, accurate answers.
*   **Interactive Control:** Allow users to command the agent to perform actions using its existing tools, such as filing a GitHub issue, linking a PR, or recording a stakeholder commitment.
*   **Agent Transparency:** The UI must clearly display the agent's "thought process," showing which tools it's calling with which arguments, and the data it gets back. This builds trust and aids debugging.
*   **Lite & Local-First:** The web UI should be lightweight, served locally, and require no complex setup or external dependencies beyond the existing Python environment. It should be launched with a simple `vulngent chat` command.

### Non-Goals

*   **Multi-user Collaboration:** The initial version is a single-player tool for the analyst running it. Real-time collaboration, user accounts, and permissions are out of scope for v1.
*   **A Full Dashboarding UI:** This is not a replacement for Grafana or a BI tool. While it will present data, the primary interface is chat, not a complex, configurable dashboard with arbitrary charts and graphs.
*   **Internet Connectivity (for the UI):** The UI itself should be self-contained and not require an internet connection to load, though the agent's tools (e.g., GitHub, Slack) obviously will.

## 3. User Experience & Key Features

The UI will be a simple, single-page web application with three main components:

1.  **Chat History:** A scrollable view of the conversation between the user and the agent.
2.  **Input Box:** A standard text input for the user to type messages.
3.  **Tool Call Inspector:** When the agent uses a tool, a special "thinking..." message will appear, which can be expanded to show the sequence of tool calls, their arguments, and the results the agent received.

### Feature: RAG-based Q&A

The user can ask questions in plain English. The agent will determine the right sequence of database query tools to call, retrieve the data, and then generate a summary.

**Example User Prompts:**
*   `"Show me the top 5 highest-priority criticals."`
*   `"Are there any overdue vulnerabilities on the billing-service asset?"`
*   `"Generate a status report but only for the 'high' severity findings."`
*   `"Who owns the asset with CVE-2026-0005?"`

### Feature: Live Agent Actions

The user can command the agent to perform write actions. For any action that has external side effects (e.g., sending a message, creating a ticket), the agent must first present its plan and ask for confirmation.

**Example User Prompts:**
*   `"File a GitHub issue for vuln #21 on the my-continuous-blog repo."`
    *   **Agent Response:** `I am about to create a GitHub issue on coopdloop/my-continuous-blog with the title "[CRITICAL] CVE-2026-27699: basic-ftp: File overwrite due to path traversal". Do you want to proceed? [Yes/No]`
*   `"Send a slack to Devon Ruiz asking for an update on CVE-2026-04471."`
*   `"Record that Priya committed to fixing CVE-2026-30112 by next Friday."`

## 4. Technical Architecture

### Backend (`vulngent chat` command)

*   **Web Server:** A **FastAPI** server will be added to `vulngent`. It will be responsible for:
    1.  Serving the static HTML/JS/CSS for the web UI.
    2.  Providing a **WebSocket** endpoint (`/ws`) for the chat session.
*   **Agent:** A new `ConversationalAgent` will be created. Unlike the `run-cycle` group chat, this will be a single `AssistantAgent` configured with a specific system prompt for conversational Q&A and a full suite of tools (both read and write).
*   **Tools (RAG):** The existing `repository.py` functions are the foundation. We will add more granular, read-only query functions and expose them as tools to the agent.
    *   **Crucially, the LLM will *not* generate SQL.** It will generate calls to safe, parameterized Python functions like `list_vulnerabilities(severity="critical", is_overdue=True)`. This prevents SQL injection entirely.

### Frontend

*   A simple, dependency-free HTML page with vanilla JavaScript and CSS to manage the WebSocket connection and render the chat UI.
*   We can use a library like `marked.js` to render markdown in the agent's responses for better formatting.

## 5. Implementation Plan

### Phase 1: MVP - Read-Only RAG Chat

1.  **Create `vulngent chat` command:** Add the new command to `vulngent/cli.py` which starts the FastAPI server.
2.  **Build the FastAPI Backend:** Implement the server and the `/ws` WebSocket endpoint.
3.  **Develop the `ConversationalAgent`:** Create a new agent with a system prompt geared towards Q&A.
4.  **Expose Read-Only Tools:** Expose all necessary `list_*` and `get_*` functions from `repository.py` as agent tools.
5.  **Build the Web UI:** Create the basic `index.html` and JavaScript to connect to the WebSocket and display messages.

### Phase 2: Interactive Actions & Confirmation

1.  **Add Write Tools:** Grant the `ConversationalAgent` access to the "write" tools (`create_github_issue`, `send_slack_update`, etc.).
2.  **Implement Confirmation Flow:** Modify the agent's logic. When a write tool is invoked, instead of executing immediately, it sends a confirmation request to the UI. The UI displays a `[Yes/No]` prompt, and the user's response is sent back to the agent to either proceed or cancel.

### Phase 3: Enhancements

1.  **Streaming Tool Output:** Stream the agent's tool calls to the UI in real-time for a more responsive "thinking..." process.
2.  **Pre-built Queries:** Add buttons for common queries like "Show all overdue" or "Show criticals."
3.  **Context-Awareness:** Allow the agent to remember the context of the conversation (e.g., if you ask about "vuln #21", you can then ask "who owns it?" without repeating the ID).

## 6. Open Questions

*   **Authentication:** For a local-first tool, v1 will not have authentication. If this were to be deployed as a shared service, a robust auth layer (e.g., OAuth2) would be a critical requirement.
*   **Chat History Persistence:** Should conversations be saved? If so, where? In the `vulngent.db` or as separate files? For v1, history will be ephemeral and lost on server restart.
