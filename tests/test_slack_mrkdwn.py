from __future__ import annotations

from vulngent.integrations.slack_client import to_slack_mrkdwn


def test_bold_double_star_converts_to_single_star() -> None:
    assert to_slack_mrkdwn("**Timeline:**") == "*Timeline:*"


def test_underscore_bold_converts() -> None:
    assert to_slack_mrkdwn("__important__") == "*important*"


def test_heading_markers_are_stripped() -> None:
    assert to_slack_mrkdwn("## Findings\n### Next steps") == "Findings\nNext steps"


def test_heading_with_bold_inside() -> None:
    assert to_slack_mrkdwn("### **Status**") == "*Status*"


def test_links_become_slack_links() -> None:
    assert to_slack_mrkdwn("[CVE-2026-1234](https://nvd.nist.gov/x)") == "<https://nvd.nist.gov/x|CVE-2026-1234>"


def test_bullets_and_plain_text_passthrough() -> None:
    text = "• Ingested on 2026-09-08\n• No remediation steps recorded yet"
    assert to_slack_mrkdwn(text) == text


def test_code_fences_left_alone() -> None:
    block = "```\napt-get install foo\n```"
    assert to_slack_mrkdwn(block) == block
