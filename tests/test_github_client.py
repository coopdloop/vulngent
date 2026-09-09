from __future__ import annotations

import pytest

from vulngent.integrations.github_client import parse_repo_full_name


@pytest.mark.parametrize(
    "value",
    [
        "owner/repo",
        "https://github.com/owner/repo",
        "https://github.com/owner/repo/",
        "https://github.com/owner/repo.git",
        "http://github.com/owner/repo",
        "github.com/owner/repo",
        "www.github.com/owner/repo",
        "git@github.com:owner/repo.git",
        "git@github.com:owner/repo",
    ],
)
def test_parse_repo_full_name_accepts_all_common_forms(value: str) -> None:
    assert parse_repo_full_name(value) == "owner/repo"


@pytest.mark.parametrize(
    "value",
    [
        "not-a-repo-or-url",
        "https://gitlab.com/owner/repo",
        "owner/repo/extra",
        "justoneword",
        "",
    ],
)
def test_parse_repo_full_name_rejects_invalid_input(value: str) -> None:
    with pytest.raises(ValueError, match="Could not parse"):
        parse_repo_full_name(value)
