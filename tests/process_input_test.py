"""Tests for the process_input Module."""
import pytest

from agent import process_input


# (
#     "",
#     ,
#     "",
# ),
# (
#     ,
#     ,
#     ,
# ),
@pytest.mark.parametrize(
    "url, expected_type",
    [
        ("https://github.com/Ostorlab/agent_trufflehog.git", "git"),
        ("https://gitlab.com/kalilinux/packages/trufflehog.git", "gitlab"),
        ("https://github.com/user/repo.git", "git"),
        ("https://www.example.com/", None),
        ("https://github.com/Ostorlab/agent_trufflehog.git", "git"),
        ("https://gitlab.com/open-source-projects-lambda/cpython_mirror.git", "gitlab"),
        ("https://www.example.edu/ball/box.html", None),
    ],
)
def testProcessLink_alwyas_returnsCorrectType(
    url: str,
    expected_type: str | None,
) -> None:
    link_type = process_input.get_link_type(url)
    assert link_type == expected_type
