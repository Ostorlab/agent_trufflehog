"""Tests for the process_input Module."""
import pytest

from agent import process_input


@pytest.mark.parametrize(
    "github_link, gitlab_link, other_link",
    [
        (
            "https://github.com/user/repo.git",
            "https://gitlab.com/kalilinux/packages/trufflehog.git",
            "http://www.example.com/",
        ),
        (
            "http://github.com/Ostorlab/agent_trufflehog.git",
            "http://gitlab.com/open-source-projects-lambda/cpython_mirror.git",
            "http://www.example.edu/ball/box.html",
        ),
    ],
)
def testProcessLink_whenGit_returnsCorrectType(
    github_link: str, gitlab_link: str, other_link: str
) -> None:
    github_match = process_input.get_link_type(github_link)
    gitlab_match = process_input.get_link_type(gitlab_link)
    other_link_match = process_input.get_link_type(other_link)

    assert github_match == "git"
    assert gitlab_match == "gitlab"
    assert other_link_match is None
