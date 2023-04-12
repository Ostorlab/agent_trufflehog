"""Tests for the process_input Module."""
from agent import process_input


def testProcessLink_Always_returnCorrectType() -> None:
    github_links = [
        "https://github.com/user/repo.git",
        "http://github.com/Ostorlab/agent_trufflehog.git",
    ]
    gitlab_links = [
        "https://gitlab.com/kalilinux/packages/trufflehog.git",
        "http://gitlab.com/open-source-projects-lambda/cpython_mirror.git",
    ]
    other_links = [
        "http://www.example.com/",
        "http://www.example.edu/ball/box.html",
        "https://sample.info/?insect=fireman&porter=attraction#cave",
    ]

    github_match = [
        process_input.process_link(link)
        for link in github_links
        if process_input.process_link(link) == "git"
    ]
    gitlab_match = [
        process_input.process_link(link)
        for link in gitlab_links
        if process_input.process_link(link) == "gitlab"
    ]
    other_match = [
        process_input.process_link(link)
        for link in other_links
        if process_input.process_link(link) == "gitlab"
    ]

    assert len(github_links) == len(github_match)
    assert len(gitlab_links) == len(gitlab_match)
    assert len(other_match) == 0
