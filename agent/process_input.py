"""Module that provides functions to handle specific input selectors."""

import tempfile
import re
from agent import trufflehog_agent


def process_link(link: str) -> str | None:
    link_type: str
    if (
        re.search(
            r"((git|ssh|http(s)?)|(git@[\w\.]+))(:(//)?)(github.com)([\w\.@\:/\-~]+)(\.git)(/)?",
            link,
        )
        is not None
    ):
        link_type = "git"
    elif (
        re.search(
            r"((git|ssh|http(s)?)|(git@[\w\.]+))(:(//)?)(gitlab.com)([\w\.@\:/\-~]+)(\.git)(/)?",
            link,
        )
        is not None
    ):
        link_type = "gitlab"
    else:
        return None
    return link_type


def process_file(content: bytes) -> bytes | None:
    with tempfile.NamedTemporaryFile() as target_file:
        target_file.write(content)
        target_file.seek(0)
        input_file = target_file.name
        cmd_output = trufflehog_agent.TruffleHogAgent.run_scanner(
            input_file, "filesystem"
        )
    return cmd_output
