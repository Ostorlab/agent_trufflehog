"""Module that provides functions to handle specific input selectors."""

import re


def get_link_type(link: str) -> str | None:
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
