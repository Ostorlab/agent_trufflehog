"""Trufflehog agent."""
import logging
import tempfile
import json
import subprocess

from rich import logging as rich_logging
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent import agent
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.message import message as m


logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)

logger = logging.getLogger(__name__)
logger.setLevel("DEBUG")


def string_to_dict(result: bytes) -> dict:
    """Convertes bytes to a list of dictionaries.

    Args:
        result: the message to be parsed into a list of dictionaries.

    Returns:
        A list of dictionaries.
    """
    str_output = result.decode("utf-8")
    vulnz = str_output.split("\n")
    return [json.loads(v) for v in vulnz if v != ""]


def prune_duplicates(dicts: list) -> list:
    """Prune the list of dictionaries from duplicates.

    Args:
        dicts: list of secrets found by trufflehog.

    Returns:
        A list of unique secret dictionaries.
    """
    my_set: set[str] = set()
    new_dicts: list = []
    for d in dicts:
        if d["Raw"] not in my_set:
            new_dicts.append(d)
        my_set.add(d["Raw"])
    return new_dicts


class TruffleHogAgent(
    agent.Agent,
    agent_persist_mixin.AgentPersistMixin,
    agent_report_vulnerability_mixin.AgentReportVulnMixin,
):
    """Trufflehog agent."""

    def start(self) -> None:
        """starting agent"""
        logger.info("running start")

    def process(self, message: m.Message) -> None:
        """Runs the trufflehog tool ont the file/link recieved.

        Args:
            message: the message containing the trufflehog tool input.

        Returns:
            None.
        """
        logger.info("processing")

        with tempfile.NamedTemporaryFile(delete=False) as target_file:
            target_file.write(message.data.get("content"))
            target_file.seek(0)
            input_media = target_file.name

        logger.info("starting trufflehog")

        cmd_output = subprocess.check_output(
            ["trufflehog", "filesystem", input_media, "--only-verified", "--json"]
        )

        logger.info("managing output")

        dicts = string_to_dict(cmd_output)

        dicts = prune_duplicates(dicts)

        logger.info("reporting vulnerabilities")

        for d in dicts:
            self.report_vulnerability(
                entry=kb.KB.SECRETS_REVIEW,
                risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                technical_detail=f'Secret `{d["Redacted"]}` found in file `{message.data.get("path")}`',
            )
        del message


if __name__ == "__main__":
    logger.info("starting agent ...")
    TruffleHogAgent.main()
