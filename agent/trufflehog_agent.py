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


def json_loader(result: bytes) -> list:
    """Convertes bytes to a list of dictionaries.

    Args:
        result: the message to be parsed into a list of dictionaries.

    Returns:
        A list of dictionaries.
    """
    str_output = result.decode("utf-8")
    vulnz = str_output.split("\n")
    return [json.loads(v) for v in vulnz if v != ""]


def prune_duplicates_vulnerabilities(vulnz: list) -> list:
    """Prune the list of dictionaries from duplicates.

    Args:
        dicts: list of secrets found by trufflehog.

    Returns:
        A list of unique secret dictionaries.
    """
    my_set: set[str] = set()
    new_vulnz: list = []
    for vuln in vulnz:
        if vuln.get("Raw", "") not in my_set:
            new_vulnz.append(vuln)
        my_set.add(vuln["Raw"])
    return new_vulnz


class TruffleHogAgent(
    agent.Agent,
    agent_persist_mixin.AgentPersistMixin,
    agent_report_vulnerability_mixin.AgentReportVulnMixin,
):
    """
    This class represents TruffleHog agent.
    this class uses the TruffleHog tool to scan files for secrests.

    Methods:
        process(): This method runs the TruffleHog tool
            and reports secrets found.
    """

    def process(self, message: m.Message) -> None:
        """Runs the trufflehog tool ont the file/link recieved.

        Args:
            message: the message containing the trufflehog tool input file.

        Returns:
            None.
        """
        logger.info("Processing input.")

        with tempfile.NamedTemporaryFile() as target_file:
            target_file.write(message.data.get("content"))
            target_file.seek(0)
            input_media = target_file.name

            logger.info("Starting trufflehog tool.")

            cmd_output = subprocess.check_output(
                ["trufflehog", "filesystem", input_media, "--only-verified", "--json"]
            )

        logger.info("Parsing trufflehog output.")

        vulnz = json_loader(cmd_output)

        vulnz = prune_duplicates_vulnerabilities(vulnz)

        logger.info("Reporting vulnerabilities.")

        for vuln in vulnz:
            logger.info("Secret found : %s.", vuln["Redacted"])
            self.report_vulnerability(
                entry=kb.KB.SECRETS_REVIEW,
                risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                technical_detail=f'Secret `{vuln["Redacted"]}` found in file `{message.data.get("path")}`',
            )
        del message


if __name__ == "__main__":
    logger.info("Starting agent ...")
    try:
        TruffleHogAgent.main()
    except subprocess.CalledProcessError as e:
        logger.error(e.output)