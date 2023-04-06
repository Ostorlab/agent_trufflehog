"""Trufflehog agent."""
import logging
import tempfile
import subprocess

from rich import logging as rich_logging
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent import agent
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.message import message as m
from agent.helpers import prune_vulnerabilities, load_newline_json


logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)

logger = logging.getLogger(__name__)


class TruffleHogAgent(
    agent.Agent,
    agent_persist_mixin.AgentPersistMixin,
    agent_report_vulnerability_mixin.AgentReportVulnMixin,
):
    """
    This class represents TruffleHog agent.
    this class uses the TruffleHog tool to scan files for secrests.
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

            secrets = load_newline_json(cmd_output)

        secrets = prune_vulnerabilities(secrets)

        logger.info("Reporting vulnerabilities.")

        for secret in secrets:
            logger.info("Secret found : %s.", secret["Redacted"])
            self.report_vulnerability(
                entry=kb.KB.SECRETS_REVIEW,
                risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                technical_detail=f'Secret `{secret["Redacted"]}` found in file `{message.data.get("path")}`',
            )


if __name__ == "__main__":
    logger.info("Starting agent ...")
    try:
        TruffleHogAgent.main()
    except subprocess.CalledProcessError as e:
        logger.error(e.output)
