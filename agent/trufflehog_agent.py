"""Trufflehog agent."""
import logging
import tempfile
import subprocess
from typing import Any

from rich import logging as rich_logging
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent import agent
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.message import message as m


from agent import trufflehog_utility_functions


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

    def __report_vulnz(self, vulnz: list[dict[str, Any]], message: m.Message) -> None:
        for vuln in vulnz:
            logger.info("Secret found : %s.", vuln["Redacted"])
            self.report_vulnerability(
                entry=kb.KB.SECRETS_REVIEW,
                risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                technical_detail=f'Secret `{vuln["Redacted"]}` found in file `{message.data.get("path")}`',
            )

    def __process_scanner_output(self, output: bytes) -> list[dict[str, Any]]:
        secrets = trufflehog_utility_functions.load_newline_json(output)
        secrets = trufflehog_utility_functions.prune_reports(secrets)
        return secrets

    def __run_scanner(self, input_file: str) -> bytes | None:
        try:
            cmd_output = subprocess.check_output(
                ["trufflehog", "filesystem", input_file, "--only-verified", "--json"]
            )
        except subprocess.CalledProcessError:
            return None
        return cmd_output

    def process(self, message: m.Message) -> None:
        """Runs the trufflehog tool ont the file/link recieved.

        Args:
            message: the message containing the trufflehog tool input file.

        Returns:
            None.
        """
        logger.info("Processing input.")

        with tempfile.NamedTemporaryFile() as target_file:
            target_file.write(message.data.get("content", b""))
            target_file.seek(0)
            input_media = target_file.name

            logger.info("Starting trufflehog tool.")

            cmd_output = self.__run_scanner(input_media)
            if cmd_output is None:
                return

            logger.info("Parsing trufflehog output.")

            secrets = self.__process_scanner_output(cmd_output)

        logger.info("Reporting vulnerabilities.")

        self.__report_vulnz(secrets, message)


if __name__ == "__main__":
    logger.info("Starting agent ...")
    TruffleHogAgent.main()
