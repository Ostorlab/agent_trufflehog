"""Trufflehog agent."""
import logging
import tempfile
import subprocess
from typing import Any
import re

from rich import logging as rich_logging
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent import agent
from ostorlab.agent.kb import kb
from ostorlab.agent.mixins import agent_report_vulnerability_mixin
from ostorlab.agent.message import message as m


from agent import utils, process_input


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

    def _report_vulnz(self, vulnz: list[dict[str, Any]], message: m.Message) -> None:
        for vuln in vulnz:
            logger.info("Secret found : %s.", vuln["Redacted"])
            self.report_vulnerability(
                entry=kb.KB.SECRETS_REVIEW,
                risk_rating=agent_report_vulnerability_mixin.RiskRating.HIGH,
                technical_detail=f'Secret `{vuln["Redacted"]}` found in file `{message.data.get("path")}`',
            )

    def _process_scanner_output(self, output: bytes) -> list[dict[str, Any]]:
        secrets = utils.load_newline_json(output)
        secrets = utils.prune_reports(secrets)
        return secrets

    @staticmethod
    def _run_scanner(input_type: str, input_media: str) -> bytes | None:
        try:
            cmd_output = subprocess.check_output(
                ["trufflehog", input_type, input_media, "--only-verified", "--json"]
            )
        except subprocess.CalledProcessError:
            return None
        return cmd_output

    def process(self, message: m.Message) -> None:
        """
        Runs the trufflehog tool ont the file/link recieved.

        Args:
            message: the message containing the trufflehog tool input file.

        Returns:
            None.
        """
        logger.info("Processing input and Starting trufflehog.")

        if message.selector == "v3.asset.link":
            cmd_output = process_input.process_and_run_link(message.data.get("url", ""))
        elif message.selector == "v3.asset.file":
            cmd_output = process_input.process_and_run_file(
                message.data.get("content", b"")
            )

        if cmd_output is None:
            return

        logger.info("Parsing trufflehog output.")

        secrets = self._process_scanner_output(cmd_output)

        logger.info("Reporting vulnerabilities.")

        self._report_vulnz(secrets, message)


if __name__ == "__main__":
    logger.info("Starting agent ...")
    TruffleHogAgent.main()
