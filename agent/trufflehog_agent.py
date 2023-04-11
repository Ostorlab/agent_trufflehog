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


from agent import utils


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

    def _process_and_run_link(self, message: m.Message) -> bytes | None:
        link = message.data.get("url", "")
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

        logger.info("Starting trufflehog scanner.")

        return self._run_scanner(link, link_type)

    def _process_and_run_file(self, message: m.Message) -> bytes | None:
        with tempfile.NamedTemporaryFile() as target_file:
            target_file.write(message.data.get("content", b""))
            target_file.seek(0)
            input_media = target_file.name

            logger.info("Starting trufflehog scanner.")

            cmd_output = self._run_scanner(input_media, "filesystem")
        return cmd_output

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

    def _run_scanner(self, input_type: str, input_media: str) -> bytes | None:
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
        logger.info("Processing input.")

        if message.selector == "v3.asset.link":
            cmd_output = self._process_and_run_link(message)
        elif message.selector == "v3.asset.file":
            cmd_output = self._process_and_run_file(message)

        if cmd_output is None:
            return

        logger.info("Parsing trufflehog output.")

        secrets = self._process_scanner_output(cmd_output)

        logger.info("Reporting vulnerabilities.")

        self._report_vulnz(secrets, message)


if __name__ == "__main__":
    logger.info("Starting agent ...")
    TruffleHogAgent.main()
