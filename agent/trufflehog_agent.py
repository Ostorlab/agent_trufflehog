"""Trufflehog agent."""

import logging
import subprocess
import tempfile
from typing import Any

from ostorlab.agent import agent
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from rich import logging as rich_logging
from ostorlab.assets import asset as os_asset
from ostorlab.assets import ios_store
from ostorlab.assets import android_store

from agent import input_type_handler
from agent import utils

BLACKLISTED_FILE_TYPES = ["image", "apple_image", "font", "css", "apk", "xapk", "ipa"]

logging.basicConfig(
    format="%(message)s",
    datefmt="[%X]",
    level="INFO",
    force=True,
    handlers=[rich_logging.RichHandler(rich_tracebacks=True)],
)

logger = logging.getLogger(__name__)


def _process_file(content: bytes) -> bytes | None:
    with tempfile.NamedTemporaryFile() as target_file:
        target_file.write(content)
        target_file.seek(0)
        input_file = target_file.name
        cmd_output = TruffleHogAgent.run_scanner("filesystem", input_file)
    return cmd_output


def _prepare_vulnerability_location(
    message: m.Message,
    file_path: str,
) -> vuln_mixin.VulnerabilityLocation | None:
    """Prepare a `VulnerabilityLocation` instance with iOS asset & its Bundle ID, with file path as vulnerability metadata."""
    package_name = message.data.get("android_metadata", {}).get("package_name")
    bundle_id = message.data.get("ios_metadata", {}).get("bundle_id")
    if bundle_id is None and package_name is None:
        return None
    asset: os_asset.Asset | None = None
    if bundle_id is not None:
        asset = ios_store.IOSStore(bundle_id=bundle_id)
    if package_name is not None:
        asset = android_store.AndroidStore(package_name=package_name)

    return vuln_mixin.VulnerabilityLocation(
        asset=asset,
        metadata=[
            vuln_mixin.VulnerabilityLocationMetadata(
                metadata_type=vuln_mixin.MetadataType.FILE_PATH,
                value=file_path,
            )
        ],
    )


class TruffleHogAgent(
    agent.Agent,
    agent_persist_mixin.AgentPersistMixin,
    vuln_mixin.AgentReportVulnMixin,
):
    """
    This class represents TruffleHog agent.
    this class uses the TruffleHog tool to scan files for secrets.
    """

    def _report_vulnz(self, vulnz: list[dict[str, Any]], message: m.Message) -> None:
        for vuln in vulnz:
            secret_token = vuln.get("Raw") or vuln.get("Redacted")
            if secret_token is None:
                logger.error("Trying to emit a vulnerability with no secret: %s", vuln)
                continue
            secret_token = utils.escape_backtick(secret_token)
            logger.info("Secret found : %s.", vuln["Redacted"])
            technical_detail = f"""Secret `{secret_token}` """
            secret_type = vuln.get("DetectorName")
            if secret_type is not None:
                technical_detail += f"""of type `{secret_type}` """
            vulnerability_location = None
            path = message.data.get("path")

            if path is not None:
                technical_detail += f"""found in file `{path}`."""
                vulnerability_location = _prepare_vulnerability_location(
                    message=message, file_path=path
                )

            if vuln.get("Verified") is True:
                self.report_vulnerability(
                    entry=kb.KB.SECRETS_REVIEW,
                    risk_rating=vuln_mixin.RiskRating.HIGH,
                    technical_detail=technical_detail,
                    vulnerability_location=vulnerability_location,
                )

    def _process_scanner_output(self, output: bytes) -> list[dict[str, Any]]:
        secrets = utils.load_newline_json(output)
        secrets = utils.prune_reports(secrets)
        return secrets

    @staticmethod
    def run_scanner(input_type: str, input_media: str) -> bytes | None:
        try:
            cmd_output = subprocess.check_output(
                ["trufflehog", input_type, input_media, "--json"]
            )
        except subprocess.CalledProcessError as e:
            logger.error("Error : %s", e)
            return None
        return cmd_output

    def process(self, message: m.Message) -> None:
        """
        Runs the trufflehog tool ont the file/link received.

        Args:
            message: the message containing the trufflehog tool input file.

        Returns:
            None.
        """
        logger.debug("Processing input and Starting trufflehog.")

        cmd_output = None
        if message.selector.startswith("v3.asset.link"):
            link = message.data.get("url", "")
            link_type = input_type_handler.get_link_type(link)
            if link_type is None:
                return
            cmd_output = self.run_scanner(link_type, link)
        elif message.selector.startswith("v3.asset.file"):
            path = message.data.get("path", "")
            content = message.data.get("content", b"")
            file_type = utils.get_file_type(filename=path, file_content=content)
            if file_type in BLACKLISTED_FILE_TYPES:
                logger.debug(
                    "Skipping file %s with blacklisted type %s", path, file_type
                )
                return
            cmd_output = _process_file(content)
        elif message.selector.startswith("v3.capture.logs"):
            content = message.data.get("message", "")
            cmd_output = _process_file(content.encode("utf-8"))
        elif message.selector.startswith("v3.capture.request_response"):
            response = message.data.get("response", {})
            request = message.data.get("request", {})
            content = response.get("body", b"") + b"\n" + request.get("body", b"")
            cmd_output = _process_file(content)
        if cmd_output is None:
            return

        logger.debug("Parsing trufflehog output.")

        secrets = self._process_scanner_output(cmd_output)

        self._report_vulnz(secrets, message)


if __name__ == "__main__":
    logger.info("Starting agent ...")
    TruffleHogAgent.main()
