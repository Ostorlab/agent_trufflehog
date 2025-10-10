"""Trufflehog agent."""

import json
import logging
import subprocess
import tempfile
import time
from typing import Any
from urllib import parse

from ostorlab.agent import agent
from ostorlab.agent.kb import kb
from ostorlab.agent.message import message as m
from ostorlab.agent.mixins import agent_persist_mixin
from ostorlab.agent.mixins import agent_report_vulnerability_mixin as vuln_mixin
from rich import logging as rich_logging
from ostorlab.assets import ios_store
from ostorlab.assets import android_store
from ostorlab.assets import domain_name

from agent import input_type_handler
from agent import utils

BLACKLISTED_FILE_TYPES = [
    "image",
    "apple_image",
    "font",
    "css",
    "apk",
    "xapk",
    "ipa",
    "irrelevant",
]
LOGS_LOCK_KEY = "trufflehog_logs_lock"
LOGS_SET_KEY = "trufflehog_logs"
MAX_LOGS_BATCH_SIZE = 1000
LOCK_RETRIES = 3
LOCK_RETRY_DELAY = 2

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
    file_path: str | None,
    content: bytes,
) -> vuln_mixin.VulnerabilityLocation | None:
    """Prepare a `VulnerabilityLocation` instance with file path as vulnerability metadata and
    iOS/Android asset & their respective bundle-ID/package name as asset metadata.
    """
    asset: (
        domain_name.DomainName | ios_store.IOSStore | android_store.AndroidStore | None
    ) = None
    metadata = []
    if message.selector == "v3.asset.link":
        url = message.data.get("url")
        url_netloc = parse.urlparse(url).netloc
        asset = domain_name.DomainName(name=str(url_netloc))
        if url is not None:
            metadata.append(
                vuln_mixin.VulnerabilityLocationMetadata(
                    metadata_type=vuln_mixin.MetadataType.URL,
                    value=url,
                )
            )
    elif (
        message.selector == "v3.capture.logs"
        or message.selector == "v3.report.event.scan.done"
    ):
        metadata.append(
            vuln_mixin.VulnerabilityLocationMetadata(
                metadata_type=vuln_mixin.MetadataType.LOG,
                value=content.decode("utf-8"),
            )
        )

    else:
        package_name = message.data.get("android_metadata", {}).get("package_name")
        bundle_id = message.data.get("ios_metadata", {}).get("bundle_id")
        if bundle_id is None and package_name is None:
            return None
        if bundle_id is not None:
            asset = ios_store.IOSStore(bundle_id=bundle_id)
        if package_name is not None:
            asset = android_store.AndroidStore(package_name=package_name)

        metadata.append(
            vuln_mixin.VulnerabilityLocationMetadata(
                metadata_type=vuln_mixin.MetadataType.FILE_PATH,
                value=file_path or "",
            )
        )

    return vuln_mixin.VulnerabilityLocation(
        asset=asset,
        metadata=metadata,
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

    def _process_logs(
        self, log_content: bytes | None, force_process: bool = False
    ) -> tuple[bytes | None, bytes | None]:
        """Process logs with Redis synchronization.

        Args:
            log_content: The log content to add (empty if forcing processing)
            force_process: Whether to force processing regardless of batch size

        Returns:
            The scanner output if logs were processed, None otherwise
        """
        retries = LOCK_RETRIES
        while retries > 0:
            if self.set_add(LOGS_LOCK_KEY, "locked"):
                try:
                    if log_content is not None:
                        self.set_add(LOGS_SET_KEY, log_content)

                    if (
                        force_process is True
                        or self.set_len(LOGS_SET_KEY) >= MAX_LOGS_BATCH_SIZE
                    ):
                        logs = self.set_members(LOGS_SET_KEY)
                        if logs is not None and len(logs) > 0:
                            combined_content = b"\n".join([log for log in logs])
                            cmd_output = _process_file(combined_content)
                            self.delete(LOGS_SET_KEY)
                            return cmd_output, combined_content
                    break
                finally:
                    self.delete(LOGS_LOCK_KEY)
            else:
                retries -= 1
                time.sleep(LOCK_RETRY_DELAY)

        if retries == 0:
            logger.error("Failed to acquire lock after multiple retries")
        return None, None

    def _report_vulnz(
        self, vulnz: list[dict[str, Any]], message: m.Message, content: bytes
    ) -> None:
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
            path = message.data.get("path")

            if path is not None:
                technical_detail += f"""found in file `{path}`."""
            vulnerability_location = _prepare_vulnerability_location(
                message=message,
                file_path=path,
                content=content,
            )

            if vuln.get("Verified") is True:
                self.report_vulnerability(
                    entry=kb.KB.SECRETS_REVIEW,
                    risk_rating=vuln_mixin.RiskRating.HIGH,
                    technical_detail=technical_detail,
                    vulnerability_location=vulnerability_location,
                    dna=_compute_dna(
                        vuln_title=kb.KB.SECRETS_REVIEW.title,
                        vuln_location=vulnerability_location,
                        secret_token=secret_token,
                    ),
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

        Returns:<
            None.
        """
        logger.debug("Processing input and Starting trufflehog.")

        cmd_output = None
        combined_content = b""
        if message.selector.startswith("v3.asset.link"):
            link = message.data.get("url", "")
            link_type = input_type_handler.get_link_type(link)
            if link_type is None:
                return
            logger.info("Processing link %s of type %s", link, link_type)
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
            logger.info("Processing file %s with type %s", path, file_type)
            cmd_output = _process_file(content)
        elif message.selector.startswith("v3.capture.logs"):
            content = message.data.get("message", "")
            if content is not None:
                cmd_output, combined_content = self._process_logs(
                    content, force_process=False
                )
        elif message.selector == "v3.report.event.scan.done":
            logger.info("Processing scan done message.")
            cmd_output, combined_content = self._process_logs(
                log_content=None, force_process=True
            )
        elif message.selector.startswith("v3.capture.request_response"):
            response = message.data.get("response", {})
            request = message.data.get("request", {})
            logger.info(
                "Processing request and response content for url %s",
                request.get("url", ""),
            )
            content = response.get("body", b"") + b"\n" + request.get("body", b"")
            cmd_output = _process_file(content)
        if cmd_output is None:
            return

        logger.debug("Parsing trufflehog output.")

        secrets = self._process_scanner_output(cmd_output)

        self._report_vulnz(secrets, message, combined_content)


def _compute_dna(
    vuln_title: str,
    vuln_location: vuln_mixin.VulnerabilityLocation | None,
    secret_token: str,
) -> str:
    """Compute a deterministic, debuggable DNA representation for a vulnerability.
    Args:
        vuln_title: The title of the vulnerability.
        vuln_location: The location of the vulnerability.
        secret_token: The founded secret.
    Returns:
        A deterministic JSON representation of the vulnerability DNA.
    """
    dna_data: dict[str, Any] = {"title": vuln_title}

    if vuln_location is not None:
        location_dict: dict[str, Any] = vuln_location.to_dict()
        sorted_location_dict = _sort_dict(location_dict)
        dna_data["location"] = sorted_location_dict

    if secret_token is not None:
        dna_data["secret_token"] = secret_token

    return json.dumps(dna_data, sort_keys=True)


def _sort_dict(dictionary: dict[str, Any] | list[Any]) -> dict[str, Any] | list[Any]:
    """Recursively sort dictionary keys and lists within.
    Args:
        dictionary: The dictionary to sort.
    Returns:
        A sorted dictionary or list.
    """
    if isinstance(dictionary, dict):
        return {k: _sort_dict(v) for k, v in sorted(dictionary.items())}
    if isinstance(dictionary, list):
        return sorted(
            dictionary,
            key=lambda x: json.dumps(x, sort_keys=True)
            if isinstance(x, dict)
            else str(x),
        )
    return dictionary


if __name__ == "__main__":
    logger.info("Starting agent ...")
    TruffleHogAgent.main()
