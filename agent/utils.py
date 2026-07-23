"""Helper functions for the Trufflehog agent"""

import json
import logging
import os
import re
from typing import Any
from urllib import parse

import magic

logger = logging.getLogger(__name__)


def build_repository_asset_directory(repository_url: str, commit_hash: str) -> str:
    """Build the repository extraction folder name used in multi-asset scans.

    Args:
        repository_url: URL of the repository asset.
        commit_hash: Commit hash checked out for the repository asset.

    Returns:
        Folder name composed from the repository name and commit hash.
    """
    parsed_url: parse.ParseResult = parse.urlparse(repository_url)
    repository_path: str = parsed_url.path
    if len(repository_path) == 0:
        repository_path = repository_url

    repository_name: str = os.path.basename(repository_path.rstrip("/"))
    if repository_name.endswith(".git") is True:
        repository_name = repository_name[: -len(".git")]
    return f"{repository_name}_{commit_hash}"


def build_repository_archive_asset_directory(content_url: str) -> str:
    """Build the archive extraction folder name from its uploaded content URL.

    Args:
        content_url: URL of the uploaded repository archive.

    Returns:
        Last path segment of the archive content URL.
    """
    parsed_url: parse.ParseResult = parse.urlparse(content_url)
    return os.path.basename(parsed_url.path.rstrip("/"))


def should_exclude_path(
    path: str | None, exclude_path_regexes: list[str] | None
) -> bool:
    """Report whether a file path matches one of the exclusion regex patterns.

    Args:
        path: The file path reported in the message, or None.
        exclude_path_regexes: List of regex patterns to match against the path.

    Returns:
        True if the path matches at least one pattern and should be skipped,
        False otherwise.
    """
    if path is None or exclude_path_regexes is None or len(exclude_path_regexes) == 0:
        return False
    for pattern in exclude_path_regexes:
        try:
            matched = re.search(pattern, path)
        except re.error as e:
            logger.warning("Invalid exclude_path_regexes regex %r: %s", pattern, e)
            continue
        if matched is not None:
            logger.info(
                "Skipping file %s: path matches exclude pattern %r.", path, pattern
            )
            return True
    return False


IRRELEVANT_FILE_PATHS = [
    "res/color",
    "res/drawable",
    "res/anim",
    "res/layout",
    "assets/dexopt",
    ".properties",
    "PhoneNumberAlternate",
    "PhoneNumberMetadata",
]


def load_newline_json(byte_data: bytes) -> list[dict[str, Any]]:
    """Convertes bytes to a list of dictionaries.

    Args:
        result: the message to be parsed into a list of dictionaries.

    Returns:
        A list of dictionaries.
    """
    string = byte_data.decode("utf-8")
    data_list = string.split("\n")
    return list(json.loads(element) for element in data_list if element != "")


def prune_reports(
    reports: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Prune the list of dictionaries from duplicates.

    Args:
        reports: list of secrets found by trufflehog.

    Returns:
        A list of unique secret dictionaries.
    """
    dedup_set = set()
    unique_reports = []
    for secret in reports:
        if secret.get("Raw", "") not in dedup_set:
            unique_reports.append(secret)
        dedup_set.add(secret["Raw"])
    return unique_reports


def escape_backtick(text: str) -> str:
    """Escapes backticks in the given text.
    Replaces each occurrence of a backtick (`) in the input text with a backslash followed by a backtick (\\`).
    Args:
        text: The input text containing backticks.
    Returns:
        The modified text with backticks escaped.
    """
    return text.replace("`", r"\`")


def get_file_type(filename: str, file_content: bytes) -> str:
    """Method responsible for getting the file type.
    Args:
        filename: Name of the file.
        file_content: Content of the file.
    Returns:
        File type as a string.
    """
    magic_type = magic.from_buffer(file_content)
    magic_mime_type = magic.from_buffer(file_content, mime=True)
    if any(irrelevant_path in filename for irrelevant_path in IRRELEVANT_FILE_PATHS):
        return "irrelevant"
    if (
        magic_type == "Android binary XML"
        and filename.endswith("AndroidManifest.xml") is True
    ):
        return "android_manifest"
    if magic_type == "Android binary XML":
        return "android_binary_xml"
    if filename.endswith(".js") or filename.endswith(".jsbundle"):
        return "js"
    if filename.endswith(".html"):
        return "html"
    if filename.endswith(".dll"):
        return "dll"
    if filename.endswith(".plist") and magic_type == "Apple binary property list":
        return "binary_plist"
    if filename.endswith(".plist") and magic_type.startswith("XML"):
        return "xml_plist"
    if filename.endswith(".xml"):
        return "xml"
    if magic_mime_type.startswith("image/"):
        return "image"
    if filename.endswith(".json"):
        return "json"
    if (
        magic_mime_type.startswith("font/")
        or "Font Format" in magic_type
        or filename.endswith(".otf")
    ):
        return "font"
    if filename.endswith(".css"):
        return "css"
    if filename.endswith(".apk"):
        return "apk"
    if filename.endswith(".ipa"):
        return "ipa"
    if filename.endswith(".xapk"):
        return "xapk"
    return "unknown"
