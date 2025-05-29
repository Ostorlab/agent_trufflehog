"""Helper functions for the Trufflehog agent"""

import json
from typing import Any

import magic

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
