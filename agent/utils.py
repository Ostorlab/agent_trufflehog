"""Helper functions for the Trufflehog agent"""

import base64
import json
import logging
import os
import re
from typing import Any, cast
from urllib import parse

import magic

logger = logging.getLogger(__name__)


def construct_repository_asset_directory(repository_url: str, commit_hash: str) -> str:
    """Construct the repository extraction directory name used in multi-asset scans.

    Args:
        repository_url: URL of the repository asset.
        commit_hash: Commit hash checked out for the repository asset.

    Returns:
        Directory name composed from the repository name and commit hash.

    Raises:
        ValueError: If the URL does not include a usable repository name.
    """
    parsed_url: parse.ParseResult = parse.urlparse(repository_url)
    repository_path: str = parsed_url.path
    if len(repository_path) == 0:
        repository_path = repository_url

    repository_name: str = os.path.basename(repository_path.rstrip("/"))
    if repository_name.endswith(".git") is True:
        repository_name = repository_name[: -len(".git")]
    if len(repository_name) == 0:
        raise ValueError(
            f"Repository URL has no repository name segment: {repository_url!r}"
        )
    return f"{repository_name}_{commit_hash}"


def construct_repository_archive_asset_directory(content_url: str) -> str:
    """Construct the archive extraction directory name from its uploaded content URL.

    The asset identifier is expected immediately after the ``uploads`` path
    segment, as in ``https://example.com/uploads/<uuid>/archive/main.zip``.
    Malformed archive URLs that carry no ``uploads`` segment, or no asset
    identifier after it, are rejected rather than falling back to an unrelated
    path segment.

    Args:
        content_url: URL of the uploaded repository archive.

    Returns:
        The asset directory name derived from the content URL.

    Raises:
        ValueError: If the content URL has no ``uploads`` segment or no asset
            identifier immediately after it.
    """
    parsed_url: parse.ParseResult = parse.urlparse(content_url)
    path_segments: list[str] = [
        segment for segment in parsed_url.path.split("/") if len(segment) > 0
    ]
    try:
        uploads_index: int = path_segments.index("uploads")
    except ValueError as e:
        raise ValueError(
            f"Repository archive content_url has no `uploads` segment: {content_url!r}"
        ) from e
    if uploads_index + 1 >= len(path_segments):
        raise ValueError(
            f"Repository archive content_url has no asset identifier after "
            f"`uploads`: {content_url!r}"
        )
    return path_segments[uploads_index + 1]


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
    return [json.loads(element) for element in data_list if element != ""]


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


# Token `token_use` claim values that identify a Cognito session token (an ID or
# an access token), as opposed to a long-lived credential. These tokens are
# minted for the running session and never persisted as application secrets.
JWT_TOKEN_USE_SESSION_VALUES = {"id", "access"}

# A session token has a short `iat`/`exp` window. Tokens whose lifetime is at
# most this many seconds are treated as transient session credentials.
SESSION_TOKEN_MAX_LIFETIME_SECONDS = 12 * 60 * 60

JWT_SEGMENT_COUNT = 3


def _decode_jwt_payload(secret_token: str) -> dict[str, Any] | None:
    """Decode and parse the payload segment of a JSON Web Token.

    Args:
        secret_token: The candidate secret, expected to be a compact JWT of the
            form ``<header>.<payload>.<signature>``.

    Returns:
        The parsed payload as a dict, or None when the value is not a
        well-formed three-segment JWT, its payload is not valid base64url JSON,
        or the payload is not a JSON object.
    """
    if secret_token.count(".") != JWT_SEGMENT_COUNT - 1:
        return None
    _header, payload, _signature = secret_token.split(".")
    try:
        padding = "=" * ((4 - len(payload) % 4) % 4)
        decoded = base64.urlsafe_b64decode((payload + padding).encode("ascii"))
        data = json.loads(decoded)
    except (ValueError, RecursionError):
        return None
    if isinstance(data, dict) is False:
        return None
    return cast(dict[str, Any], data)


def is_short_lived_session_token_jwt(secret_token: str) -> bool:
    """Report whether a secret is a short-lived session token JWT.

    Mobile runtime logs and auth responses frequently contain short-lived
    session tokens — Cognito ID and access tokens carry a ``token_use`` claim of
    ``id`` or ``access``, and session tokens in general are minted with a short
    ``iat``/``exp`` window. These are transient session credentials of the test
    run, not secrets persisted in the application.

    Args:
        secret_token: The candidate secret.

    Returns:
        True when the JWT's ``iat`` and ``exp`` claims show a lifetime within the
        session-token window. If present as a string, ``token_use`` must be
        ``id`` or ``access``.
    """
    payload = _decode_jwt_payload(secret_token)
    if payload is None:
        return False
    token_use = payload.get("token_use")
    if (
        isinstance(token_use, str)
        and token_use.lower() not in JWT_TOKEN_USE_SESSION_VALUES
    ):
        return False
    iat = payload.get("iat")
    exp = payload.get("exp")
    if isinstance(iat, int) and isinstance(exp, int):
        lifetime = exp - iat
        if 0 <= lifetime <= SESSION_TOKEN_MAX_LIFETIME_SECONDS:
            return True
    return False


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
    if filename.endswith((".js", ".jsbundle")):
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
