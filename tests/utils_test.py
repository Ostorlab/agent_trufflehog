"""Unittest for helper funstions"""

import base64
import json
from typing import Any

import pytest
from pytest_mock import plugin

from agent import utils


def _build_jwt(payload: dict[str, Any]) -> str:
    """Build a compact JWT string with a fixed header and a base64url payload."""
    header = {"alg": "RS256", "kid": "test-kid"}

    def _segment(data: dict[str, Any]) -> str:
        raw = json.dumps(data, separators=(",", ":")).encode("ascii")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    return f"{_segment(header)}.{_segment(payload)}.c2lnbmF0dXJl"


def testLoadNewLineJson_always_LoadDataCorrectly() -> None:
    input_value = (
        b'{"id": 1,'
        b'"first_name": "Jeanette",'
        b'"last_name": "Penddreth",'
        b'"email": "jpenddreth0@census.gov",'
        b'"gender": "Female",'
        b'"ip_address": "26.58.193.2"'
        b"}\n"
        b"{"
        b'"id": 2,'
        b'"first_name": "Giavani",'
        b'"last_name": "Frediani",'
        b'"email": "gfrediani1@senate.gov",'
        b'"gender": "Male",'
        b'"ip_address": "229.179.4.212"}'
    )
    expected_result = [
        {
            "id": 1,
            "first_name": "Jeanette",
            "last_name": "Penddreth",
            "email": "jpenddreth0@census.gov",
            "gender": "Female",
            "ip_address": "26.58.193.2",
        },
        {
            "id": 2,
            "first_name": "Giavani",
            "last_name": "Frediani",
            "email": "gfrediani1@senate.gov",
            "gender": "Male",
            "ip_address": "229.179.4.212",
        },
    ]

    current_result = utils.load_newline_json(input_value)

    assert len(current_result) == len(expected_result)
    assert any(
        curr_elem["id"] == expected_elem["id"]
        for curr_elem, expected_elem in zip(current_result, expected_result)
    )


def testPruneReports_always_dedupCorrectly() -> None:
    dups_list = [
        {
            "Raw": 1,
            "first_name": "Jeanette",
            "last_name": "Penddreth",
            "email": "jpenddreth0@census.gov",
            "gender": "Female",
            "ip_address": "26.58.193.2",
        },
        {
            "Raw": 2,
            "first_name": "Giavani",
            "last_name": "Frediani",
            "email": "gfrediani1@senate.gov",
            "gender": "Male",
            "ip_address": "229.179.4.212",
        },
        {
            "Raw": 2,
            "first_name": "Giavani",
            "last_name": "Frediani",
            "email": "gfrediani1@senate.gov",
            "gender": "Male",
            "ip_address": "229.179.4.212",
        },
        {
            "Raw": 2,
            "first_name": "Giavani",
            "last_name": "Frediani",
            "email": "gfrediani1@senate.gov",
            "gender": "Male",
            "ip_address": "229.179.4.212",
        },
        {
            "Raw": 1,
            "first_name": "Jeanette",
            "last_name": "Penddreth",
            "email": "jpenddreth0@census.gov",
            "gender": "Female",
            "ip_address": "26.58.193.2",
        },
    ]

    deduped_list = utils.prune_reports(dups_list)

    assert len(deduped_list) == 2


def testEscapeBacktick_always_returnExpectedText() -> None:
    token_with_backtick = "SomeSecret`super`"
    assert utils.escape_backtick(token_with_backtick) == "SomeSecret\\`super\\`"


def testIsShortLivedSessionTokenJwt_whenCognitoIdToken_isTrue() -> None:
    """A Cognito ID token (token_use=id) is a short-lived session token."""
    token = _build_jwt(
        {
            "sub": "9245a4e4-e011-7069-98a1-0c30cca61479",
            "iss": "https://cognito-idp.eu-west-1.amazonaws.com/eu-west-1_0qT3FNUlW",
            "token_use": "id",
            "iat": 1795143222,
            "exp": 1795143821,
        }
    )

    assert utils.is_short_lived_session_token_jwt(token) is True


def testIsShortLivedSessionTokenJwt_whenCognitoAccessToken_isTrue() -> None:
    """A Cognito access token (token_use=access) is a short-lived session token."""
    token = _build_jwt({"token_use": "access", "iat": 1000, "exp": 1001})

    assert utils.is_short_lived_session_token_jwt(token) is True


def testIsShortLivedSessionTokenJwt_whenShortLivedWithoutTokenUse_isTrue() -> None:
    """A JWT with a short iat/exp window is a session token even without token_use."""
    token = _build_jwt({"iat": 1795143222, "exp": 1795143521})

    assert utils.is_short_lived_session_token_jwt(token) is True


def testIsShortLivedSessionTokenJwt_whenLongLivedJwt_isFalse() -> None:
    """A long-lived JWT is a persisted-style credential, not a session token."""
    token = _build_jwt({"iat": 1000, "exp": 1000 + 30 * 24 * 60 * 60})

    assert utils.is_short_lived_session_token_jwt(token) is False


@pytest.mark.parametrize("token_use", ["id", "access"])
@pytest.mark.parametrize("expiration", [None, 1000 + 30 * 24 * 60 * 60])
def testIsShortLivedSessionTokenJwt_whenSessionLifetimeIsUnproven_isFalse(
    token_use: str, expiration: int | None
) -> None:
    """A session claim alone cannot establish that a JWT is short-lived."""
    claims: dict[str, Any] = {"token_use": token_use, "iat": 1000}
    if expiration is not None:
        claims["exp"] = expiration

    assert utils.is_short_lived_session_token_jwt(_build_jwt(claims)) is False


def testIsShortLivedSessionTokenJwt_whenRefreshTokenUse_isFalse() -> None:
    """A token_use value other than id/access is not treated as a session token."""
    token = _build_jwt({"token_use": "refresh", "iat": 1000, "exp": 1001})

    assert utils.is_short_lived_session_token_jwt(token) is False


def testIsShortLivedSessionTokenJwt_whenNotAJwt_isFalse() -> None:
    """A non-JWT secret is never a session token JWT."""
    assert utils.is_short_lived_session_token_jwt("plain_secret") is False


def testIsShortLivedSessionTokenJwt_whenMalformedJwt_isFalse() -> None:
    """A token that is not a well-formed three-segment JWT is not matched."""
    assert utils.is_short_lived_session_token_jwt("header.payload") is False


def testIsShortLivedSessionTokenJwt_whenJsonExceedsRecursionLimit_isFalse(
    mocker: plugin.MockerFixture,
) -> None:
    """Treat payloads the JSON parser cannot decode as ordinary secrets."""
    token = _build_jwt({"iat": 1000, "exp": 1001})
    mocker.patch("agent.utils.json.loads", side_effect=RecursionError)

    assert utils.is_short_lived_session_token_jwt(token) is False


def testIsShortLivedSessionTokenJwt_whenPayloadIsNotObject_isFalse() -> None:
    """A JWT whose payload is not a JSON object is not matched."""
    header = base64.urlsafe_b64encode(b'{"alg":"RS256"}').rstrip(b"=").decode("ascii")
    array_payload = base64.urlsafe_b64encode(b"[1,2,3]").rstrip(b"=").decode("ascii")
    malformed = f"{header}.{array_payload}.c2lnbmF0dXJl"
    assert utils.is_short_lived_session_token_jwt(malformed) is False


def testIsShortLivedSessionTokenJwt_whenNoTimingClaims_isFalse() -> None:
    """A JWT with no token_use and no iat/exp claims is not a session token."""
    token = _build_jwt({"sub": "some-user", "aud": "some-client"})

    assert utils.is_short_lived_session_token_jwt(token) is False


@pytest.mark.parametrize(
    "path,content,type",
    [
        (
            "some/path.jpg",
            b"\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x01\x00\x60",
            "image",
        ),
        (
            "some/path.plist",
            b"bplist00\xd1\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
            "binary_plist",
        ),
        (
            "some/otherpath.plist",
            b'<?xml version="1.0" encoding="UTF-8"?>\n',
            "xml_plist",
        ),
        ("AndroidManifest.xml", b"\x03\x00\x08\x00", "android_manifest"),
        ("some/path.xml", b"\x03\x00\x08\x00", "android_binary_xml"),
        ("some/path.font", b"\x77\x4f\x46\x32", "font"),
        ("some/path.js", b"", "js"),
        ("some/path.html", b"", "html"),
        ("some/path.dll", b"", "dll"),
        ("some/path.xml", b"", "xml"),
        ("some/path.json", b"", "json"),
        ("some/path.css", b"", "css"),
        ("some/path.apk", b"", "apk"),
        ("some/path.ipa", b"", "ipa"),
        ("some/path.xapk", b"", "xapk"),
        ("some/path.stuff", b"", "unknown"),
    ],
)
def testGetFileType_always_detectTheCorrectType(
    path: str, content: bytes, type: str
) -> None:
    assert utils.get_file_type(path, content) == type


def testShouldExcludePath_whenPathMatchesPattern_shouldReturnTrue() -> None:
    """A path matching an exclude pattern returns True."""
    result = utils.should_exclude_path("/workspace/src/main.py", [r"^/workspace(/|$)"])

    assert result is True


def testShouldExcludePath_whenPathDoesNotMatch_shouldReturnFalse() -> None:
    """A path not matching any pattern returns False."""
    result = utils.should_exclude_path("/tmp/main.py", [r"^/workspace(/|$)"])

    assert result is False


def testShouldExcludePath_whenSimilarPrefixNotUnderWorkspace_shouldReturnFalse() -> (
    None
):
    """A lookalike path is not excluded by the anchored pattern."""
    result = utils.should_exclude_path("/workspace_backup/a.py", [r"^/workspace(/|$)"])

    assert result is False


def testShouldExcludePath_whenLaterPatternMatches_shouldReturnTrue() -> None:
    """A match on any pattern in the list returns True."""
    result = utils.should_exclude_path(
        "/private/a.py", [r"^/workspace(/|$)", r"^/private(/|$)"]
    )

    assert result is True


def testShouldExcludePath_whenPathIsNone_shouldReturnFalse() -> None:
    """A None path is never excluded."""
    result = utils.should_exclude_path(None, [r"^/workspace(/|$)"])

    assert result is False


def testShouldExcludePath_whenExcludePathsIsEmpty_shouldReturnFalse() -> None:
    """An empty pattern list excludes nothing."""
    result = utils.should_exclude_path("/workspace/a.py", [])

    assert result is False


def testShouldExcludePath_whenExcludePathsIsNone_shouldReturnFalse() -> None:
    """A None pattern list excludes nothing."""
    result = utils.should_exclude_path("/workspace/a.py", None)

    assert result is False


def testShouldExcludePath_whenRegexIsInvalid_shouldSkipPatternAndReturnFalse() -> None:
    """An invalid regex pattern is skipped instead of raising."""
    result = utils.should_exclude_path("/workspace/a.py", ["[invalid("])

    assert result is False


def testConstructRepositoryAssetDirectory_whenGitUrl_returnsNameAndCommitHash() -> None:
    """A `.git` repository URL yields `<repository_name>_<commit_hash>`."""
    result = utils.construct_repository_asset_directory(
        "https://github.com/Ostorlab/agent_trufflehog.git",
        "a1a10cdbc6551ba359169a3033f193b7f8c1b95d",
    )

    assert result == "agent_trufflehog_a1a10cdbc6551ba359169a3033f193b7f8c1b95d"


def testConstructRepositoryAssetDirectory_whenUrlWithoutGitSuffix_returnsNameAndCommitHash() -> (
    None
):
    """A repository URL without a `.git` suffix still yields the bare repository name."""
    result = utils.construct_repository_asset_directory(
        "https://github.com/Ostorlab/agent_trufflehog",
        "abc123",
    )

    assert result == "agent_trufflehog_abc123"


def testConstructRepositoryAssetDirectory_whenTrailingSlash_returnsNameAndCommitHash() -> (
    None
):
    """A trailing slash on the repository URL does not leak into the folder name."""
    result = utils.construct_repository_asset_directory(
        "https://github.com/Ostorlab/agent_trufflehog.git/",
        "abc123",
    )

    assert result == "agent_trufflehog_abc123"


@pytest.mark.parametrize(
    ("repository_url", "expected_repository_name"),
    [
        ("https://github.com/example-org/juice-shop-private", "juice-shop-private"),
        ("https://gitlab.com/example-user/juice-shop-private", "juice-shop-private"),
        ("https://bitbucket.org/example-user/juice-shop", "juice-shop"),
        (
            "https://example-org@dev.azure.com/example-org/test-project/_git/juice-shop",
            "juice-shop",
        ),
        ("git://git.example.com/example-org/juice-shop.git", "juice-shop"),
    ],
)
def testConstructRepositoryAssetDirectory_whenProviderUrlShapes_returnsNameAndCommitHash(
    repository_url: str, expected_repository_name: str
) -> None:
    """Supported repository provider URL shapes yield `<repository_name>_<commit_hash>`."""
    result = utils.construct_repository_asset_directory(repository_url, "abc123")

    assert result == f"{expected_repository_name}_abc123"


@pytest.mark.parametrize(
    "repository_url",
    ["", "/", "https://github.com/", "https://github.com/user/.git"],
)
def testConstructRepositoryAssetDirectory_whenUrlHasNoRepositoryName_raisesValueError(
    repository_url: str,
) -> None:
    """A URL with no derivable repository name is rejected by the helper."""
    with pytest.raises(ValueError):
        utils.construct_repository_asset_directory(repository_url, "abc123")


def testConstructRepositoryArchiveAssetDirectory_returnsSegmentAfterUploads() -> None:
    """The archive directory is the path segment immediately after `uploads`."""
    result = utils.construct_repository_archive_asset_directory(
        "https://example.com/uploads/62f54a92-6d5f-4ce8-848e-adf13ff79fee"
    )

    assert result == "62f54a92-6d5f-4ce8-848e-adf13ff79fee"


def testConstructRepositoryArchiveAssetDirectory_whenUploadsFollowedByPath_returnsUuid() -> (
    None
):
    """Only the segment after `uploads` is kept, later path segments are ignored."""
    result = utils.construct_repository_archive_asset_directory(
        "https://example.com/uploads/cc3714/archive/main.zip"
    )

    assert result == "cc3714"


def testConstructRepositoryArchiveAssetDirectory_whenQueryParams_ignoresQuery() -> None:
    """Query parameters on the content URL are ignored when deriving the directory."""
    result = utils.construct_repository_archive_asset_directory(
        "https://example.com/uploads/abc-123?token=secret&expiry=1"
    )

    assert result == "abc-123"


def testConstructRepositoryArchiveAssetDirectory_whenTrailingSlash_returnsLastSegment() -> (
    None
):
    """A trailing slash does not produce an empty segment."""
    result = utils.construct_repository_archive_asset_directory(
        "https://example.com/uploads/abc-123/"
    )

    assert result == "abc-123"


def testConstructRepositoryArchiveAssetDirectory_whenNoUploadsSegment_raisesValueError() -> (
    None
):
    """An archive URL without an `uploads` segment is rejected instead of
    falling back to an unrelated path segment."""
    with pytest.raises(ValueError):
        utils.construct_repository_archive_asset_directory(
            "https://example.com/archives/abc-123"
        )


def testConstructRepositoryArchiveAssetDirectory_whenUploadsIsLastSegment_raisesValueError() -> (
    None
):
    """An archive URL whose `uploads` segment has no asset identifier after it
    is rejected instead of returning `uploads` as the directory name."""
    with pytest.raises(ValueError):
        utils.construct_repository_archive_asset_directory(
            "https://example.com/uploads"
        )


def testConstructRepositoryArchiveAssetDirectory_whenUploadsTrailingSlash_raisesValueError() -> (
    None
):
    """A trailing slash after `uploads` does not produce an asset identifier."""
    with pytest.raises(ValueError):
        utils.construct_repository_archive_asset_directory(
            "https://example.com/uploads/"
        )
