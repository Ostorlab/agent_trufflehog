"""Unittest for helper funstions"""

import pytest

from agent import utils


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


def testBuildRepositoryAssetDirectory_whenGitUrl_returnsNameAndCommitHash() -> None:
    """A `.git` repository URL yields `<repository_name>_<commit_hash>`."""
    result = utils.build_repository_asset_directory(
        "https://github.com/Ostorlab/agent_trufflehog.git",
        "a1a10cdbc6551ba359169a3033f193b7f8c1b95d",
    )

    assert result == "agent_trufflehog_a1a10cdbc6551ba359169a3033f193b7f8c1b95d"


def testBuildRepositoryAssetDirectory_whenUrlWithoutGitSuffix_returnsNameAndCommitHash() -> (
    None
):
    """A repository URL without a `.git` suffix still yields the bare repository name."""
    result = utils.build_repository_asset_directory(
        "https://github.com/Ostorlab/agent_trufflehog",
        "abc123",
    )

    assert result == "agent_trufflehog_abc123"


def testBuildRepositoryAssetDirectory_whenTrailingSlash_returnsNameAndCommitHash() -> (
    None
):
    """A trailing slash on the repository URL does not leak into the folder name."""
    result = utils.build_repository_asset_directory(
        "https://github.com/Ostorlab/agent_trufflehog.git/",
        "abc123",
    )

    assert result == "agent_trufflehog_abc123"


def testBuildRepositoryArchiveAssetDirectory_returnsLastPathSegment() -> None:
    """The archive directory is the last path segment of the content URL."""
    result = utils.build_repository_archive_asset_directory(
        "https://storage.googleapis.com/ostorlabapps/uploads/"
        "62f54a92-6d5f-4ce8-848e-adf13ff79fee"
    )

    assert result == "62f54a92-6d5f-4ce8-848e-adf13ff79fee"


def testBuildRepositoryArchiveAssetDirectory_whenQueryParams_ignoresQuery() -> None:
    """Query parameters on the content URL are ignored when deriving the directory."""
    result = utils.build_repository_archive_asset_directory(
        "https://storage.googleapis.com/uploads/abc-123?token=secret&expiry=1"
    )

    assert result == "abc-123"


def testBuildRepositoryArchiveAssetDirectory_whenTrailingSlash_returnsLastSegment() -> (
    None
):
    """A trailing slash does not produce an empty segment."""
    result = utils.build_repository_archive_asset_directory(
        "https://storage.googleapis.com/uploads/abc-123/"
    )

    assert result == "abc-123"
