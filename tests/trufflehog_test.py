"""Unittest for truflehog agent."""

import logging

import pytest
from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import trufflehog_agent


def testTruffleHog_whenFileHasFinding_reportVulnerabilities(
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    """Tests running the agent on a file and parsing the json output."""

    mocker.patch(
        "subprocess.check_output",
        return_value=b'{"SourceMetadata":{"Data":{"Git":{"commit":"77b2a3e56973785a52ba4ae4b8dac61d4bac016f",'
        b'"file":"keys","email":"counter 003ccounter@counters-MacBook-Air.local003e",'
        b'"repository":"https://github.com/trufflesecurity/test_keys","timestamp":"2022-06-16 10:27:56 -0700"'
        b',"line":3}}},"SourceID":0,"SourceType":16,"SourceName":"trufflehog - git","DetectorType":17,'
        b'"DetectorName":"URI","DecoderName":"BASE64","Verified":true,'
        b'"Raw":"https://admin:admin@the-internet.herokuapp.com",'
        b'"Redacted":"https://********:********@the-internet.herokuapp.com",'
        b'"ExtraData":null,"StructuredData":null}',
    )
    msg = message.Message.from_data(
        selector="v3.asset.file",
        data={
            "content": b"some file content",
            "path": "/tmp/path/file.txt",
            "android_metadata": {"package_name": "a.b.c"},
        },
    )

    trufflehog_agent_file.process(msg)

    assert len(agent_mock) == 1
    assert (
        agent_mock[0].data["dna"]
        == '{"location": {"android_store": {"package_name": "a.b.c"}, "metadata": [{"type": "FILE_PATH", "value": "/tmp/path/file.txt"}]}, "secret_token": "https://admin:admin@the-internet.herokuapp.com", "title": "Secret information stored in the application"}'
    )
    assert agent_mock[0].selector == "v3.report.vulnerability"
    vulnerability = agent_mock[0].data
    assert vulnerability["technical_detail"] is not None
    assert (
        "Secret `https://admin:admin@the-internet.herokuapp.com` of type `URI` found"
        in vulnerability["technical_detail"]
    )
    assert vulnerability["risk_rating"] == "HIGH"
    assert vulnerability["vulnerability_location"]["metadata"][0]["type"] == "FILE_PATH"
    assert (
        vulnerability["vulnerability_location"]["metadata"][0]["value"]
        == "/tmp/path/file.txt"
    )
    assert vulnerability["vulnerability_location"]["android_store"] is not None
    assert (
        vulnerability["vulnerability_location"]["android_store"]["package_name"]
        == "a.b.c"
    )


def testSubprocessParameter_whenProcessingFile_beValid(
    scan_message_file: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    subprocess_check_output_mock = mocker.patch(
        "subprocess.check_output", return_value=b""
    )

    trufflehog_agent_file.process(scan_message_file)
    args = subprocess_check_output_mock.call_args[0][0]

    assert len(args) == 4
    assert args[0] == "trufflehog"
    assert args[1] == "filesystem"
    assert args[3] == "--json"


def testSubprocessParameter_whenProcessingLogs_beValid(
    scan_message_logs: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    subprocess_check_output_mock = mocker.patch(
        "subprocess.check_output", return_value=b""
    )

    trufflehog_agent_file.process(scan_message_logs)
    args = subprocess_check_output_mock.call_args[0][0]

    assert len(args) == 4
    assert args[0] == "trufflehog"
    assert args[1] == "filesystem"
    assert args[3] == "--json"


def testSubprocessParameter_whenProcessingRequestResponse_beValid(
    scan_message_request_response: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    subprocess_check_output_mock = mocker.patch(
        "subprocess.check_output", return_value=b""
    )

    trufflehog_agent_file.process(scan_message_request_response)
    args = subprocess_check_output_mock.call_args[0][0]

    assert len(args) == 4
    assert args[0] == "trufflehog"
    assert args[1] == "filesystem"
    assert args[3] == "--json"


def testSubprocessParameter_whenProcessingLink_beValid(
    scan_message_gihub_without_key: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    subprocess_check_output_mock = mocker.patch(
        "subprocess.check_output", return_value=b""
    )

    trufflehog_agent_file.process(scan_message_gihub_without_key)
    args = subprocess_check_output_mock.call_args[0][0]

    assert len(args) == 4
    assert args[0] == "trufflehog"
    assert args[1] == "git"
    assert args[3] == "--json"


def testSubprocessParameter_whenProcessingInvalidGitLink_beValid(
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    """Verifies that `run_scanner` method of `TruffleHogAgent` is not called when processing an invalid git link."""
    subprocess_check_output_mock = mocker.patch(
        "agent.trufflehog_agent.TruffleHogAgent.run_scanner", return_value=None
    )
    invalid_gi_link_message = message.Message.from_data(
        selector="v3.asset.link",
        data={"url": "https://mykillers.com/mykillers/will/not..."},
    )
    trufflehog_agent_file.process(invalid_gi_link_message)

    assert subprocess_check_output_mock.call_count == 0


def testTrufflehog_whenProcessingVerifiedAndUnverifiedSecrets_shouldReportOnlyVerifiedVulns(
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    msg = message.Message.from_data(
        selector="v3.asset.file",
        data={"content": b"some file content", "path": "magic_is_real.js"},
    )
    mocker.patch(
        "subprocess.check_output",
        return_value=b'{"Verified":true,'
        b'"Raw":"https://admin:admin@the-internet.herokuapp.com",'
        b'"Redacted":"https://********:********@the-internet.herokuapp.com"}',
    )
    trufflehog_agent_file.process(msg)
    mocker.patch(
        "subprocess.check_output",
        return_value=b'{"Verified":false,'
        b'"Raw":"plain_secret",'
        b'"Redacted":"plain*secret"}',
    )
    trufflehog_agent_file.process(msg)

    assert len(agent_mock) == 1
    assert (
        agent_mock[0].data["dna"]
        == '{"secret_token": "https://admin:admin@the-internet.herokuapp.com", "title": "Secret information stored in the application"}'
    )
    assert agent_mock[0].data.get("risk_rating") == "HIGH"
    assert (
        "Secret `https://admin:admin@the-internet.herokuapp.com` found in file `magic_is_real.js`."
        == agent_mock[0].data.get("technical_detail")
    )


def testAgent_whenFileTypeIsUnrelated_skipIt(
    apk_message_file: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    """test that unrelated files are skipped."""
    subprocess_mock = mocker.patch("subprocess.check_output", return_value=b"")

    trufflehog_agent_file.process(apk_message_file)

    assert len(agent_mock) == 0
    assert subprocess_mock.call_count == 0


def testTrufflehog_whenProcessingSecrets_shouldLogNonCriticalMessagesAtDebugLeve(
    scan_message_file: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Tests that non-critical messages are logged at debug level."""

    mocker.patch(
        "subprocess.check_output",
        return_value=b'{"SourceMetadata":{"Data":{"Git":{"commit":"77b2a3e56973785a52ba4ae4b8dac61d4bac016f",'
        b'"file":"keys","email":"counter 003ccounter@counters-MacBook-Air.local003e",'
        b'"repository":"https://github.com/trufflesecurity/test_keys","timestamp":"2022-06-16 10:27:56 -0700"'
        b',"line":3}}},"SourceID":0,"SourceType":16,"SourceName":"trufflehog - git","DetectorType":17,'
        b'"DetectorName":"URI","DecoderName":"BASE64","Verified":true,'
        b'"Raw":"https://admin:admin@the-internet.herokuapp.com",'
        b'"Redacted":"https://********:********@the-internet.herokuapp.com",'
        b'"ExtraData":null,"StructuredData":null}',
    )
    msg = message.Message.from_data(
        selector="v3.asset.file",
        data={"content": b"some file content"},
    )
    logging.getLogger().setLevel(logging.DEBUG)

    trufflehog_agent_file.process(msg)

    for record in caplog.records:
        if (
            "Processing input and Starting trufflehog." in record.message
            or "Parsing trufflehog output." in record.message
        ):
            assert record.levelname == "DEBUG"


def testTruffleHog_whenFileHasFindingAndIosFile_reportVulnerabilitiesWithIosAssetMetadata(
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    """Ensure the reported vulnerability contains metadata about the exact file & the iOS asset information."""

    mocker.patch(
        "subprocess.check_output",
        return_value=b'{"SourceMetadata":{"Data":{"Git":{"commit":"77b2a3e56973785a52ba4ae4b8dac61d4bac016f",'
        b'"file":"keys","email":"counter 003ccounter@counters-MacBook-Air.local003e",'
        b'"repository":"https://github.com/trufflesecurity/test_keys","timestamp":"2022-06-16 10:27:56 -0700"'
        b',"line":3}}},"SourceID":0,"SourceType":16,"SourceName":"trufflehog - git","DetectorType":17,'
        b'"DetectorName":"URI","DecoderName":"BASE64","Verified":true,'
        b'"Raw":"https://admin:admin@the-internet.herokuapp.com",'
        b'"Redacted":"https://********:********@the-internet.herokuapp.com",'
        b'"ExtraData":null,"StructuredData":null}',
    )
    msg = message.Message.from_data(
        selector="v3.asset.file",
        data={
            "content": b"some file content",
            "path": "/tmp/path/file.txt",
            "ios_metadata": {"bundle_id": "a.b.c"},
        },
    )

    trufflehog_agent_file.process(msg)

    assert len(agent_mock) == 1
    assert (
        agent_mock[0].data["dna"]
        == '{"location": {"ios_store": {"bundle_id": "a.b.c"}, "metadata": [{"type": "FILE_PATH", "value": "/tmp/path/file.txt"}]}, "secret_token": "https://admin:admin@the-internet.herokuapp.com", "title": "Secret information stored in the application"}'
    )
    assert agent_mock[0].selector == "v3.report.vulnerability"
    vulnerability = agent_mock[0].data
    assert vulnerability["technical_detail"] is not None
    assert (
        "Secret `https://admin:admin@the-internet.herokuapp.com` of type `URI` found"
        in vulnerability["technical_detail"]
    )
    assert vulnerability["risk_rating"] == "HIGH"
    assert vulnerability["vulnerability_location"]["metadata"][0]["type"] == "FILE_PATH"
    assert (
        vulnerability["vulnerability_location"]["metadata"][0]["value"]
        == "/tmp/path/file.txt"
    )
    assert vulnerability["vulnerability_location"]["ios_store"] is not None
    assert vulnerability["vulnerability_location"]["ios_store"]["bundle_id"] == "a.b.c"


def testTrufflehog_whenLinkdAndUnverifiedSecrets_shouldReportOnlyVerifiedVulns(
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    msg = message.Message.from_data(
        selector="v3.asset.link",
        data={"url": "http://example.com/test"},
    )
    mocker.patch("agent.input_type_handler.get_link_type", return_value="git")
    mocker.patch(
        "subprocess.check_output",
        return_value=b'{"Verified":true,'
        b'"Raw":"https://admin:admin@the-internet.herokuapp.com",'
        b'"Redacted":"https://********:********@the-internet.herokuapp.com"}',
    )

    trufflehog_agent_file.process(msg)

    mocker.patch(
        "subprocess.check_output",
        return_value=b'{"Verified":false,'
        b'"Raw":"plain_secret",'
        b'"Redacted":"plain*secret"}',
    )
    trufflehog_agent_file.process(msg)

    assert len(agent_mock) == 1
    assert (
        agent_mock[0].data["dna"]
        == '{"location": {"domain_name": {"name": "example.com"}, "metadata": [{"type": "URL", "value": "http://example.com/test"}]}, "secret_token": "https://admin:admin@the-internet.herokuapp.com", "title": "Secret information stored in the application"}'
    )


def testTrufflehog_whenLogsMessageAndUnverifiedSecrets_shouldReportOnlyVerifiedVulns(
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    msg = message.Message.from_data(
        selector="v3.capture.logs",
        data={"message": "just a dummy logs"},
    )
    mocker.patch(
        "subprocess.check_output",
        return_value=b'{"Verified":true,'
        b'"Raw":"https://admin:admin@the-internet.herokuapp.com",'
        b'"Redacted":"https://********:********@the-internet.herokuapp.com"}',
    )

    trufflehog_agent_file.process(msg)
    mocker.patch(
        "subprocess.check_output",
        return_value=b'{"Verified":false,'
        b'"Raw":"plain_secret",'
        b'"Redacted":"plain*secret"}',
    )
    trufflehog_agent_file.process(msg)

    assert len(agent_mock) == 1
    assert (
        agent_mock[0].data["dna"]
        == '{"location": {"metadata": [{"type": "LOG", "value": "just a dummy logs"}]}, "secret_token": "https://admin:admin@the-internet.herokuapp.com", "title": "Secret information stored in the application"}'
    )


def testTruffleHog_whenFileHasBlackListedPath_skipProcessing(
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: dict[str | bytes, str | bytes],
    agent_mock: list[message.Message],
) -> None:
    """Ensure that we skip blacklisted path files."""
    msg = message.Message.from_data(
        selector="v3.asset.file",
        data={
            "content": b"some file content",
            "path": "/tmp/res/drawable/file.txt",
            "ios_metadata": {"bundle_id": "a.b.c"},
        },
    )

    trufflehog_agent_file.process(msg)

    assert len(agent_mock) == 0
