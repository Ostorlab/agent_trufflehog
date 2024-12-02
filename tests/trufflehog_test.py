"""Unittest for truflehog agent."""

from typing import Dict
import logging

from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import trufflehog_agent


def testTruffleHog_whenFileHasFinding_reportVulnerabilities(
    scan_message_file: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: Dict[str | bytes, str | bytes],
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
        data={"content": b"some file content"},
    )

    trufflehog_agent_file.process(msg)

    assert len(agent_mock) == 1
    assert agent_mock[0].selector == "v3.report.vulnerability"
    technical_detail = agent_mock[0].data.get("technical_detail")
    assert technical_detail is not None
    assert (
        "Secret `https://admin:admin@the-internet.herokuapp.com` of type `URI` found"
        in technical_detail
    )
    assert agent_mock[0].data.get("risk_rating") == "HIGH"


def testSubprocessParameter_whenProcessingFile_beValid(
    scan_message_file: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: Dict[str | bytes, str | bytes],
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
    agent_persist_mock: Dict[str | bytes, str | bytes],
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
    agent_persist_mock: Dict[str | bytes, str | bytes],
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
    agent_persist_mock: Dict[str | bytes, str | bytes],
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
    agent_persist_mock: Dict[str | bytes, str | bytes],
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
    agent_persist_mock: Dict[str | bytes, str | bytes],
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
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
    caplog,
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
