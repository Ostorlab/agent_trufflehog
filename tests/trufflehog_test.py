"""Unittest for truflehog agent."""
from typing import Dict

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
    assert "https://********:********@the-internet.herokuapp.com" in str(
        agent_mock[0].data.get("technical_detail")
    )
    assert agent_mock[0].data.get("risk_rating") == "HIGH"


def testSubprocessParameter_whenProcessingFile_beValid(
    scan_message_file: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    magicMocker = mocker.patch("subprocess.check_output", return_value=b"")

    trufflehog_agent_file.process(scan_message_file)
    args = magicMocker.call_args[0][0]

    assert len(args) == 5
    assert args[0] == "trufflehog"
    assert args[1] == "filesystem"
    assert args[3] == "--only-verified"
    assert args[4] == "--json"

def testSubprocessParameter_whenProcessingLogs_beValid(
    scan_message_logs: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    magicMocker = mocker.patch("subprocess.check_output", return_value=b"")

    trufflehog_agent_file.process(scan_message_logs)
    args = magicMocker.call_args[0][0]

    assert len(args) == 5
    assert args[0] == "trufflehog"
    assert args[1] == "filesystem"
    assert args[3] == "--only-verified"
    assert args[4] == "--json"

def testSubprocessParameter_whenProcessingRequestResponse_beValid(
    scan_message_requestResponse: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    magicMocker = mocker.patch("subprocess.check_output", return_value=b"")

    trufflehog_agent_file.process(scan_message_requestResponse)
    args = magicMocker.call_args[0][0]

    assert len(args) == 5
    assert args[0] == "trufflehog"
    assert args[1] == "filesystem"
    assert args[3] == "--only-verified"
    assert args[4] == "--json"


def testSubprocessParameter_whenProcessingLink_beValid(
    scan_message_gihub_without_key: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock: list[message.Message],
) -> None:
    magicMocker = mocker.patch("subprocess.check_output", return_value=b"")

    trufflehog_agent_file.process(scan_message_gihub_without_key)
    args = magicMocker.call_args[0][0]

    assert len(args) == 5
    assert args[0] == "trufflehog"
    assert args[1] == "git"
    assert args[3] == "--only-verified"
    assert args[4] == "--json"
