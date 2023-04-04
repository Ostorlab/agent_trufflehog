"""Unittests for truflehog agent."""
from typing import Dict

from ostorlab.agent.message import message
from pytest_mock import plugin

from agent import trufflehog_agent


def testTruffleHog_scanFile_reportTwoVulnz(
    scan_message_file: message.Message,
    trufflehog_agent_file: trufflehog_agent.TruffleHogAgent,
    agent_persist_mock: Dict[str | bytes, str | bytes],
    mocker: plugin.MockerFixture,
    agent_mock,
) -> None:
    """Tests running the agent on a file and parsing the json output."""

    trufflehog_agent_file.process(scan_message_file)

    assert len(agent_mock) == 2
    assert agent_mock[0].selector == "v3.report.vulnerability"


def testStringToDict_always_shouldBeEqual():
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

    current_result = trufflehog_agent.string_to_dict(input_value)

    assert len(current_result) == len(expected_result)
    for elems in zip(current_result, expected_result):
        assert elems[0]["id"] == elems[1]["id"]
