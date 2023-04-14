"""
    conftest for trufflehog agent tests
"""

import pytest
import random
import pathlib
from typing import Dict

from ostorlab.agent.message import message
from ostorlab.agent import definitions as agent_definitions
from ostorlab.runtimes import definitions as runtime_definitions
from agent import trufflehog_agent


@pytest.fixture
def scan_message_file() -> message.Message:
    """Creates a dummy message of type v3.asset.file to be used by the agent for testing purposes."""
    selector = "v3.asset.file"
    with open("./tests/keys", "rb") as infile:
        msg_data = {"content": infile.read()}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_gihub_without_key() -> message.Message:
    """Creates a dummy message of type v3.asset.link to be used by the agent for testing purposes."""
    selector = "v3.asset.link"
    msg_data = {"url": "https://github.com/trufflesecurity/test_keys.git"}
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_logs() -> message.Message:
    """Creates a dummy message of type v3.capture.logs to be used by the agent for testing purposes."""
    selector = "v3.capture.logs"
    msg_data = {
        "message": "03/22 08:51:06 INFO   :.....mailslot_create: creating mailslot for RSVP\
03/22 08:51:06 INFO   :....mailbox_register: mailbox allocated for rsvp\
03/22 08:51:06 INFO   :.....mailslot_create: creating mailslot for RSVP via UDP\
03/22 08:51:06 INFO   :....mailbox_register: mailbox allocated for rsvp-udp\
03/22 08:51:06 TRACE  :..entity_initialize: interface 127.0.0.1, entity for rsvp allocated and initialized\
03/22 08:51:06 INFO   :......mailslot_create: creating socket for querying route\
03/22 08:51:06 INFO   :.....mailbox_register: no mailbox necessary for forward\
03/22 08:51:06 INFO   :......mailslot_create: creating mailslot for route engine - informational socket\
03/22 08:51:06 TRACE  :......mailslot_create: ready to accept informational socket connection\
03/22 08:51:11 INFO   :.....mailbox_register: mailbox allocated for route"
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture
def scan_message_request_response() -> message.Message:
    """Creates a dummy message of type v3.asset.link to be used by the agent for testing purposes."""
    selector = "v3.capture.request_response"
    msg_data = {
        "response": {
            "body": b"Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum \
            has been the industry's standard dummy text ever since the 1500s, when an unknown printer took \
                a galley of type and scrambled it to make a type specimen book."
        },
        "request": {
            "body": b"It has survived not only five centuries, but also the leap into electronic \
            typesetting, remaining essentially unchanged"
        },
    }
    return message.Message.from_data(selector, data=msg_data)


@pytest.fixture()
def trufflehog_agent_file(
    agent_persist_mock: Dict[str | bytes, str | bytes]
) -> trufflehog_agent.TruffleHogAgent:
    with (pathlib.Path(__file__).parent.parent / "ostorlab.yaml").open() as yaml_o:
        definition = agent_definitions.AgentDefinition.from_yaml(yaml_o)
        settings = runtime_definitions.AgentSettings(
            key="agent/ostorlab/trufflehog",
            bus_url="NA",
            bus_exchange_topic="NA",
            args=[],
            healthcheck_port=random.randint(5000, 6000),
            redis_url="redis://guest:guest@localhost:6379",
        )
        agent_object = trufflehog_agent.TruffleHogAgent(definition, settings)
    return agent_object
