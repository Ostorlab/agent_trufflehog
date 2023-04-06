"""Unittest for helper funstions"""

from agent.helpers import load_newline_json, prune_vulnerabilities


def testLoadNewLineJson_always_LoadDataCorrectly():
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

    current_result = load_newline_json(input_value)

    assert len(current_result) == len(expected_result)
    assert any(
        curr_elem["id"] == expected_elem["id"]
        for curr_elem, expected_elem in zip(current_result, expected_result)
    )


def testPrune_always_dedupCorrectly():
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

    deduped_list = prune_vulnerabilities(dups_list)

    assert len(deduped_list) == 2
