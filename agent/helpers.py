"""Helper functions for the Trufflehog agent"""
import json


def load_newline_json(byte_data: bytes) -> list[dict[str:any]]:
    """Convertes bytes to a list of dictionaries.

    Args:
        result: the message to be parsed into a list of dictionaries.

    Returns:
        A list of dictionaries.
    """
    string = byte_data.decode("utf-8")
    data_list = string.split("\n")
    return list(json.loads(element) for element in data_list if element != "")


def prune_vulnerabilities(
    secrets: list[dict[str:any]],
) -> list[dict[str:any]]:
    """Prune the list of dictionaries from duplicates.

    Args:
        dicts: list of secrets found by trufflehog.

    Returns:
        A list of unique secret dictionaries.
    """
    my_set: set[str] = set()
    new_secrets: list = []
    for secret in secrets:
        if secret.get("Raw", "") not in my_set:
            new_secrets.append(secret)
        my_set.add(secret["Raw"])
    return new_secrets
