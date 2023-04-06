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


def prune_reports(
    reports: list[dict[str:any]],
) -> list[dict[str:any]]:
    """Prune the list of dictionaries from duplicates.

    Args:
        reports: list of secrets found by trufflehog.

    Returns:
        A list of unique secret dictionaries.
    """
    dedup_set = set()
    unique_reports: list = []
    for secret in reports:
        if secret.get("Raw", "") not in dedup_set:
            unique_reports.append(secret)
        dedup_set.add(secret["Raw"])
    return unique_reports
