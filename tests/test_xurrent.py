"""Contains tests for the FixItClient class."""

from mde_fixit_integration.lib.xurrent import XurrentClient


def test_extract_id():
    """Test the FixItClient.extract_id method."""
    valid_tags = ["#7502349", "# 758489712", "#      93557821"]
    for tag in valid_tags:
        assert XurrentClient.extract_id(tag)

    invalid_tags = ["8792375", "DAE", "ZZZ", "#Abekat", "#ajsd", "A#51233", "#51233A"]
    for tag in invalid_tags:
        assert not XurrentClient.extract_id(tag)
