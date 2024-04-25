from lib.fixit import FixItClient

def test_extract_id():
    valid_tags = ["#7502349", "# 758489712", "#      93557821"]
    for tag in valid_tags:
        assert FixItClient.extract_id(tag)
    
    invalid_tags = ["12315123", "3141", "DAE", "ZZZ", "#Abekat", "#ajsd"]
    for tag in invalid_tags:
        assert not FixItClient.extract_id(tag)
