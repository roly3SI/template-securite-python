from src.tp2.utils.scanner import YaraScanner
from unittest.mock import patch


def test_yara_scanner_invalide():
    scanner = YaraScanner("blabla.yar")
    matches = scanner.scan(b"random malware data")
    assert matches == []


@patch("src.tp2.utils.scanner.yara.compile")
def test_compile_rules(mock_compile):
    from src.tp2.utils.scanner import YaraScanner

    scanner = YaraScanner("rules")
    scanner._compile_rules()
    assert True
