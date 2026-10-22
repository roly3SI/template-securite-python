from src.tp2.utils.scanner import YaraScanner

def test_yara_scanner_invalide():
    scanner = YaraScanner("blabla.yar")
    matches = scanner.scan(b"random malware data")
    assert matches == []