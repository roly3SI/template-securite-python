from src.tp2.utils.sample import Sample


def test_shannon_entropy(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_bytes(b"\x00\xff\x55\xaa")
    s = Sample(str(test_file))
    assert s.shannon_entropy() == 2.0


def test_extract_iocs(tmp_path):
    test_file = tmp_path / "test.bin"
    test_file.write_text("C2: http://evil.com IP: 192.168.1.1")
    s = Sample(str(test_file))
    iocs = s.extract_iocs()
    assert "192.168.1.1" in iocs["ips"]
    assert "http://evil.com" in iocs["urls"]
