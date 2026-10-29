from src.tp2.utils.sample import Sample
from unittest.mock import patch, mock_open


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


@patch("src.tp2.utils.sample.magic.Magic")
@patch("builtins.open", new_callable=mock_open, read_data=b"fake_data")
def test_get_file_metadata(mock_file, mock_magic):
    from src.tp2.utils.sample import Sample

    sample = Sample("dummy.exe")
    sample.get_file_metadata()
    assert True


@patch("src.tp2.utils.sample.lief.parse")
@patch("builtins.open", new_callable=mock_open, read_data=b"fake_data")
def test_parse_binary(mock_file, mock_parse):
    from src.tp2.utils.sample import Sample

    sample = Sample("dummy.exe")
    sample.parse_binary()
    assert True
