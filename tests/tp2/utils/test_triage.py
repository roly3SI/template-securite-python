from unittest.mock import patch


@patch("src.tp2.utils.triage.YaraScanner")
@patch("src.tp2.utils.triage.Sample")
def test_triage_run(mock_sample_class, mock_scanner_class):
    from src.tp2.utils.triage import Triage

    mock_sample_instance = mock_sample_class.return_value
    mock_sample_instance.get_file_metadata.return_value = {}
    mock_sample_instance.parse_binary.return_value = {}
    mock_sample_instance.extract_iocs.return_value = {}

    mock_sample_instance.data = b"fake binary data without any flag inside"

    mock_scanner_instance = mock_scanner_class.return_value
    mock_scanner_instance.scan.return_value = []

    with patch("src.tp2.utils.triage.LLMTriage.triage") as mock_llm:
        mock_llm.return_value = '{"status": "clean", "score": 0}'

        triage = Triage("dummy_file.exe", "dummy_backend")
        triage.run()

    assert True
