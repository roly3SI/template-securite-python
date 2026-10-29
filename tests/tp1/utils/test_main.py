import sys
from unittest.mock import patch, MagicMock

from src.tp1.main import parse_args, main


def test_parse_args():
    test_args = ["tp1", "--pcap", "test.pcap", "--out", "result.json"]
    with patch.object(sys, "argv", test_args):
        args = parse_args()
        assert args.pcap == "test.pcap"
        assert args.out == "result.json"


@patch("src.tp1.main.parse_args")
@patch("src.tp1.main.Capture")
@patch("src.tp1.main.Report")
@patch("builtins.open")
@patch("src.tp1.main.json.dump")
def test_main(mock_json_dump, mock_open, MockReport, MockCapture, mock_parse_args):
    mock_args = MagicMock()
    mock_args.pcap = "test.pcap"
    mock_args.out = "test.json"
    mock_parse_args.return_value = mock_args

    mock_capture_instance = MagicMock()
    mock_capture_instance.get_summary.return_value = {"flag": "ESGI{MOCK}"}
    MockCapture.return_value = mock_capture_instance

    mock_report_instance = MagicMock()
    MockReport.return_value = mock_report_instance

    main()

    mock_capture_instance.read_pcap.assert_called_once_with("test.pcap")
    mock_capture_instance.analyse.assert_called_once_with("all")
    mock_report_instance.generate.assert_any_call("graph")
    mock_report_instance.generate.assert_any_call("array")
    mock_report_instance.save.assert_called_once_with("report.pdf")
    mock_open.assert_called_once_with("test.json", "w", encoding="utf-8")
    mock_json_dump.assert_called_once()
