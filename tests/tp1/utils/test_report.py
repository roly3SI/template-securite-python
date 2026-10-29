from unittest.mock import MagicMock, patch
from src.tp1.utils.report import Report


def test_report_init():
    capture = MagicMock()
    filename = "test.pdf"
    summary = {"flag": "test"}

    report = Report(capture, filename, summary)

    assert report.capture == capture
    assert report.filename == filename
    assert report.title == "Rapport d'Analyse"
    assert report.summary == summary
    assert report.array == ""


def test_concat_report():
    report = Report(MagicMock(), "test.pdf", {})
    report.title = "Test Title"
    report.array = "Test Array"

    result = report.concat_report()
    assert result == "Test Title\nTest Array"


@patch("src.tp1.utils.report.FPDF")
def test_save(MockFPDF):
    mock_doc = MagicMock()
    MockFPDF.return_value = mock_doc

    report = Report(MagicMock(), "test.pdf", {"protocols": {"TCP": 10}})
    report.title = "Test Title"

    report.save("test.pdf")

    mock_doc.add_page.assert_called_once()
    mock_doc.output.assert_called_once_with("test.pdf")


@patch("src.tp1.utils.report.pygal.Bar")
def test_generate_graph(MockBar):
    mock_bar = MagicMock()
    MockBar.return_value = mock_bar

    report = Report(MagicMock(), "test.pdf", {"protocols": {"TCP": 5}})
    report.generate("graph")

    mock_bar.add.assert_called_once_with("TCP", 5)
    mock_bar.render_to_file.assert_called_once_with("graph.svg")


def test_generate_array():
    report = Report(
        MagicMock(),
        "test.pdf",
        {"flag": "ESGI{TEST}", "attacks": [{"type": "arp_spoofing", "attacker": "192.168.1.1"}]},
    )

    report.generate("array")

    assert "ESGI{TEST}" in report.array
    assert "arp_spoofing" in report.array


def test_generate_invalid_param():
    report = Report(MagicMock(), "test.pdf", {})
    report.generate("invalid")
    assert report.array == ""
