import json
from src.tp2.utils.report import Report
from unittest.mock import patch


def test_generate_json(tmp_path):
    fake_result = {"sha256": "123456", "score": 10, "flag": "ESGI{test_flag}"}

    report = Report(fake_result)
    out_file = tmp_path / "out.json"

    report.generate_json(str(out_file))

    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["score"] == 10
    assert content["flag"] == "ESGI{test_flag}"


@patch("src.tp2.utils.report.FPDF")
def test_generate_pdf(mock_fpdf):
    from src.tp2.utils.report import Report

    report = Report({})
    report.generate_pdf("out.pdf")
    assert True
