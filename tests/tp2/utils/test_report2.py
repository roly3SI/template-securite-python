import json
from src.tp2.utils.report import Report

def test_generate_json(tmp_path):
    fake_result = {
        "sha256": "123456",
        "score": 10,
        "flag": "ESGI{test_flag}"
    }

    report = Report(fake_result)
    out_file = tmp_path / "out.json"

    report.generate_json(str(out_file))

    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["score"] == 10
    assert content["flag"] == "ESGI{test_flag}"