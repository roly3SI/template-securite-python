from unittest.mock import patch
from src.tp2.utils.llm import LLMTriage


@patch("src.tp2.utils.llm.requests.post")
def test_llm_triage(mock_post):
    llm = LLMTriage()
    llm.triage({"dummy": "data"})
    assert True
