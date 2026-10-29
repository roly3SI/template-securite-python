from unittest.mock import MagicMock, patch

from src.tp3.utils.session import Session


def test_session_init():
    # Given
    url = "http://example.com/captcha"

    # When
    session = Session(url)

    # Then
    assert session.url == url
    assert session.captcha_value == ""
    assert session.flag_value == ""
    assert session.valid_flag == ""


@patch("src.tp3.utils.session.requests.Session.post")
def test_submit_request(mock_post):
    # Given
    session = Session("http://example.com/captcha")
    session.captcha_value = "TEST_CAPTCHA"

    # When
    session.submit_request()

    # Then
    # This is a minimal test since the method doesn't do anything yet
    mock_post.assert_called_once()
    assert session.response is not None


def test_process_response():
    # Given
    session = Session("http://example.com/captcha")
    session.response = MagicMock()
    session.response.json.return_value = {
        "flag1": "ESGI{mock_flag}",
        "host": "127.0.0.1",
        "port": 9090,
        "key": "deadbeef",
    }
    # When
    session.process_response()

    # Then
    # This is a minimal test since the method doesn't do anything yet
    assert session.valid_flag == "ESGI{mock_flag}"
    assert session.tcp_host == "127.0.0.1"
    assert session.tcp_port == 9090
    assert session.tcp_key == bytes.fromhex("deadbeef")


def test_get_flag():
    # Given
    session = Session("http://example.com/captcha")
    session.valid_flag = "FLAG123"

    # When
    result = session.get_flag()

    # Then
    assert result == "FLAG123"
