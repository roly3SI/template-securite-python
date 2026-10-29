from unittest.mock import MagicMock, patch

import requests

from src.tp3.utils.captcha import Captcha


def test_captcha_init():
    # Given
    url = "http://example.com/captcha"
    req_session = requests.Session()

    # When
    captcha = Captcha(url, req_session)

    # Then
    assert captcha.url == url
    assert captcha.value == ""


@patch("src.tp3.utils.captcha.pytesseract.image_to_string")
@patch("src.tp3.utils.captcha.Image.open")
def test_solve(mock_image_open, mock_image_to_string):
    # Given
    captcha = Captcha("http://example.com/captcha", requests.Session())
    captcha.image = b"fake_image_data"
    mock_image_to_string.return_value = "MOCKED_CAPTCHA\n"

    # When
    captcha.solve()

    # Then
    assert captcha.get_value() == "MOCKED_CAPTCHA"


@patch.object(requests.Session, "get")
def test_capture(mock_get):
    # Given
    req_session = requests.Session()
    captcha = Captcha("http://example.com/captcha", req_session)
    mock_response = MagicMock()
    mock_response.content = b"fake_image_data"
    mock_get.return_value = mock_response

    # When
    captcha.capture()

    # Then
    # This is a minimal test since the method doesn't do anything yet
    assert captcha.image is not None


def test_get_value():
    # Given
    captcha = Captcha("http://example.com/captcha", requests.Session())
    captcha.value = "TEST123"

    # When
    result = captcha.get_value()

    # Then
    assert result == "TEST123"
