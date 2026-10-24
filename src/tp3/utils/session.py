import requests
import re
from src.tp3.utils.captcha import Captcha


class Session:
    """
    Class representing a session to solve a captcha and submit a flag.

    Attributes:
        url (str): The URL of the captcha.
        captcha_value (str): The value of the solved captcha.
        flag_value (str): The value of the flag to submit.
        valid_flag (str): The valid flag obtained after processing the response.
    """

    def __init__(self, url):
        """
        Initializes a new session with the given URL.

        Args:
            url (str): The URL of the captcha.
        """
        self.url = url
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.req_session = requests.Session()

        self.tcp_host = ""
        self.tcp_port = 0
        self.tcp_key = b""
        self.response = None

    def prepare_request(self):
        """
        Prepares the request for sending by capturing and solving the captcha.
        """
        captcha = Captcha(self.url, self.req_session)
        captcha.capture()
        captcha.solve()
        self.captcha_value = captcha.get_value()

    def submit_request(self):
        """
        Sends the flag and captcha.
        """
        data = {"captcha": self.captcha_value}
        self.response = self.req_session.post(self.url, data=data)

    def process_response(self):
        """
        Processes the response.
        """
        html_content = self.response.text

        flag_match = re.search(r'ESGI\{.*?\}', html_content)
        if flag_match:
            self.valid_flag = flag_match.group(0)

        host_match = re.search(r'Host:\s*([a-zA-Z0-9.-]+)', html_content, re.IGNORECASE)
        port_match = re.search(r'Port:\s*(\d+)', html_content, re.IGNORECASE)
        key_match = re.search(r'Key:\s*([a-zA-Z0-9]+)', html_content, re.IGNORECASE)

        if host_match and port_match and key_match:
            self.tcp_host = host_match.group(1)
            self.tcp_port = int(port_match.group(1))
            self.tcp_key = key_match.group(1).encode('utf-8')

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
