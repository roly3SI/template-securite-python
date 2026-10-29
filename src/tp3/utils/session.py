import requests
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
        self.req_session.get(self.url)
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
        try:
            data = self.response.json()

            self.valid_flag = data.get("flag1", "")
            self.tcp_host = data.get("host", "")
            self.tcp_port = int(data.get("port", 0))

            key_hex = data.get("key", "")
            if key_hex:
                self.tcp_key = bytes.fromhex(key_hex)

        except requests.exceptions.JSONDecodeError:
            pass

    def get_flag(self):
        """
        Returns the valid flag.

        Returns:
            str: The valid flag.
        """
        return self.valid_flag
