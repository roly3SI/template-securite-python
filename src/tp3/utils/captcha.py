import requests
from io import BytesIO
from PIL import Image
import pytesseract

class Captcha:
    def __init__(self, url,req_session=None):
        self.url = url
        self.image = ""
        self.value = ""
        self.req_session = req_session or requests.Session()

    def solve(self):
        """
        Fonction permettant la résolution du captcha.
        """
        img = Image.open(BytesIO(self.image)).convert('L')
        img = img.point(lambda p: p > 128 and 255)
        text = pytesseract.image_to_string(
            img,
            config='--psm 8 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        )
        self.value = text.strip()

    def capture(self):
        """
        Fonction permettant la capture du captcha.
        """
        response = self.req_session.get(f"{self.url}/captcha.png")
        self.image = response.content

    def get_value(self):
        """
        Fonction retournant la valeur du captcha
        """
        return self.value
