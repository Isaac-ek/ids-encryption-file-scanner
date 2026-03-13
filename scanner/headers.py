import requests
from urllib.parse import urlparse
from colorama import Fore, Style

REQUIRED_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
]


def check_headers(url: str) -> None:
    try:
        resp = requests.get(url, timeout=10)
    except Exception as e:
        print(f"[!] Error fetching headers for {url}: {e}")
        return

    headers = resp.headers
    for hdr in REQUIRED_HEADERS:
        if hdr not in headers:
            print(f"{Fore.RED}[!] Missing header: {hdr}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] Found header: {hdr}{Style.RESET_ALL}")
