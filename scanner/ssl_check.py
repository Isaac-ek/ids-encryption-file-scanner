import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime
from colorama import Fore, Style


def check_ssl(target: str) -> None:
    # Accept urls or host names
    if target.startswith("http"):
        target = urlparse(target).hostname

    print(f"[+] Checking SSL/TLS for {target}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(5)
            s.connect((target, 443))
            cert = s.getpeercert()
            proto = s.version()
    except Exception as e:
        print(f"[!] SSL connection error: {e}")
        return

    # protocol
    print(f"{Fore.GREEN}[+] Protocol: {proto}{Style.RESET_ALL}")

    # check expiration
    not_after = cert.get("notAfter")
    if not_after:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        if exp < datetime.utcnow():
            print(f"{Fore.RED}[!] Certificate expired on {exp}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[+] Certificate valid until {exp}{Style.RESET_ALL}")
