"""Bounded HTTP checks, limited to configured targets and pinned validated addresses."""
import http.client
import ipaddress
import os
import socket
import ssl
import time
from contextvars import ContextVar
from types import SimpleNamespace
from urllib.parse import urlparse, urljoin, urlencode, urlunparse
from requests.structures import CaseInsensitiveDict

budget = ContextVar("scan_budget", default=None)

class TargetDenied(ValueError):
    pass

def resolve_target(url):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise TargetDenied("Use an http(s) URL without embedded credentials")
    host = parsed.hostname.lower().rstrip('.')
    allowed = {name.strip().lower().rstrip('.') for name in os.getenv("SCAN_ALLOWED_HOSTS", "").split(',') if name.strip()}
    if host not in allowed:
        raise TargetDenied("Target hostname is not in SCAN_ALLOWED_HOSTS")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    fixture_host = os.getenv("SCAN_ALLOW_LOCALHOST") == "true" and host in {"localhost", "127.0.0.1", "::1"}
    if port not in {80, 443} and not fixture_host:
        raise TargetDenied("Only standard HTTP/HTTPS ports are allowed")
    addresses = list(dict.fromkeys(info[4][0] for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    if not addresses: raise TargetDenied("Target did not resolve")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        local_fixture = fixture_host and ip.is_loopback
        if (not ip.is_global or ip.is_multicast) and not local_fixture:
            raise TargetDenied("Private, link-local, reserved and metadata addresses are not scan targets")
    return parsed, addresses[0], port

class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self.address = address
    def connect(self):
        sock = socket.create_connection((self.address, self.port), self.timeout)
        try: self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception: sock.close(); raise

def fetch(url, **kwargs):
    stop = budget.get()
    if stop is not None and time.monotonic() >= stop: raise TimeoutError("Scan time budget exhausted")
    params = kwargs.pop("params", None)
    if params:
        parsed = urlparse(url)
        url = urlunparse(parsed._replace(query=urlencode(params)))
    follow = kwargs.pop("allow_redirects", True)
    for _ in range(4):
        parsed, address, port = resolve_target(url)
        remaining = max(.1, min(3, stop - time.monotonic())) if stop else 3
        if parsed.scheme == "https": connection = PinnedHTTPS(parsed.hostname, port, address, remaining)
        else: connection = http.client.HTTPConnection(address, port, timeout=remaining)
        headers = {"Host": parsed.netloc, "User-Agent": "SecureStream-authorized-check/1.0", **kwargs.get("headers", {})}
        try:
            connection.request("GET", (parsed.path or '/') + ('?' + parsed.query if parsed.query else ''), headers=headers)
            response = connection.getresponse()
            data = response.read(1_000_001)
            if len(data) > 1_000_000: raise ValueError("Response exceeds 1 MB scan limit")
            result = SimpleNamespace(status_code=response.status, headers=CaseInsensitiveDict(response.getheaders()), text=data.decode('utf-8', errors='replace'), content=data, url=url)
        finally: connection.close()
        if follow and result.status_code in {301,302,303,307,308} and result.headers.get("Location"):
            url = urljoin(url, result.headers["Location"])
            continue  # The redirected destination is validated and pinned again.
        return result
    raise TargetDenied("Too many redirects")
