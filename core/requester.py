"""HTTP request helper that mimics a browser."""

import requests
from requests.exceptions import RequestException
from urllib.parse import urlparse


DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; vuln-scanner/1.0)"
}


def fetch(url: str, **kwargs) -> requests.Response:
    """Perform a GET request with default headers."""
    headers = kwargs.pop("headers", {})
    merged = {**DEFAULT_HEADERS, **headers}
    try:
        return requests.get(url, headers=merged, timeout=10, **kwargs)
    except RequestException as e:
        raise
