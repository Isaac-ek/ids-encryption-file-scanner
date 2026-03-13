import os, sys
import pytest
from unittest.mock import patch, MagicMock

# ensure project root is on PYTHONPATH so tests can import core package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core import scanner


def test_analyze_headers_missing():
    # simulate response without headers
    class Resp:
        headers = {}

    with patch('core.scanner.fetch', return_value=Resp()):
        scanner.analyze_headers('http://example.com')


def test_xss_no_forms():
    class Resp:
        text = "<html><body>No forms here</body></html>"

    with patch('core.scanner.fetch', return_value=Resp()):
        scanner.test_xss('http://example.com')


def test_xss_reflected():
    # create a fake form page and respond to submission with payload echoed
    initial = MagicMock()
    initial.text = '<form action="/submit" method="get"><input name="q" /></form>'

    def fake_fetch(url, **kwargs):
        # when fetching action with params, echo payload
        class R:
            text = kwargs.get('params', {}).get('q', '')
        return R()

    with patch('core.scanner.fetch', side_effect=[initial, fake_fetch('/submit', params={'q':'<script>alert(\'x\')</script>'})]):
        scanner.test_xss('http://example.com')
