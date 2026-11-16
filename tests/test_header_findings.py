from types import SimpleNamespace
from requests.structures import CaseInsensitiveDict
import pytest
from web_scanner import scanner
from web_scanner.reporter import Reporter


def analyze(monkeypatch, headers, url="https://owned.example/", status=200):
    response = SimpleNamespace(headers=CaseInsensitiveDict(headers),url=url,status_code=status)
    monkeypatch.setattr(scanner,"fetch",lambda *a,**k:response)
    report=Reporter();scanner.analyze_headers(url,report)
    return report.entries


def messages(entries, level=None):
    return " ".join(item["message"] for item in entries if level is None or item["level"]==level)


def test_report_only_is_optional_and_obsolete_expect_ct_is_not_recommended(monkeypatch):
    entries=analyze(monkeypatch,{"content-type":"text/html","content-security-policy":"default-src 'self'; frame-ancestors 'none'","strict-transport-security":"max-age=63072000","x-content-type-options":"nosniff"})
    assert not messages(entries,"warn")
    assert "Report-Only" not in messages(entries) and "Expect-CT" not in messages(entries)


def test_report_only_policy_does_not_replace_enforcement_or_restrict_framing(monkeypatch):
    entries=analyze(monkeypatch,{"Content-Type":"text/html","Content-Security-Policy-Report-Only":"frame-ancestors 'none'"})
    assert "Missing enforced Content-Security-Policy" in messages(entries,"warn")
    assert "review whether this page should allow embedding" in messages(entries,"warn")
    assert "does not enforce" in messages(entries,"info")


@pytest.mark.parametrize("policy",["frame-ancestors 'none'", "default-src 'self'; FRAME-ANCESTORS 'self' https://portal.example", "frame-ancestors https://*.example.com:443", "frame-ancestors * , frame-ancestors 'none'"])
def test_enforced_parent_allowlist_does_not_require_legacy_x_frame_options(monkeypatch,policy):
    entries=analyze(monkeypatch,{"Content-Security-Policy":policy,"Strict-Transport-Security":"max-age=300"})
    assert not messages(entries,"warn")
    assert "Framing is restricted" in messages(entries,"info")


@pytest.mark.parametrize("policy",["default-src 'self'", "frame-ancestors *", "frame-ancestors https:", "frame-ancestors", "frame-ancestors *; frame-ancestors 'none'", "frame-ancestors https://*"])
def test_absent_empty_or_open_parent_policy_still_needs_review(monkeypatch,policy):
    entries=analyze(monkeypatch,{"Content-Security-Policy":policy})
    assert "review whether this page should allow embedding" in messages(entries,"warn")


@pytest.mark.parametrize("value",["DENY","sameorigin"])
def test_valid_x_frame_options_remains_a_supported_fallback(monkeypatch,value):
    entries=analyze(monkeypatch,{"Content-Security-Policy":"default-src 'self'","Strict-Transport-Security":"max-age=300","X-Frame-Options":value})
    assert not messages(entries,"warn")


def test_http_hsts_and_non_html_document_policies_are_not_missing_header_warnings(monkeypatch):
    entries=analyze(monkeypatch,{"Content-Type":"application/json"},url="http://owned.example/api")
    assert not messages(entries,"warn")
    assert "non-HTML" in messages(entries) and "not evaluated" in messages(entries)


def test_error_response_is_identified_and_cors_does_not_claim_browsers_allow_wildcard_credentials(monkeypatch):
    headers={"Content-Type":"text/html","Access-Control-Allow-Origin":"*","Access-Control-Allow-Credentials":"true"}
    entries=analyze(monkeypatch,headers,status=404)
    assert "error response" in messages(entries,"info")
    reporter=Reporter();scanner.check_cors("https://owned.example",reporter)
    assert "rejected by browsers" in messages(reporter.entries,"warn")
