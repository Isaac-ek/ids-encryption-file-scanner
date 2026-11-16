"""Vulnerability detection routines."""

from urllib.parse import urljoin, urlparse
import ssl
import socket
import shutil
import re
from datetime import datetime
import nmap
from bs4 import BeautifulSoup

from .requester import fetch
from .reporter import Reporter


ADDITIONAL_SECURITY_HEADERS = [
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]


def _restricted_frame_ancestors(policy: str) -> bool:
    """Recognize parent allowlists, without claiming full CSP validation.

    Enforced policies intersect. Within one policy, the first duplicate
    directive wins. Report-only policies are deliberately never passed here.
    """
    host_source = re.compile(r"^(?:https?://)?(?:\*\.)?(?:[a-z0-9-]+\.)*[a-z0-9-]+(?::(?:[0-9]+|\*))?(?:/[^\s]*)?$", re.I)
    for item in policy.split(","):
        for directive in item.split(";"):
            tokens = directive.strip().split()
            if not tokens or tokens[0].lower() != "frame-ancestors":
                continue
            sources = tokens[1:]
            if sources and all(source.lower() in {"'none'", "'self'"} or host_source.fullmatch(source) for source in sources):
                return True
            break
    return False


PORTS = "21,22,23,25,80,443,3306,3389,8080"
COMMON_PATHS = [
    "admin",
    "login",
    "dashboard",
    "wp-login.php",
    ".env",
    "robots.txt",
    ".git/config",
    "config.php",
]


def analyze_headers(url: str, reporter: Reporter | None = None) -> None:
    reporter = reporter or Reporter()

    try:
        resp = fetch(url)
    except Exception as e:
        reporter.error(f"Error fetching headers for {url}: {e}")
        return

    headers = resp.headers
    is_document = not headers.get("Content-Type") or any(kind in headers.get("Content-Type", "").lower() for kind in ("text/html", "application/xhtml+xml"))
    if resp.status_code >= 400:
        reporter.info(f"HTTP {resp.status_code}: these observations describe the error response, not necessarily the application document.")
    if is_document:
        policy = headers.get("Content-Security-Policy", "")
        if policy:
            reporter.info("Found enforced Content-Security-Policy; directive effectiveness requires review.")
        else:
            reporter.warn("Missing enforced Content-Security-Policy on the HTML response.")
        if headers.get("Content-Security-Policy-Report-Only"):
            reporter.info("CSP Report-Only is present for monitoring; it does not enforce a policy.")
        if _restricted_frame_ancestors(policy):
            reporter.info("Framing is restricted by an enforced CSP frame-ancestors allowlist.")
        elif headers.get("X-Frame-Options", "").strip().upper() in {"DENY", "SAMEORIGIN"}:
            reporter.info("Framing is restricted by X-Frame-Options.")
        else:
            reporter.warn("No restricted enforced CSP frame-ancestors allowlist or valid X-Frame-Options found; review whether this page should allow embedding.")
    else:
        reporter.info("Document CSP and framing checks skipped for this non-HTML response.")

    if urlparse(resp.url).scheme == "https":
        if headers.get("Strict-Transport-Security"):
            reporter.info("Found header: Strict-Transport-Security")
        else:
            reporter.warn("Missing Strict-Transport-Security on the HTTPS response.")
    else:
        reporter.info("HSTS is only honored over HTTPS; it is not evaluated on this HTTP response.")

    for hdr in ADDITIONAL_SECURITY_HEADERS:
        if hdr not in headers:
            reporter.info(f"Missing optional header: {hdr}")
        else:
            reporter.info(f"Found optional header: {hdr}")


def scan_common_paths(url: str, reporter: Reporter | None = None) -> None:
    reporter = reporter or Reporter()
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    reporter.info(f"Checking common paths on {parsed.netloc}")

    for path in COMMON_PATHS:
        try:
            full = urljoin(base + "/", path)
            resp = fetch(full)
            if resp.status_code == 200:
                reporter.warn(f"Found accessible path: {full} (200)")
        except Exception:
            # keep scanning even if one path fails
            continue


def check_cors(url: str, reporter: Reporter | None = None) -> None:
    reporter = reporter or Reporter()

    try:
        resp = fetch(url)
    except Exception as e:
        reporter.error(f"Error fetching page for CORS check: {e}")
        return

    origin = resp.headers.get("Access-Control-Allow-Origin")
    creds = resp.headers.get("Access-Control-Allow-Credentials")
    if origin:
        reporter.info(f"Access-Control-Allow-Origin: {origin}")
        if origin.strip() == "*" and creds and creds.lower() == "true":
            reporter.warn("Wildcard CORS origin with credentials is rejected by browsers; review the intended cross-origin access configuration.")
    else:
        reporter.info("No Access-Control-Allow-Origin header detected.")


def check_open_redirect(url: str, reporter: Reporter | None = None) -> None:
    reporter = reporter or Reporter()
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    target = "https://example.com/"
    params = ["next", "redirect", "url", "dest", "return"]

    for p in params:
        try:
            probe = f"{url}?{p}={target}"
            resp = fetch(probe, allow_redirects=False)
            location = resp.headers.get("Location")
            if resp.status_code in (301, 302, 303, 307, 308) and location:
                if target in location:
                    reporter.warn(f"Possible open redirect via parameter '{p}' (Location: {location})")
                    return
        except Exception:
            continue

    reporter.info("No obvious open redirect parameters found.")


def scan_sensitive_strings(
    url: str,
    reporter: Reporter | None = None,
    extra_keywords: list[str] | None = None,
) -> None:
    reporter = reporter or Reporter()

    try:
        resp = fetch(url)
    except Exception as e:
        reporter.error(f"Error fetching page for sensitive string scan: {e}")
        return

    text = resp.text.lower()
    patterns = [
        "password",
        "pass=",
        "api_key",
        "api-key",
        "apikey",
        "client_secret",
        "token",
        "aws_access_key",
        "ssh-rsa",
        "private_key",
    ]

    if extra_keywords:
        patterns += [k.strip().lower() for k in extra_keywords if k.strip()]

    found = set(p for p in patterns if p in text)
    if found:
        reporter.warn(f"Found potentially sensitive terms in response: {', '.join(sorted(found))}")
    else:
        reporter.info("No obvious sensitive keywords found in response.")


def scan_mixed_content(url: str, reporter: Reporter | None = None) -> None:
    reporter = reporter or Reporter()

    try:
        resp = fetch(url)
    except Exception as e:
        reporter.error(f"Error fetching page for mixed-content check: {e}")
        return

    parsed = urlparse(url)
    if parsed.scheme != "https":
        reporter.info("Mixed-content checks only run on HTTPS pages.")
        return

    soup = BeautifulSoup(resp.text, "html.parser")
    insecure = []

    for tag in soup.find_all(["script", "img", "iframe", "link", "audio", "video"]):
        attr = "src" if tag.has_attr("src") else "href" if tag.has_attr("href") else None
        if not attr:
            continue
        val = tag.get(attr, "")
        if val.startswith("http://"):
            insecure.append(val)

    if insecure:
        reporter.warn(f"Found {len(insecure)} insecure (http://) resource(s) on page")
        for res in insecure[:10]:
            reporter.warn(f" - {res}")
        if len(insecure) > 10:
            reporter.warn(f" - ...and {len(insecure) - 10} more")
    else:
        reporter.info("No mixed-content (http://) resources detected")


def scan_ports(target: str, reporter: Reporter | None = None) -> None:
    """Scan ports either using nmap (if available) or a simple socket check.

    This avoids failing entirely if the nmap binary isn't installed.
    """

    reporter = reporter or Reporter()

    if target.startswith("http"):
        target = urlparse(target).hostname

    reporter.info(f"Scanning ports on {target}")

    # Primary: use nmap if installed, otherwise fall back to a basic socket scan.
    if shutil.which("nmap"):
        try:
            nm = nmap.PortScanner()
            nm.scan(target, PORTS)
            if target not in nm.all_hosts():
                reporter.error("No hosts found during scan")
                return

            hostinfo = nm[target]
            for proto in hostinfo.all_protocols():
                lport = hostinfo[proto].keys()
                for port in sorted(lport):
                    state = hostinfo[proto][port]["state"]
                    service = hostinfo[proto][port].get("name", "")
                    reporter.warn(f"Port {port}/{proto} {state} {service}")
            return
        except Exception as e:
            reporter.info(
                "nmap scan failed; falling back to a basic socket port scan."
            )
            reporter.info(f"(nmap error: {e})")
    else:
        reporter.info(
            "nmap not found in PATH; using a basic socket port scan instead."
        )

    # Fallback: try connecting to each port with a socket
    for port in map(int, PORTS.split(",")):
        try:
            with socket.create_connection((target, port), timeout=1):
                reporter.warn(f"Port {port}/tcp open")
        except Exception:
            pass


def check_ssl(target: str, reporter: Reporter | None = None) -> None:
    reporter = reporter or Reporter()

    if target.startswith("http"):
        target = urlparse(target).hostname

    reporter.info(f"Checking SSL/TLS for {target}")
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=target) as s:
            s.settimeout(5)
            s.connect((target, 443))
            cert = s.getpeercert()
            proto = s.version()
    except Exception as e:
        reporter.error(f"SSL connection error: {e}")
        return

    reporter.info(f"Protocol: {proto}")

    # Warn if the server uses an old TLS version.
    if proto in ("TLSv1", "TLSv1.1"):
        reporter.warn("Server is using an outdated TLS version (TLS1.0/1.1).")

    not_after = cert.get("notAfter")
    if not_after:
        exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        if exp < datetime.utcnow():
            reporter.error(f"Certificate expired on {exp}")
        else:
            reporter.info(f"Certificate valid until {exp}")


def test_xss(url: str, reporter: Reporter | None = None) -> None:
    """Basic XSS check: look for forms and inject a harmless payload."""
    reporter = reporter or Reporter()

    try:
        resp = fetch(url)
    except Exception as e:
        reporter.error(f"Error fetching page for XSS: {e}")
        return

    soup = BeautifulSoup(resp.text, "html.parser")
    forms = soup.find_all("form")
    if not forms:
        reporter.info("No forms found for XSS testing")
        return

    payload = "<script>alert('x')</script>"
    for form in forms[:5]:
        action = urljoin(url, form.get("action") or url)
        method = form.get("method", "get").lower()
        inputs = {inp.get('name'): payload for inp in form.find_all('input') if inp.get('name')}
        reporter.info(f"Testing form {action} with {method}")
        try:
            if method != 'get':
                reporter.info('Skipped non-GET form; this check does not submit state-changing forms')
                continue
            r = fetch(action, params=inputs)
            if payload in r.text:
                reporter.warn(f"Possible reflected XSS at {action}")
        except Exception:
            reporter.error(f"Error submitting form at {action}")
