"""Simple web UI for the vulnerability scanner.

Run with:
    python web.py

Or in Docker, set the container entrypoint to run this file.
"""

import re
import io
import contextlib

from flask import Flask, request, render_template, jsonify, Response, stream_with_context

from core import scanner

app = Flask(__name__)

ANSI_ESCAPE_RE = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from scanner output."""
    return ANSI_ESCAPE_RE.sub("", text)


def run_scan(
    url: str,
    host: str | None = None,
    xss: bool = False,
    keywords: list[str] | None = None,
):
    """Run all scanners and return a Reporter with collected entries."""
    reporter = scanner.Reporter()

    scanner.analyze_headers(url, reporter)
    scanner.check_cors(url, reporter)
    scanner.check_open_redirect(url, reporter)
    scanner.scan_ports(host or url, reporter)
    scanner.check_ssl(host or url, reporter)
    scanner.scan_common_paths(url, reporter)
    scanner.scan_sensitive_strings(url, reporter, extra_keywords=keywords)
    scanner.scan_mixed_content(url, reporter)
    if xss:
        scanner.test_xss(url, reporter)

    return reporter


def stream_scan(
    url: str,
    host: str | None = None,
    xss: bool = False,
    keywords: list[str] | None = None,
):
    """Run scan and stream output progressively."""
    reporter = scanner.Reporter()

    def flush():
        nonlocal last
        while last < len(reporter.entries):
            entry = reporter.entries[last]
            last += 1
            yield strip_ansi(f"[{entry['level'].upper()}] {entry['message']}\n")

    last = 0
    yield from flush()

    scanner.analyze_headers(url, reporter)
    yield from flush()

    scanner.scan_ports(host or url, reporter)
    yield from flush()

    scanner.check_ssl(host or url, reporter)
    yield from flush()

    scanner.check_cors(url, reporter)
    yield from flush()

    scanner.check_open_redirect(url, reporter)
    yield from flush()

    scanner.scan_common_paths(url, reporter)
    yield from flush()

    scanner.scan_sensitive_strings(url, reporter, extra_keywords=keywords)
    yield from flush()

    scanner.scan_mixed_content(url, reporter)
    yield from flush()

    if xss:
        scanner.test_xss(url, reporter)
        yield from flush()


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", url=None, host=None, xss=False)


@app.route("/scan", methods=["POST"])
def scan():
    url = request.form.get("url", "")
    host = request.form.get("host")
    xss = bool(request.form.get("xss"))
    keywords = request.form.get("keywords", "")

    if not url:
        return "Missing `url` parameter", 400

    keyword_list = [k.strip() for k in keywords.split(",") if k.strip()]

    reporter = run_scan(url, host, xss, keyword_list)
    logs = reporter.as_text()
    return render_template(
        "index.html",
        url=url,
        host=host,
        xss=xss,
        keywords=keywords,
        logs=logs,
    )


@app.route("/api/report", methods=["POST"])
def api_report():
    payload = request.get_json(force=True, silent=True) or request.form
    url = payload.get("url")
    host = payload.get("host")
    xss = bool(payload.get("xss"))
    keywords = payload.get("keywords")
    keyword_list = [k.strip() for k in (keywords or "").split(",") if k.strip()]

    if not url:
        return jsonify({"error": "Missing required field: url"}), 400

    reporter = run_scan(url, host, xss, keyword_list)
    return jsonify({"url": url, "host": host, "xss": xss, "entries": reporter.as_json()})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    payload = request.get_json(force=True, silent=True) or request.form
    url = payload.get("url")
    host = payload.get("host")
    xss = bool(payload.get("xss"))
    keywords = payload.get("keywords")
    keyword_list = [k.strip() for k in (keywords or "").split(",") if k.strip()]

    if not url:
        return jsonify({"error": "Missing required field: url"}), 400

    logs = run_scan(url, host, xss, keyword_list)
    return jsonify({"url": url, "host": host, "xss": xss, "logs": logs})


@app.route("/api/scan-stream", methods=["POST"])
def api_scan_stream():
    payload = request.get_json(force=True, silent=True) or request.form
    url = payload.get("url")
    host = payload.get("host")
    xss = bool(payload.get("xss"))
    keywords = payload.get("keywords")
    keyword_list = [k.strip() for k in (keywords or "").split(",") if k.strip()]

    if not url:
        return ("Missing required field: url", 400)

    return Response(
        stream_with_context(stream_scan(url, host, xss, keyword_list)),
        mimetype="text/plain; charset=utf-8",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=False)
