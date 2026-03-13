#!/usr/bin/env python3
import argparse

from core import scanner
from utils import logger


def main():
    parser = argparse.ArgumentParser(description="Lightweight vulnerability scanner")
    parser.add_argument("--url", required=True, help="Target URL (include scheme)")
    parser.add_argument("--host", help="Target host for port/ssl scans (defaults to host from URL)")
    parser.add_argument("--xss", action="store_true", help="Perform basic XSS form tests")
    parser.add_argument("--dir", action="store_true", help="Check common directories (admin, login, etc.)")
    parser.add_argument("--mixed", action="store_true", help="Check for mixed-content (http:// resources)")
    args = parser.parse_args()

    target = args.url
    host = args.host

    logger.info(f"Scanning {target}")
    reporter = scanner.Reporter()

    scanner.analyze_headers(target, reporter)
    scanner.scan_ports(host or target, reporter)
    scanner.check_ssl(host or target, reporter)

    if args.dir:
        scanner.scan_common_paths(target, reporter)

    if args.mixed:
        scanner.scan_mixed_content(target, reporter)

    if args.xss:
        scanner.test_xss(target, reporter)

    print(reporter.as_text())


if __name__ == "__main__":
    main()
