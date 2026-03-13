<<<<<<< HEAD
# Vulnerability-Scanner
Automated Vulnerability Scanner — A lightweight Python web/CLI tool that inspects a target URL for common security issues (missing security headers, open ports, SSL/TLS problems, mixed content, open redirects, sensitive strings, etc.) and ships with a web UI (Flask) plus a production-ready WSGI entrypoint for easy deployment.
=======
# Automated Vulnerability Scanner

A lightweight, containerized web vulnerability scanner written in Python. This project demonstrates an automated reconnaissance tool capable of checking security headers, scanning ports, and verifying SSL/TLS health.

## Features

- **Header Analysis**: Detects missing critical security headers.
- **Port Scanning**: Uses `python-nmap` to identify open ports and suspicious services.
- **SSL/TLS Health**: Checks for outdated protocols and expired certificates.

## Getting Started

1. Clone the repository.
2. Create and activate a local virtual environment (recommended):

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3. Install dependencies:

    ```bash
    pip install -r requirements.txt
    ```

4. Run the scanner (CLI):

    ```bash
    python main.py --url https://example.com
    ```

### Web UI (optional)

Run a web frontend for public usage (development only):

```bash
python web.py
```

> ⚠️ This uses Flask’s built-in development server and is not recommended for production.

### Production (recommended)

Use a WSGI server like Gunicorn:

```bash
gunicorn -w 4 -b 0.0.0.0:8000 wsgi:application
```

Then open http://localhost:8000 in your browser.

### REST API

- Stream scan results: `POST /api/scan-stream` (JSON body: `{ "url": "https://example.com" }`)
- Get full report JSON: `POST /api/report` (same JSON body)

### Extra CLI scan modes

You can enable additional checks with CLI flags:

```bash
python main.py --url https://example.com --dir --mixed
```

Where:
- `--dir` checks common paths like `/admin`, `/login`, `/.env`
- `--mixed` checks for insecure `http://` resources on HTTPS pages

## Sample Output

```
[+] Scanning https://example.com
[!] Missing header: Content-Security-Policy
[+] Open ports: 22 (ssh)
[!] Certificate expired on 2023-01-01 (TLS1.2)
```

## Docker

Build the container:

```bash
docker build -t vuln-scanner .
```

Run it as a CLI scanner:

```bash
docker run --rm vuln-scanner --url https://example.com
```

Run it as a web service (listen on port 8000):

```bash
docker run --rm -p 8000:8000 vuln-scanner
```

## Vercel Deployment (GitHub → Vercel)

1. Push this repository to GitHub.
2. In Vercel, create a new project and select this GitHub repo.
3. Vercel will automatically use `vercel.json` to build `web.py` as a Python server.

Once deployed, your app will be available at the Vercel URL (e.g., `https://<project>.vercel.app`).

> Note: Vercel runs serverless functions; scans may take several seconds to complete.
>>>>>>> c7346e6 (Initial commit)
