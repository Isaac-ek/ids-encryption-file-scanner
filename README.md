# SecureStream

One authenticated security workspace combining the trained intrusion detector from `ids-encryption-file-scanner` with the website-checking engine from `Vulnerability-Scanner`.

- **Events:** inspect persisted sensor events and run supplied connection features through the existing trained model. Replays are labelled `model-replay` and never presented as live capture.
- **Website checks:** run scoped HTTP/TLS/header, CORS, redirect, keyword, mixed-content and optional common-path/TCP/reflected-GET checks. Reports persist and link to the shared audit history.
- **Files:** upload, preview, encrypt and restore files using AES-256-GCM. Restores return SHA-256 and retain the encrypted backup.
- **Audit:** verify the stored hash chain and inspect user actions. A valid chain is not an externally signed or immutable ledger.

The current bundled classifier is **XGBoost**. Its model, scaler and feature-column artifacts are preserved, not retrained. The Random Forest and XGBoost training sources remain available. The interface reads model identity from the loaded object and only shows an evaluation whose model hash matches.

## Run locally

Use Python 3.12 and Node 22+. The scikit-learn and XGBoost versions match the preserved serialized bundle. From the repository root:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
npm ci --prefix frontend
npm run build --prefix frontend
export JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export WORKER_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
export BOOTSTRAP_PASSWORD='choose-a-strong-local-password'
.venv/bin/python scripts/create_admin.py
.venv/bin/uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. The same service serves the React build, HTTP API and authenticated alert WebSocket. Data and private keys live in ignored `.runtime/` by default. The secret variables must persist across restarts; supply them through your deployment secret store. The app does not load a `.env` file implicitly.

Website checks are disabled until `SCAN_ALLOWED_HOSTS` contains explicit hostnames you are authorized to assess. Authentication, administrator access and an authorization confirmation are required to start a check. Private/reserved/metadata IPs and out-of-scope redirects are blocked. `SCAN_ALLOW_LOCALHOST=true` is only for explicitly configured localhost test fixtures. The checks are bounded and are not a complete vulnerability assessment.

Development UI: `npm run dev --prefix frontend`. It proxies `/api` and WebSockets to localhost:8000 (override `VITE_API_TARGET` if needed).

## Existing IDS sensor

To capture your own authorized interface, run the sensor on the host with the required packet-capture permissions:

```sh
export API_URL=http://127.0.0.1:8000
.venv/bin/python scripts/run_monitor.py --interface en0
```

It uses the existing NSL-KDD feature extractor and saved detector. `--simulate` generates sample features, labels them as sensor simulation, and keeps actual model predictions. It does not force results to match the generated attack label. Automatic directory encryption is off by default and rejected in simulation mode. Live capture is not launched by opening the dashboard or running a website check. Validate the feature extraction against real traffic before interpreting offline benchmark performance as live-network effectiveness.

The worker API requires `X-Worker-Token`; browser bearer tokens cannot ingest sensor alerts. Use the same `WORKER_TOKEN` in API and sensor processes.

The optional legacy automatic-encryption setting creates backups and retains originals. The authenticated Files workflow is the supported way to remove a plaintext copy after a durable encrypted copy has been saved and audited.

## Verification

```sh
.venv/bin/pytest
npm run build --prefix frontend
# Install Chromium once with: npx --prefix frontend playwright install chromium
npm run test:e2e --prefix frontend
```

Tests use a fresh temporary database, temporary sample files and a local owned HTTP fixture. They check actual classifier inference, event persistence, file recovery and tamper rejection, traversal/symlink denial, worker/socket authentication, scan scope, saved results and audit entries. They do not scan public third-party systems.

## Deployment

`docker compose up --build` runs one container with one persistent volume. Set `JWT_SECRET` and `WORKER_TOKEN` first. Create an administrator with `docker compose exec -e BOOTSTRAP_PASSWORD=... security python scripts/create_admin.py`. Put HTTPS in front of the app. The container serves the web app; packet capture remains a separately configured host sensor. The old split Flask/Vercel and nginx UI entrypoints were removed.

A new installation uses SQLite with a single API process. PostgreSQL is supported via `DATABASE_URL`. Alert fan-out is currently process-local: run one API worker until a shared broadcast broker is configured. Existing FastAPI-rewrite databases need the additive migration described in `docs/migration.md`; original project folders/databases are not modified by this consolidation.
