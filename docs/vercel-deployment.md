# Persistent Vercel deployment

The Vercel app and portfolio are separate projects. The security app's production alias is `https://ids-encryption-file-scanner.vercel.app/`.

## Hosting contract

- `app.py` exports the existing FastAPI app at a supported Vercel entrypoint. `vercel.json` builds the React frontend and includes its assets and the preserved model artifacts.
- Linux x86-64 uses the CPU-only XGBoost 3.0.2 wheel. Other platforms retain the standard 3.0.2 distribution. This changes packaging, not the saved classifier or training results.
- A hosted customer deployment requires PostgreSQL and `FILE_STORAGE_BACKEND=database`. The app refuses ephemeral SQLite/file storage on Vercel.
- Accounts, roles, workspaces, rules, events, reports, audit chains, wrapped workspace keys, and encrypted file objects persist in PostgreSQL. `/tmp` holds temporary working data only. Files never depend on a function instance's filesystem.
- Both original-file records and encrypted backups are encrypted at rest with a per-workspace AES-256-GCM key. The workspace key is wrapped by a separate `KEY_ENCRYPTION_KEY` deployment secret. Authentication binds stored ciphertext to its workspace, kind, and filename.
- Small-file storage is intentionally bounded: a 3 MiB upload limit on Vercel (leaves room below its request-body limit), 100 MiB and 500 file records per workspace. Originals and retained backups both count. This is a small-file workspace, not an unlimited archive. A future large-file migration should use private object storage and direct uploads.
- PostgreSQL transaction locks coordinate file operations, audit writes, and website scans across instances. File replacements and their audit entry commit together. A failed replacement retains the original.
- Hosted event views refresh every 15 seconds while the page is visible. They read shared PostgreSQL state; they do not rely on the process-local WebSocket manager. Local/container deployments retain WebSocket updates.
- A serverless deployment does not capture packets from a customer's network. Run the separately configured sensor on an authorized host; its workspace token sends events to the authenticated worker endpoint. Live feature extraction remains experimental as described in `detector-validation.md`.
- Website assessments require an operator-configured, customer-specific hostname allowlist. ClamAV is optional and accurately reported as unavailable when it is absent; code-pattern checks are not a full antivirus engine.

## Environment and credentials

Set the following separately for preview and production, in the existing security project's Vercel settings:

| Key | Value |
| --- | --- |
| `DATABASE_URL` | Pooled PostgreSQL URL for a dedicated read/write runtime role |
| `FILE_STORAGE_BACKEND` | `database` |
| `JWT_SECRET` | Newly generated, stable signing secret (at least 32 characters) |
| `KEY_ENCRYPTION_KEY` | URL-safe base64 encoding of 32 random bytes |
| `SECURITY_DATA_DIR` | `/tmp/securestream` |

Use sensitive environment-variable storage for the database URL and both secrets. Never commit these values. Preview and production must have different databases and secrets. Back up the wrapping key separately from the database: losing or replacing it makes existing file keys unreadable. A later rotation needs an explicit rewrapping migration; changing an environment variable is not a rotation workflow.

The runtime role needs `SELECT`, `INSERT`, `UPDATE`, `DELETE`, schema usage, and sequence access on this app's tables. It does not need schema-creation or database-administration privileges. Run `scripts/init_db.py` using a direct connection and the migration owner before deploying. Vercel startup validates the schema without running DDL. Additive local migrations are serialized and idempotent.

Create the first hosted administrator with `scripts/create_admin.py`, using the migration owner/direct connection and generated `BOOTSTRAP_PASSWORD`. The HTTP signup endpoint stays closed. The hosted database starts independently of the local installation: local accounts, files, and keys are not copied automatically. Existing local files and their legacy keys remain untouched.

## Release checks

1. Run backend tests, frontend build, and browser flows.
2. Migrate and test an isolated preview database, including cross-process file operations and cross-customer denial.
3. Configure the matching preview environment, deploy the exact Git commit, and verify the real hosted interface and APIs.
4. Prepare the separate production database, create its operator account, and set production environment values.
5. Merge and deploy only after the preview succeeds. Verify the production hostname, static assets, login, authenticated upload/protect/restore, and audit verification. A build marked READY alone does not establish that the app works.

Do not promote a preview database containing test accounts or fixtures into production. Do not change deployment protection to make a check pass.
