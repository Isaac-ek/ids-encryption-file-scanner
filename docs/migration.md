# Consolidation and migration

Primary destination: `Isaac-ek/ids-encryption-file-scanner`. The other repository remains intact as source history; this change does not delete a GitHub repository or local checkout.

The React/FastAPI rewrite supplies the shared shell, authentication, file controls and audit chain. The website engine is imported under `web_scanner/` and `scanner_utils/` to avoid name collisions. The old Flask templates/entrypoints, obsolete UI components, duplicated nginx frontend deployment and default-credential seeding path are removed from the combined tree. Training scripts, packet feature extraction and both classifier approaches are retained.

A fresh installation creates all tables. For an existing database from the local FastAPI rewrite, back it up, then apply this additive PostgreSQL change before using the new code:

```sql
ALTER TABLE threat_alerts ADD COLUMN IF NOT EXISTS origin VARCHAR NOT NULL DEFAULT 'sensor';
```

Run `python scripts/init_db.py` to create `scan_runs` (and any other missing tables). This does not drop existing tables. Use the appropriate migration tool for a non-PostgreSQL existing database. Original Flask YAML users and keys are not imported automatically; provision operator accounts intentionally and retain backups of old encrypted files and their matching key material. The new service uses its configured data root and never silently rewrites the original folders.

Keep `.runtime/keys` with the encrypted files during backups. Losing keys makes recovery impossible. Current storage keys are protected by filesystem permissions; this prototype is not a KMS/HSM deployment. Limit deployment access accordingly.

Existing audit entries retain their format. New scan/prediction/file operations append to the same chain. The website service uses one scan slot per API process and a 25-second request budget; run one API process for the default SQLite deployment. Multi-process deployments should add a shared job queue/rate-limit before increasing public throughput.
