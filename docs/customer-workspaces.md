# Customer workspace isolation

Every customer has a separate workspace. A signed-in account is bound to one workspace; the UI does not accept a client-selected workspace ID. Names, events, rules, reports and audit entries are scoped through the authenticated SQLAlchemy session. Cross-workspace writes are rejected. Usernames remain globally unique; customers should use namespaced usernames when necessary.

Files, encryption keys and operation locks use the authenticated workspace's private storage root. The original installation remains workspace 1 with its existing files, key format and audit chain. Additional customers use `.runtime/workspaces/<id>/` with separate AES-256-GCM keys protected by filesystem permissions. An application host operator can still access the database and local keys: this is application isolation, not isolation from a compromised host or a KMS deployment.

Each workspace has its own audit chain. New customer hashes bind the workspace ID. Sensor tokens map to one workspace and only their hashes are stored; the original `WORKER_TOKEN` environment credential remains restricted to workspace 1. WebSocket recipients are registered to their account's workspace. Password changes revoke sessions and worker rotation invalidates the previous workspace token.

## Provision a customer

Use an operator terminal configured for the intended database and data root. Supply secrets through your secret store or environment, not source files or shell history:

```sh
export BOOTSTRAP_USERNAME='acme-owner'
export BOOTSTRAP_WORKSPACE='acme'
export BOOTSTRAP_WORKSPACE_NAME='Acme security'
# Supply BOOTSTRAP_PASSWORD securely (at least 12 characters).
# Optional: BOOTSTRAP_SCAN_ALLOWED_HOSTS contains explicitly authorized hostnames.
.venv/bin/python scripts/create_admin.py
```

That administrator can create team members through People & access. Administrators cannot provision other customer workspaces. Public signup remains disabled.

To provision or rotate the customer's sensor credential:

```sh
.venv/bin/python scripts/rotate_worker_token.py --workspace acme
```

The token is shown once to the operator. Put it in that sensor's `WORKER_TOKEN` secret. It must not be copied into frontend code. This command does not change the legacy workspace-1 environment token.

Website target allowlists are workspace-specific. Additional workspaces default to no allowed targets. Workspace 1 retains its existing `SCAN_ALLOWED_HOSTS` environment configuration. Redirects are checked against the same customer policy; private/reserved targets stay blocked. `SCAN_ALLOW_LOCALHOST` remains a local test-fixture setting only.

## Migration and deployment boundary

Back up the database, encrypted files and matching keys before upgrading. Startup and `scripts/init_db.py` add workspace columns, indexes and the initial workspace without dropping data or moving files. Existing records are assigned to workspace 1. Existing browser sessions must sign in again because tokens now include the workspace binding. Never assign old customers' records to a new customer by changing only an account's workspace field.

Tests cover cross-customer CRUD, filtered lists, report histories, exports, aggregate totals, distinct file contents and keys, ingestion credentials, WebSocket fan-out and audit chain tampering. An additional browser test signs into two customer accounts and verifies separate file/account views. Migration is tested on SQLite; PostgreSQL migration syntax and sequence handling are included but require deployment-specific verification.

Run one API worker while WebSocket delivery is process-local. Production still needs HTTPS, managed secret storage, backup/restore exercises, monitoring, login abuse controls and an independent security review before handling customer-sensitive data. These changes are not a production certification.

Workspace administrators can manage exact approved hostnames under **Website checks → Approved websites**. Paste website URLs or hostnames, confirm permission, and save before checking a target. Subdomains and redirected hosts each need approval. Every change is recorded in the workspace audit chain. Members can read the scope but cannot change it. Private-address and DNS validation still apply after approval.
