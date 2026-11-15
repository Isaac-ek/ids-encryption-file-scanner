# Combined workspace feature coverage

The consolidation keeps the trained intrusion detector and imports the website-checking engine into one authenticated app. The interface restores controls from the original scanner alongside the existing API functionality.

| Capability | Current workflow | Scope and limits |
| --- | --- | --- |
| Accounts | Administrators create accounts, assign member/admin access, edit names, reset passwords and remove accounts. Members change their own password. | No public registration or default production password. Password changes revoke older sessions; administrators cannot delete or demote their own account. Initial credentials are shown for private sharing after creation. |
| Event review | Filter by date, class, source, destination and origin; page through results; export CSV or JSON. | Export includes at most 10,000 matching records. Sensor events, simulations and model replays retain separate origin labels. |
| Packet capture | Run `scripts/run_monitor.py --allow-experimental-features` on an authorized host interface. | Capture needs host permissions and configuration. Opening the dashboard does not start capture. Simulation retains actual classifier predictions. |
| Model inspection | Load one of five labelled connection examples, inspect its features, run inference and save the result as a replay. | Examples come from NSL-KDD test records. Their expected classes are separate from predictions. No attack traffic is generated. |
| Model evidence | View model identity, matching offline evaluation, per-class precision/recall/F1/support and artifact metadata. | The preserved bundle is XGBoost. Offline results do not establish effectiveness on a live network; R2L and U2R recall remain weak. |
| File protection | Upload, preview, download, encrypt and restore; select multiple eligible files for encryption or recovery. | AES-256-GCM. Originals are removed only after durable encryption and audit. Recovery retains the encrypted backup. Bulk actions report partial failures. Existing backups are not silently overwritten. |
| File inspection | Check the EICAR test signature, review configured code patterns and invoke local ClamAV when installed. View saved reports. | Maximum 8 MB. Uploads are never executed and temporary contents are discarded. Pattern matches are review hints. Missing or failed antivirus produces a limited result, not a safety guarantee. ClamAV has a 30-second execution timeout. |
| Detection rules | Create, edit, enable/disable and delete stored rules. | These are stored detection configuration, not proof of an applied operating-system firewall rule. |
| Website checks | Authorized, explicitly allowed hosts; selectable bounded checks, saved findings and reports. | Administrator-only execution with target confirmation. Scope and redirect validation remain enforced. |
| Audit history | Filter by date, actor or action; inspect chain verification; export the displayed entries as JSON. | Latest 500 matching entries. Chain verification covers the stored history; it is not an externally immutable ledger. |
| Workspace overview | Real event, file and check totals, recent activity, event-source counts and last recorded sensor event. | WebSocket connection status describes the app event stream, not whether host capture is running. |

## Updating an existing installation

Run `python scripts/init_db.py` with the intended database and data-root configuration. This creates the additive `file_checks` table alongside any other missing tables without dropping existing tables. Existing deployments also need the event-origin migration in [migration.md](migration.md), when applicable.

Existing browser sessions must sign in again after this update because access tokens now bind to the account password state. A member password change issues a replacement token for that current session; other sessions are revoked.

Legacy account files and original encryption keys remain private local archives. They are not silently imported into the new workspace. Keep encrypted files with their corresponding keys.

## Verification

Backend coverage exercises account administration, role enforcement, password revocation, filtered exports, inspection outcomes, audit entries and temporary-upload cleanup. Browser coverage exercises member sign-in, administrative editing, rule editing, file inspection, actual recovered download contents, bulk actions, model replay, website checks and navigation at a 390-pixel viewport.

Each customer now has a separate workspace for accounts, files/keys, records, reports, audit chains, target policy and live delivery. See [customer workspace provisioning](customer-workspaces.md). Sensor-driven automatic encryption is disabled, and live classification remains experimental pending labelled capture validation.
