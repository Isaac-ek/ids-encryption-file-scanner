# Source consolidation

The maintained application is in `Isaac-ek/ids-encryption-file-scanner`. The website-checking engine is integrated under `web_scanner/`; its original license is retained in `web_scanner/LICENSE`.

The website source was imported from `Isaac-ek/Vulnerability-Scanner` at commit `41f4c58`. Its complete original branch history is preserved in this repository under `archive/vulnerability-scanner/branches/main`. The final retirement branch is also preserved under `archive/vulnerability-scanner/branches/codex/retire-standalone-scanner`. These tags retain the source history independently of the redundant repository.

The React/FastAPI rewrite supplied the integration starting point. Its earlier uncommitted local source is preserved in the local branch `codex/local-rewrite-before-cleanup`. Local keys, encrypted files, logs, account records and environment configuration were preserved during cleanup and are not published in Git.

Consolidation is based on remote main at `ef472ee`. Its feature-engineering and rare-class training sources remain under `legacy/`. The active `models2` bundle is the user's selected local XGBoost model, scaler and feature-column triple, preserved byte for byte without retraining. The earlier Random Forest/specialist binaries remain recoverable from Git history at `ef472ee`; incompatible specialist artifacts are not mixed into the active bundle.

One permanent local checkout, `Downloads/scanner`, runs the combined app. Duplicate checkouts, obsolete entrypoints, generated test artifacts and redundant environments were removed after verification.
