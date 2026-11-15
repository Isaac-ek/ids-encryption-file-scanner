# Source consolidation

Primary repository: Isaac-ek/ids-encryption-file-scanner.
Website scanning engine imported from Isaac-ek/Vulnerability-Scanner (local source commit 41f4c58).
The existing uncommitted React/FastAPI IDS rewrite was preserved as the integration starting point.
Original working folders, private keys, .env files, logs, user files and databases were not modified or copied.
The existing XGBoost model/scaler/feature-column bundle was copied locally for verification and is not retrained.

Remote main was ahead of the local checkout at ef472ee. The consolidation is based on that commit, and retains its feature-engineering and rare-class training sources under legacy/. The active models2 bundle intentionally uses the user's local XGBoost model, matching the user's explicit choice. The earlier Random Forest/specialist binary bundle remains recoverable from Git commit ef472ee; incompatible specialist artifacts are not mixed into the XGBoost bundle. No model was retrained.

The imported website engine retains its original license in `web_scanner/LICENSE`. The permanent local combined checkout is `/Users/user/Downloads/scanner`; redundant source copies and generated environments may be removed after migration while private data stays local.
