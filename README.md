# IDS Encryption File Scanner

Flask-based security dashboard with user management, file scanning, AES encryption/decryption workflows, threat logs, and IDS model metrics.

## Features
- User authentication with Flask-Login
- Threat dashboard and audit log views
- File scanning with heuristic checks and optional ClamAV support
- File encryption and decryption workflows
- IDS metrics view backed by trained model artifacts

## Setup

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Train or provide the IDS model artifacts:

```bash
python train_ids.py
```

This generates the files expected under `models2/`.

3. Run the app:

```bash
python app.py
```

4. Open the app:

Visit [http://localhost:8080](http://localhost:8080).

## First Login

This project does not ship with default credentials. On a fresh setup, create the first admin account from the signup flow.

## Optional Services

- `clamscan` improves file scanning results when ClamAV is installed.
- Live IDS monitoring depends on Scapy support, the trained model files, and access to the selected network interface.
