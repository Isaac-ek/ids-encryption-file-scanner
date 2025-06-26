# aes_encryptor.py

import os
import json
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from getpass import getpass

# ── CONFIGURABLE PATHS ─────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
TARGET_DIR      = os.path.join(BASE_DIR, "sensitive_data")
QUARANTINE_DIR  = os.path.join(BASE_DIR, "quarantine")
KEYS_DIR        = os.path.join(BASE_DIR, "keys")
RSA_PRIV_PATH   = os.path.join(KEYS_DIR, "rsa_private.pem")
RSA_PUB_PATH    = os.path.join(KEYS_DIR, "rsa_public.pem")
AES_KEY_PATH    = os.path.join(KEYS_DIR, "aes_gcm_key.bin.enc")  # now encrypted
LOG_PATH        = os.path.join(QUARANTINE_DIR, "encryption_log.json")

# ── RSA KEY MANAGEMENT ─────────────────────────────────────────────────────────

def load_or_generate_rsa_keys():
    os.makedirs(KEYS_DIR, exist_ok=True)
    if not os.path.exists(RSA_PRIV_PATH) or not os.path.exists(RSA_PUB_PATH):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(RSA_PRIV_PATH, 'wb') as f:
            f.write(priv_pem)
        with open(RSA_PUB_PATH, 'wb') as f:
            f.write(pub_pem)
        return private_key, public_key
    else:
        with open(RSA_PRIV_PATH, 'rb') as f:
            priv_pem = f.read()
        private_key = serialization.load_pem_private_key(priv_pem, password=None, backend=default_backend())
        with open(RSA_PUB_PATH, 'rb') as f:
            pub_pem = f.read()
        public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
        return private_key, public_key

# ── AES KEY ENCRYPTION/DECRYPTION WITH RSA ─────────────────────────────────────

def encrypt_aes_key_with_rsa(aes_key: bytes, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_aes_key_with_rsa(enc_aes_key: bytes, private_key):
    return private_key.decrypt(
        enc_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# ── MODIFIED AES KEY LOADING ───────────────────────────────────────────────────

def load_or_generate_key():
    os.makedirs(KEYS_DIR, exist_ok=True)
    private_key, public_key = load_or_generate_rsa_keys()
    if os.path.exists(AES_KEY_PATH):
        with open(AES_KEY_PATH, "rb") as f:
            enc_aes_key = f.read()
        aes_key = decrypt_aes_key_with_rsa(enc_aes_key, private_key)
        if len(aes_key) != 32:
            raise ValueError(f"Decrypted AES key is {len(aes_key)} bytes; expected 32.")
        return aes_key
    else:
        aes_key = AESGCM.generate_key(bit_length=256)
        enc_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)
        with open(AES_KEY_PATH, "wb") as f:
            f.write(enc_aes_key)
        return aes_key

# ── UTILITY FUNCTIONS ───────────────────────────────────────────────────────────

def _load_log():
    """
    Load the JSON encryption log from LOG_PATH. If it doesn't exist, return [].
    Each log entry is a dict with keys:
      - "original": str (absolute path of plaintext file before encryption)
      - "encrypted": str (absolute path of ciphertext .enc file)
      - "nonce":   str (hex-encoded 12-byte nonce)
      - "timestamp": str (ISO8601)
    """
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_log(log_entries):
    """
    Overwrite LOG_PATH with the provided list of log entries (as JSON).
    """
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    import sys
    try:
        import flask
        from socket_manager import socketio
        # Find new entries (assume last N are new if called after batch encrypt)
        old_entries = []
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                try:
                    old_entries = json.load(f)
                except Exception:
                    old_entries = []
        new_count = max(0, len(log_entries) - len(old_entries))
        new_entries = log_entries[-new_count:] if new_count else []
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(log_entries, f, indent=2)
        for entry in new_entries:
            msg = f"[{entry['timestamp']}] [ENCRYPT] {os.path.basename(entry['original'])}  {os.path.basename(entry['encrypted'])}"
            socketio.emit('info_alert', {'message': msg})
    except Exception:
        # Fallback: just save the log
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            json.dump(log_entries, f, indent=2)


# ── CORE ENCRYPTION / DECRYPTION ─────────────────────────────────────────────────

def encrypt_file(aesgcm: AESGCM, infile_path: str, out_path: str, log_entries: list):
    """
    Read infile_path bytes, encrypt with AES-GCM (fresh 12-byte nonce), and write:
        [12-byte nonce] ‖ [ciphertext]
    to out_path. Then append a log entry to log_entries.
    """
    with open(infile_path, "rb") as f:
        plaintext = f.read()

    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f_enc:
        f_enc.write(nonce + ciphertext)

    entry = {
        "original": os.path.abspath(infile_path),
        "encrypted": os.path.abspath(out_path),
        "nonce": nonce.hex(),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    log_entries.append(entry)


def decrypt_file(aesgcm: AESGCM, enc_path: str, out_path: str):
    """
    Read enc_path, parse first 12 bytes as nonce and the rest as ciphertext,
    decrypt via AESGCM.decrypt(nonce, ciphertext, None), and write plaintext
    to out_path.
    """
    with open(enc_path, "rb") as f:
        data = f.read()
    if len(data) < 13:
        raise ValueError(f"File {enc_path} too short to contain nonce + ciphertext.")

    nonce = data[:12]
    ciphertext = data[12:]
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "wb") as f_out:
        f_out.write(plaintext)


# ── HIGH-LEVEL OPERATIONS ────────────────────────────────────────────────────────

def encrypt_directory(target_dir=None, quarantine_dir=None, recursive=True, delete_plain=False):
    """
    Encrypt every file under target_dir (if recursive=True, walk subdirectories;
    otherwise only top-level). For each file:
      1. Compute relative path from target_dir.
      2. Build out_path = os.path.join(quarantine_dir, relative_path + ".enc").
      3. Call encrypt_file().
      4. Optionally delete the plaintext file (delete_plain=True).
    Update the JSON log at LOG_PATH accordingly (append new entries).
    """

    td = target_dir or TARGET_DIR
    qd = quarantine_dir or QUARANTINE_DIR

    key = load_or_generate_key()
    aesgcm = AESGCM(key)

    log_entries = _load_log()

    if recursive:
        for root, dirs, files in os.walk(td):
            for filename in files:
                infile = os.path.join(root, filename)
                rel_path = os.path.relpath(infile, td)
                out_subdir = os.path.join(qd, os.path.dirname(rel_path))
                basename = os.path.basename(rel_path)
                out_filename = basename + ".enc"
                out_path = os.path.join(out_subdir, out_filename)

                try:
                    encrypt_file(aesgcm, infile, out_path, log_entries)
                    if delete_plain:
                        os.remove(infile)
                except Exception as e:
                    print(f"[ERROR][AES] Could not encrypt {infile}: {e}")
    else:
        # Only top-level of td
        for entry in os.scandir(td):
            if entry.is_file():
                infile = entry.path
                rel_path = os.path.basename(infile)
                out_subdir = qd
                out_filename = rel_path + ".enc"
                out_path = os.path.join(out_subdir, out_filename)

                try:
                    encrypt_file(aesgcm, infile, out_path, log_entries)
                    if delete_plain:
                        os.remove(infile)
                except Exception as e:
                    print(f"[ERROR][AES] Could not encrypt {infile}: {e}")

    _save_log(log_entries)


def decrypt_directory(quarantine_dir=None, output_dir=None, recursive=True, delete_encrypted=False):
    """
    For every ".enc" file under quarantine_dir, decrypt it to the mirror location
    under output_dir (if recursive=True, maintain subdirectory structure).
    If delete_encrypted=True, remove the .enc file after decryption.
    """
    qd = quarantine_dir or QUARANTINE_DIR
    od = output_dir or TARGET_DIR  # by default, restore to original location

    key = load_or_generate_key()
    aesgcm = AESGCM(key)

    if recursive:
        for root, dirs, files in os.walk(qd):
            for filename in files:
                if not filename.endswith(".enc"):
                    continue
                enc_path = os.path.join(root, filename)
                rel_path_enc = os.path.relpath(enc_path, qd)       # e.g. "subdir/file.txt.enc"
                rel_path = os.path.splitext(rel_path_enc)[0]        # remove ".enc"
                out_path = os.path.join(od, rel_path)

                try:
                    decrypt_file(aesgcm, enc_path, out_path)
                    if delete_encrypted:
                        os.remove(enc_path)
                except Exception as e:
                    print(f"[ERROR][AES] Could not decrypt {enc_path}: {e}")
    else:
        for entry in os.scandir(qd):
            if entry.is_file() and entry.name.endswith(".enc"):
                enc_path = entry.path
                rel_name = os.path.splitext(entry.name)[0]  # e.g. "file.txt"
                out_path = os.path.join(od, rel_name)

                try:
                    decrypt_file(aesgcm, enc_path, out_path)
                    if delete_encrypted:
                        os.remove(enc_path)
                except Exception as e:
                    print(f"[ERROR][AES] Could not decrypt {enc_path}: {e}")


def rotate_key(quarantine_dir=None):
    """
    1) Load old key from KEY_PATH.
    2) Decrypt each .enc file under quarantine_dir in place (to memory) or via temp file.
    3) Generate a new key (overwrite KEY_PATH).
    4) Re-encrypt each plaintext with the new key, writing back to the same .enc path.
    5) Update LOG_PATH entries with new nonce and new timestamp for each file.
    """
    qd = quarantine_dir or QUARANTINE_DIR
    key_old = load_or_generate_key()
    aesgcm_old = AESGCM(key_old)

    # Load and update the log entries in memory
    log_entries = _load_log()
    updated_logs = []

    # Overwrite KEY_PATH now to generate new key
    key_new = AESGCM.generate_key(bit_length=256)
    with open(AES_KEY_PATH, "wb") as f:
        f.write(encrypt_aes_key_with_rsa(key_new, public_key))
    aesgcm_new = AESGCM(key_new)

    for entry in log_entries:
        enc_path = entry["encrypted"]
        try:
            # 2.a) Decrypt with old key
            with open(enc_path, "rb") as f_enc:
                data = f_enc.read()
            nonce_old = bytes.fromhex(entry["nonce"])
            ciphertext = data[12:]
            plaintext = aesgcm_old.decrypt(nonce_old, ciphertext, None)

            # 2.b) Re-encrypt with new key (fresh nonce)
            nonce_new = os.urandom(12)
            ciphertext_new = aesgcm_new.encrypt(nonce_new, plaintext, None)

            # 2.c) Overwrite the existing ciphertext file
            with open(enc_path, "wb") as f_out:
                f_out.write(nonce_new + ciphertext_new)

            # 2.d) Update log entry
            entry["nonce"] = nonce_new.hex()
            entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
            updated_logs.append(entry)
        except Exception as e:
            print(f"[ERROR][AES] rotate_key: failed to re-encrypt {enc_path}: {e}")
            # Keep old entry if we fail to re-encrypt
            updated_logs.append(entry)

    # 5) Save updated log entries
    _save_log(updated_logs)
