from flask import Flask, render_template, redirect, url_for, request, flash, session, send_file, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import csv
from collections import Counter
import json
from werkzeug.utils import secure_filename
import zipfile
import eventlet
import threading
import network_monitor as nm
import base64
import yaml
from functools import wraps
from datetime import datetime
import hashlib
from io import StringIO
import math
from urllib.parse import urlencode
from file_scanner import FileScanner
from socket_manager import socketio, init_socketio
from sklearn.metrics import precision_recall_curve, average_precision_score
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc, precision_recall_curve, average_precision_score, classification_report
)
from sklearn.metrics import precision_recall_fscore_support
from sklearn.preprocessing import label_binarize

app = Flask(__name__)
app.secret_key = os.urandom(24)
init_socketio(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

USERS_FILE = os.path.join(os.path.dirname(__file__), 'users.yaml')
AUDIT_LOG = os.path.join('logs', 'user_audit.log')
RULES_FILE = os.path.join(os.path.dirname(__file__), 'rules.yaml')

# At module level, keep a cache of recent info and detected alerts
recent_info_alerts = []
recent_detected_alerts = []

# Caching for model metrics (update to models2 metrics)
MODEL_METRICS_CACHE = {
    'accuracy': 72.22,  # Update with actual models2 metrics if available
    'precision': 80.42,
    'recall': 72.22,
    'f1': 67.76
}

def get_cached_model_metrics():
    return MODEL_METRICS_CACHE

def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f) or {}
        return data.get('users', [])

def save_users(users):
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        yaml.safe_dump({'users': users}, f)

def find_user(username):
    users = load_users()
    for u in users:
        if u['username'] == username:
            return u
    return None

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or getattr(current_user, 'role', None) != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

class User(UserMixin):
    def __init__(self, username, name, role):
        self.id = username
        self.name = name
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    u = find_user(user_id)
    if u:
        return User(u['username'], u['name'], u.get('role', 'user'))
    return None

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        u = find_user(username)
        if u and check_password_hash(u['password'], password):
            user = User(u['username'], u['name'], u.get('role', 'user'))
            login_user(user)
            flash(f"Welcome {user.name}!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    alerts = []
    log_path = os.path.join('logs', 'threat_alerts.csv')
    if os.path.exists(log_path):
        with open(log_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            alerts = list(reader)
    # Summary stats
    total_alerts = len(alerts)
    type_counts = Counter(alert['alert_type'] for alert in alerts)
    unique_types = sorted(type_counts.keys())
    alert_types = unique_types
    alert_counts = [type_counts[t] for t in unique_types]
    alert_type_data = alert_counts
    # For filtering
    selected_type = None
    if 'type' in request.args and request.args['type']:
        selected_type = request.args['type']
        alerts = [a for a in alerts if a['alert_type'] == selected_type]
    # Info/system alerts: model/scaler/feature load, simulation mode, etc.
    info_alerts = []
    # --- Add recent audit log entries ---
    audit_log_path = os.path.join('logs', 'user_audit.log')
    if os.path.exists(audit_log_path):
        with open(audit_log_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            entries = [json.loads(line) for line in lines if line.strip()]
            for entry in sorted(entries, key=lambda e: e['timestamp'], reverse=True)[:10]:
                msg = f"[{entry['timestamp']}] [AUDIT] {entry['action']} (user: {entry.get('admin')}, target: {entry.get('target_user')})"
                info_alerts.append(msg)
    # --- Add recent encryption events ---
    enc_log_path = os.path.join('quarantine', 'encryption_log.json')
    if os.path.exists(enc_log_path):
        with open(enc_log_path, 'r', encoding='utf-8') as f:
            try:
                enc_entries = json.load(f)
                for entry in sorted(enc_entries, key=lambda e: e['timestamp'], reverse=True)[:10]:
                    msg = f"[{entry['timestamp']}] [ENCRYPT] {os.path.basename(entry['original'])} → {os.path.basename(entry['encrypted'])}"
                    info_alerts.append(msg)
            except Exception:
                pass
    # Sort all info_alerts by timestamp descending (parse timestamp)
    import re
    from datetime import datetime
    def extract_ts(s):
        m = re.match(r'\[(.*?)\]', s)
        if m:
            try:
                return datetime.fromisoformat(m.group(1).replace('Z',''))
            except Exception:
                return datetime.min
        return datetime.min
    info_alerts = sorted(info_alerts, key=extract_ts, reverse=True)
    info_alerts = info_alerts[:20]
    # Pagination logic
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 100))
    total_entries = len(alerts)
    total_pages = (total_entries // per_page) + (1 if total_entries % per_page else 0)
    start = (page - 1) * per_page
    end = start + per_page
    page_alerts = alerts[start:end]
    metrics = get_cached_model_metrics()
    return render_template(
        'dashboard.html',
        name=current_user.name,
        alerts=page_alerts,
        total_alerts=total_alerts,
        type_counts=type_counts,
        unique_types=unique_types,
        selected_type=selected_type,
        alert_types=alert_types,
        alert_counts=alert_counts,
        alert_type_data=alert_type_data,
        page=page,
        per_page=per_page,
        total_entries=total_entries,
        total_pages=total_pages,
        model_accuracy=metrics['accuracy'],
        model_precision=metrics['precision'],
        model_recall=metrics['recall'],
        model_f1=metrics['f1'],
        info_alerts=info_alerts
    )

@app.route('/encrypt_decrypt', methods=['GET'])
@login_required
def encrypt_decrypt():
    sensitive_dir = os.path.join(os.path.dirname(__file__), 'sensitive_data')
    quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
    sensitive_files = []
    encrypted_files = []
    if os.path.exists(sensitive_dir):
        sensitive_files = [f for f in os.listdir(sensitive_dir) if os.path.isfile(os.path.join(sensitive_dir, f))]
    if os.path.exists(quarantine_dir):
        encrypted_files = [f for f in os.listdir(quarantine_dir) if f.endswith('.enc')]
    return render_template('encrypt_decrypt.html', sensitive_files=sensitive_files, encrypted_files=encrypted_files)

@app.route('/encrypt_decrypt/encrypt', methods=['POST'])
@login_required
def encrypt_file_route():
    from aes_encryptor import encrypt_file, load_or_generate_key, QUARANTINE_DIR
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    file = request.files.get('file')
    if not file or not file.filename:
        flash('No file selected for encryption.', 'warning')
        return redirect(url_for('encrypt_decrypt'))
    filename = secure_filename(file.filename)
    sensitive_dir = os.path.join(os.path.dirname(__file__), 'sensitive_data')
    os.makedirs(sensitive_dir, exist_ok=True)
    file_path = os.path.join(sensitive_dir, filename)
    file.save(file_path)
    # Encrypt the file
    key = load_or_generate_key()
    aesgcm = AESGCM(key)
    enc_path = os.path.join(QUARANTINE_DIR, filename + '.enc')
    try:
        encrypt_file(aesgcm, file_path, enc_path, log_entries=[])
        flash(f'File encrypted and stored as {enc_path}', 'success')
    except Exception as e:
        flash(f'Encryption failed: {e}', 'danger')
    return redirect(url_for('encrypt_decrypt'))

@app.route('/encrypt_decrypt/decrypt', methods=['POST'])
@login_required
def decrypt_file_route():
    from aes_encryptor import decrypt_file, load_or_generate_key, QUARANTINE_DIR
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    file = request.files.get('file')
    if not file or not file.filename:
        flash('No file selected for decryption.', 'warning')
        return redirect(url_for('encrypt_decrypt'))
    filename = secure_filename(file.filename)
    quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
    os.makedirs(quarantine_dir, exist_ok=True)
    enc_path = os.path.join(quarantine_dir, filename)
    file.save(enc_path)
    # Decrypt the file
    key = load_or_generate_key()
    aesgcm = AESGCM(key)
    import tempfile
    tmp = tempfile.NamedTemporaryFile(delete=False)
    tmp.close()
    try:
        decrypt_file(aesgcm, enc_path, tmp.name)
        return send_file(tmp.name, as_attachment=True, download_name=filename.replace('.enc', ''))
    except Exception as e:
        flash(f'Decryption failed: {e}', 'danger')
        return redirect(url_for('encrypt_decrypt'))

@app.route('/encrypt_decrypt/download')
@login_required
def download_file():
    file_type = request.args.get('type')
    filename = request.args.get('filename')
    if not filename:
        return "No file specified", 400
    if file_type == 'sensitive':
        dir_path = os.path.join(os.path.dirname(__file__), 'sensitive_data')
    elif file_type == 'encrypted':
        dir_path = os.path.join(os.path.dirname(__file__), 'quarantine')
    else:
        return "Invalid file type", 400
    file_path = os.path.join(dir_path, filename)
    if not os.path.exists(file_path):
        return "File not found", 404
    return send_file(file_path, as_attachment=True, download_name=filename)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    # Load encrypted files log
    enc_log_path = os.path.join('quarantine', 'encryption_log.json')
    encrypted_files = []
    if os.path.exists(enc_log_path):
        with open(enc_log_path, 'r', encoding='utf-8') as f:
            all_entries = json.load(f)
            # Remove duplicates: keep only the latest entry for each original file
            seen = {}
            for entry in reversed(all_entries):
                if entry['original'] not in seen:
                    seen[entry['original']] = entry
            encrypted_files = list(seen.values())
    # Handle restore request
    restore_msg = None
    if request.method == 'POST':
        to_restore = request.form.getlist('restore')
        if to_restore:
            from aes_encryptor import decrypt_file, load_or_generate_key
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            key = load_or_generate_key()
            aesgcm = AESGCM(key)
            restored = []
            for enc_path in to_restore:
                # Find log entry
                entry = next((e for e in encrypted_files if e['encrypted'] == enc_path), None)
                if entry:
                    out_path = entry['original']
                    try:
                        decrypt_file(aesgcm, enc_path, out_path)
                        restored.append(os.path.basename(out_path))
                    except Exception as e:
                        restore_msg = f"Error restoring {os.path.basename(enc_path)}: {e}"
            if restored:
                restore_msg = f"Restored: {', '.join(restored)}"
    # Last intrusion notification
    last_intrusion = None
    log_path = os.path.join('logs', 'threat_alerts.csv')
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
            if len(lines) > 1:
                last = lines[-1].split(',')[0]
                last_intrusion = last
    return render_template('admin.html', encrypted_files=encrypted_files, restore_msg=restore_msg, last_intrusion=last_intrusion)

@app.route('/admin/download')
@login_required
def admin_download():
    enc_path = request.args.get('enc_path')
    if not enc_path:
        return "No file specified", 400
    # Find the log entry
    enc_log_path = os.path.join('quarantine', 'encryption_log.json')
    if not os.path.exists(enc_log_path):
        return "No log found", 404
    with open(enc_log_path, 'r', encoding='utf-8') as f:
        all_entries = json.load(f)
        entry = next((e for e in all_entries if e['encrypted'] == enc_path), None)
        if not entry:
            return "File not found in log", 404
        # Decrypt to a temp file
        from aes_encryptor import decrypt_file, load_or_generate_key
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import tempfile
        key = load_or_generate_key()
        aesgcm = AESGCM(key)
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.close()
        try:
            decrypt_file(aesgcm, enc_path, tmp.name)
            return send_file(tmp.name, as_attachment=True, download_name=os.path.basename(entry['original']))
        except Exception as e:
            return f"Error decrypting file: {e}", 500

@app.route('/admin/upload', methods=['POST'])
@login_required
def admin_upload():
    upload_dir = os.path.join(os.path.dirname(__file__), 'sensitive_data')
    os.makedirs(upload_dir, exist_ok=True)
    files = request.files.getlist('file')
    uploaded = []
    for file in files:
        if file and file.filename:
            filename = secure_filename(file.filename)
            save_path = os.path.join(upload_dir, filename)
            file.save(save_path)
            uploaded.append(filename)
    if uploaded:
        flash(f"Uploaded: {', '.join(uploaded)}", "success")
    else:
        flash("No files uploaded.", "warning")
    return redirect(url_for('admin'))

# Store the original process_features function
original_process_features = nm.process_features

def process_features_with_socketio(features):
    from datetime import datetime
    # Call the original function
    result = original_process_features(features)
    # After logging, emit the new alert if an intrusion was detected
    log_path = os.path.join('logs', 'threat_alerts.csv')
    if os.path.exists(log_path):
        with open(log_path, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
            if len(lines) > 1:
                last = lines[-1].split(',')
                if len(last) >= 4:
                    alert = {
                        'timestamp': last[0],
                        'label': last[1],
                        'src': last[2],
                        'dst': last[3]
                    }
                    socketio.emit('new_alert', alert)
    return result

# Replace the original function with our wrapped version
nm.process_features = process_features_with_socketio

def start_ids_monitor():
    # Start the monitor with real network traffic on interface en0
    nm.start_monitor(interface="en0", simulate=False)

@app.route('/encrypt_decrypt/bulk_encrypt', methods=['POST'])
@login_required
def bulk_encrypt():
    from aes_encryptor import encrypt_file, load_or_generate_key, QUARANTINE_DIR
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    files = request.form.getlist('files')
    sensitive_dir = os.path.join(os.path.dirname(__file__), 'sensitive_data')
    key = load_or_generate_key()
    aesgcm = AESGCM(key)
    success, failed = [], []
    for filename in files:
        file_path = os.path.join(sensitive_dir, filename)
        enc_path = os.path.join(QUARANTINE_DIR, filename + '.enc')
        try:
            encrypt_file(aesgcm, file_path, enc_path, log_entries=[])
            success.append(filename)
        except Exception as e:
            failed.append(f"{filename} ({e})")
    if success:
        flash(f"Encrypted: {', '.join(success)}", "success")
    if failed:
        flash(f"Failed: {', '.join(failed)}", "danger")
    return redirect(url_for('encrypt_decrypt'))

@app.route('/encrypt_decrypt/bulk_decrypt', methods=['POST'])
@login_required
def bulk_decrypt():
    from aes_encryptor import decrypt_file, load_or_generate_key, QUARANTINE_DIR
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    files = request.form.getlist('files')
    quarantine_dir = os.path.join(os.path.dirname(__file__), 'quarantine')
    sensitive_dir = os.path.join(os.path.dirname(__file__), 'sensitive_data')
    key = load_or_generate_key()
    aesgcm = AESGCM(key)
    success, failed = [], []
    for filename in files:
        enc_path = os.path.join(quarantine_dir, filename)
        out_path = os.path.join(sensitive_dir, filename.replace('.enc', ''))
        try:
            decrypt_file(aesgcm, enc_path, out_path)
            success.append(filename)
        except Exception as e:
            failed.append(f"{filename} ({e})")
    if success:
        flash(f"Decrypted: {', '.join(success)}", "success")
    if failed:
        flash(f"Failed: {', '.join(failed)}", "danger")
    return redirect(url_for('encrypt_decrypt'))

@app.route('/encrypt_decrypt/preview')
@login_required
def preview_file():
    file_type = request.args.get('type')
    filename = request.args.get('filename')
    if not filename:
        return {"error": "No file specified"}, 400
    if file_type == 'sensitive':
        dir_path = os.path.join(os.path.dirname(__file__), 'sensitive_data')
    elif file_type == 'encrypted':
        dir_path = os.path.join(os.path.dirname(__file__), 'quarantine')
    else:
        return {"error": "Invalid file type"}, 400
    file_path = os.path.join(dir_path, filename)
    if not os.path.exists(file_path):
        return {"error": "File not found"}, 404
    try:
        # Image preview
        if filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')) and file_type == 'sensitive':
            with open(file_path, 'rb') as f:
                encoded = base64.b64encode(f.read()).decode('utf-8')
            return {"is_image": True, "content": encoded}
        # Text preview
        elif filename.lower().endswith(('.txt', '.log', '.csv', '.py', '.md', '.json')) and file_type == 'sensitive':
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read(10000)
            return {"is_image": False, "content": content}
        # For encrypted files, show hex or message
        elif file_type == 'encrypted':
            with open(file_path, 'rb') as f:
                content = f.read(256)
            return {"is_image": False, "content": content.hex() + ("..." if len(content) == 256 else "")}
        else:
            return {"is_image": False, "content": "Preview not supported for this file type."}
    except Exception as e:
        return {"error": str(e)}, 500

def log_user_audit(action, target_user, details=None):
    os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
    # Get previous hash
    prev_hash = '0'
    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG, 'rb') as f:
            try:
                f.seek(-4096, os.SEEK_END)
            except OSError:
                f.seek(0)
            lines = f.readlines()
            if lines:
                last = json.loads(lines[-1].decode('utf-8'))
                prev_hash = last.get('entry_hash', '0')
    entry = {
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'admin': getattr(current_user, 'id', None),
        'action': action,
        'target_user': target_user,
        'details': details or {},
        'prev_hash': prev_hash
    }
    # Compute entry hash
    entry_str = json.dumps(entry, sort_keys=True)
    entry_hash = hashlib.sha256((entry_str + prev_hash).encode('utf-8')).hexdigest()
    entry['entry_hash'] = entry_hash
    with open(AUDIT_LOG, 'a', encoding='utf-8') as f:
        f.write(json.dumps(entry) + '\n')
    # Emit info_alert for live log
    msg = f"[{entry['timestamp']}] [AUDIT] {entry['action']} (user: {entry.get('admin')}, target: {entry.get('target_user')})"
    socketio.emit('info_alert', {'message': msg})

def verify_audit_log():
    """Returns (is_valid, entries, tamper_index)"""
    if not os.path.exists(AUDIT_LOG):
        return True, [], None
    entries = []
    prev_hash = '0'
    with open(AUDIT_LOG, 'r', encoding='utf-8') as f:
        for idx, line in enumerate(f):
            entry = json.loads(line)
            entry_str = json.dumps({k: entry[k] for k in entry if k not in ('entry_hash')}, sort_keys=True)
            expected_hash = hashlib.sha256((entry_str + prev_hash).encode('utf-8')).hexdigest()
            if entry.get('entry_hash') != expected_hash or entry.get('prev_hash') != prev_hash:
                return False, entries + [entry], idx
            prev_hash = entry['entry_hash']
            entries.append(entry)
    return True, entries, None

@app.route('/admin/users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    users = load_users()
    msg = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            username = request.form['username']
            name = request.form['name']
            password = request.form['password']
            role = request.form['role']
            if find_user(username):
                msg = 'Username already exists.'
            else:
                users.append({
                    'username': username,
                    'name': name,
                    'password': generate_password_hash(password),
                    'role': role
                })
                save_users(users)
                log_user_audit('add', username, {'name': name, 'role': role})
                msg = 'User added.'
        elif action == 'delete':
            username = request.form['username']
            users = [u for u in users if u['username'] != username]
            save_users(users)
            log_user_audit('delete', username)
            msg = 'User deleted.'
        elif action == 'edit':
            username = request.form['username']
            for u in users:
                if u['username'] == username:
                    old = {'name': u['name'], 'role': u['role']}
                    u['name'] = request.form['name']
                    u['role'] = request.form['role']
                    changed = {'name': u['name'], 'role': u['role']}
                    if request.form['password']:
                        u['password'] = generate_password_hash(request.form['password'])
                        changed['password_changed'] = True
                    save_users(users)
                    log_user_audit('edit', username, {'old': old, 'new': changed})
                    break
            msg = 'User updated.'
    return render_template('manage_users.html', users=users, msg=msg)

@app.route('/admin/audit_log')
@login_required
@admin_required
def audit_log():
    import math
    import csv
    from io import StringIO
    from urllib.parse import urlencode
    # Filtering
    action = request.args.get('action')
    admin_user = request.args.get('admin')
    target_user = request.args.get('target_user')
    export = request.args.get('export')  # 'csv' or 'json'
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))
    is_valid, entries, tamper_index = verify_audit_log()
    filtered = entries
    if action:
        filtered = [e for e in filtered if e['action'] == action]
    if admin_user:
        filtered = [e for e in filtered if e['admin'] == admin_user]
    if target_user:
        filtered = [e for e in filtered if e['target_user'] == target_user]
    total_entries = len(filtered)
    total_pages = max(1, math.ceil(total_entries / per_page))
    # Export (always export all filtered, not just current page)
    if export == 'csv':
        si = StringIO()
        writer = csv.DictWriter(si, fieldnames=filtered[0].keys() if filtered else [])
        writer.writeheader()
        for e in filtered:
            writer.writerow(e)
        output = si.getvalue()
        return app.response_class(output, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=audit_log.csv'})
    elif export == 'json':
        return app.response_class(json.dumps(filtered, indent=2), mimetype='application/json', headers={'Content-Disposition': 'attachment;filename=audit_log.json'})
    # Pagination
    start = (page - 1) * per_page
    end = start + per_page
    page_entries = filtered[start:end]
    # Build query_args for template (exclude export)
    query_args = {k: v for k, v in request.args.items() if k != 'export'}
    export_csv_url = url_for('audit_log') + '?' + urlencode({**query_args, 'export': 'csv'})
    export_json_url = url_for('audit_log') + '?' + urlencode({**query_args, 'export': 'json'})
    def build_page_url(page_num, per_page_val):
        args = dict(query_args)
        args['page'] = page_num
        args['per_page'] = per_page_val
        return url_for('audit_log') + '?' + urlencode(args)
    first_page_url = build_page_url(1, per_page)
    prev_page_url = build_page_url(page-1 if page > 1 else 1, per_page)
    next_page_url = build_page_url(page+1 if page < total_pages else total_pages, per_page)
    last_page_url = build_page_url(total_pages, per_page)
    return render_template(
        'audit_log.html',
        entries=page_entries,
        is_valid=is_valid,
        tamper_index=tamper_index,
        all_entries=entries,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_entries=total_entries,
        query_args=query_args,
        export_csv_url=export_csv_url,
        export_json_url=export_json_url,
        first_page_url=first_page_url,
        prev_page_url=prev_page_url,
        next_page_url=next_page_url,
        last_page_url=last_page_url
    )

@app.route('/admin/threat_logs')
@login_required
@admin_required
def threat_logs():
    import csv
    import math
    from io import StringIO
    log_path = os.path.join('logs', 'threat_alerts.csv')
    logs = []
    if os.path.exists(log_path):
        with open(log_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            logs = list(reader)
    # Filtering
    date = request.args.get('date')
    alert_type = request.args.get('alert_type')
    src = request.args.get('src')
    dst = request.args.get('dst')
    export = request.args.get('export')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 25))
    filtered = logs
    if date:
        filtered = [l for l in filtered if l['timestamp'].startswith(date)]
    if alert_type:
        filtered = [l for l in filtered if l['alert_type'] == alert_type]
    if src:
        filtered = [l for l in filtered if src in l['source_ip']]
    if dst:
        filtered = [l for l in filtered if dst in l['destination_ip']]
    total_entries = len(filtered)
    total_pages = max(1, math.ceil(total_entries / per_page))
    # Export (all filtered)
    if export == 'csv':
        si = StringIO()
        writer = csv.DictWriter(si, fieldnames=filtered[0].keys() if filtered else [])
        writer.writeheader()
        for l in filtered:
            writer.writerow(l)
        output = si.getvalue()
        return app.response_class(output, mimetype='text/csv', headers={'Content-Disposition': 'attachment;filename=threat_logs.csv'})
    elif export == 'json':
        return app.response_class(json.dumps(filtered, indent=2), mimetype='application/json', headers={'Content-Disposition': 'attachment;filename=threat_logs.json'})
    # Pagination
    start = (page - 1) * per_page
    end = start + per_page
    page_logs = filtered[start:end]
    # For filter dropdowns
    unique_types = sorted(set(l['alert_type'] for l in logs))
    query_args = {k: v for k, v in request.args.items() if k != 'export'}
    export_csv_url = url_for('threat_logs') + '?' + urlencode({**query_args, 'export': 'csv'})
    export_json_url = url_for('threat_logs') + '?' + urlencode({**query_args, 'export': 'json'})
    return render_template(
        'threat_logs.html',
        logs=page_logs,
        all_logs=logs,
        page=page,
        per_page=per_page,
        total_pages=total_pages,
        total_entries=total_entries,
        unique_types=unique_types,
        query_args=query_args,
        export_csv_url=export_csv_url,
        export_json_url=export_json_url
    )

def load_rules():
    if not os.path.exists(RULES_FILE):
        return []
    with open(RULES_FILE, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f) or {}
        return data.get('rules', [])

def save_rules(rules):
    with open(RULES_FILE, 'w', encoding='utf-8') as f:
        yaml.safe_dump({'rules': rules}, f)

@app.route('/admin/rules', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_rules():
    rules = load_rules()
    msg = None
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            rule = {
                'name': request.form['name'],
                'type': request.form['type'],
                'value': request.form['value'],
                'threshold': request.form.get('threshold'),
                'enabled': request.form.get('enabled') == 'on'
            }
            rules.append(rule)
            save_rules(rules)
            msg = 'Rule added.'
        elif action == 'delete':
            idx = int(request.form['index'])
            if 0 <= idx < len(rules):
                rules.pop(idx)
                save_rules(rules)
                msg = 'Rule deleted.'
        elif action == 'edit':
            idx = int(request.form['index'])
            if 0 <= idx < len(rules):
                rules[idx]['name'] = request.form['name']
                rules[idx]['type'] = request.form['type']
                rules[idx]['value'] = request.form['value']
                rules[idx]['threshold'] = request.form.get('threshold')
                rules[idx]['enabled'] = request.form.get('enabled') == 'on'
                save_rules(rules)
                msg = 'Rule updated.'
    return render_template('rules.html', rules=rules, msg=msg)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    users = load_users()
    # Only allow signup if no admin exists
    if any(u['role'] == 'admin' for u in users):
        flash('Signup is disabled: an admin already exists.', 'warning')
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username']
        name = request.form['name']
        password = request.form['password']
        confirm = request.form['confirm']
        if not username or not name or not password:
            flash('All fields are required.', 'danger')
        elif password != confirm:
            flash('Passwords do not match.', 'danger')
        elif find_user(username):
            flash('Username already exists.', 'danger')
        else:
            users.append({
                'username': username,
                'name': name,
                'password': generate_password_hash(password),
                'role': 'admin'
            })
            save_users(users)
            user = User(username, name, 'admin')
            login_user(user)
            flash('Admin account created and logged in.', 'success')
            return redirect(url_for('dashboard'))
    return render_template('signup.html')

# Initialize the file scanner
file_scanner = FileScanner()

@app.route('/scan', methods=['GET'])
@login_required
def scan_page():
    """Render the file scanning page"""
    return render_template('scan.html', name=current_user.name)

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
        
    is_safe, message = file_scanner.scan_file(file)
    
    # Get current timestamp in the exact format from logs
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    
    if is_safe:
        return jsonify({
            'status': 'success',
            'message': message,
            'timestamp': timestamp
        })
    else:
        return jsonify({
            'status': 'error',
            'message': message,
            'timestamp': timestamp
        }), 400

@app.route('/scan/status')
def scan_status():
    status = file_scanner.get_scanner_status()
    return jsonify(status)

@app.route('/test_alert')
def test_alert():
    socketio.emit('attack_alert', {'message': 'Test attack from /test_alert'})
    return 'Test alert sent!'

@app.route('/model_metrics')
@login_required
def model_metrics():
    # Update model/scaler/feature_columns loading to use the latest retrained files
    MODEL_DIR = "models"
    MODEL_PATH = os.path.join(MODEL_DIR, "ids_model_full.joblib")
    SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")
    FEATURE_COLUMNS_PATH = os.path.join(MODEL_DIR, "feature_columns.joblib")

    # Load model, scaler, and feature columns at startup
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)

    # Update class names for dashboard and metrics
    CLASS_NAMES = ['Normal', 'DoS', 'Probe', 'R2L']

    # Load test data
    test_csv = "dataset/NSL_KDD_Test.csv"
    col_names = [
        "duration", "protocol_type", "service", "flag", "src_bytes",
        "dst_bytes", "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
        "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
        "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
        "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
        "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
        "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
        "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
        "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
        "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"
    ]
    label_map = {
        "normal": 0,
        # DoS
        "neptune": 1, "back": 1, "land": 1, "pod": 1, "smurf": 1, "teardrop": 1,
        "mailbomb": 1, "apache2": 1, "processtable": 1, "udpstorm": 1, "worm": 1,
        # Probe
        "ipsweep": 2, "nmap": 2, "portsweep": 2, "satan": 2, "mscan": 2, "saint": 2,
        # R2L
        "ftp_write": 3, "guess_passwd": 3, "imap": 3, "multihop": 3, "phf": 3,
        "spy": 3, "warezclient": 3, "warezmaster": 3, "sendmail": 3, "named": 3,
        "snmpgetattack": 3, "snmpguess": 3, "xlock": 3, "xsnoop": 3, "httptunnel": 3,
        # U2R
        "buffer_overflow": 4, "loadmodule": 4, "perl": 4, "rootkit": 4,
        "ps": 4, "sqlattack": 4, "xterm": 4
    }
    df_test = pd.read_csv(test_csv, names=col_names, header=None)
    df_test["label"] = df_test["label"].replace(label_map)

    # Filter for only Normal, DoS, Probe, and R2L
    keep_classes = [0, 1, 2, 3]
    df_test = df_test[df_test['label'].isin(keep_classes)].copy()

    # Apply log1p to src_bytes and dst_bytes
    for col in ['src_bytes', 'dst_bytes']:
        df_test[col] = np.log1p(df_test[col])
    # Add src_dst_ratio
    df_test['src_dst_ratio'] = df_test['src_bytes'] / (df_test['dst_bytes'] + 1)
    if 'src_dst_ratio' not in col_names:
        col_names.insert(col_names.index('dst_bytes') + 1, 'src_dst_ratio')

    # One-hot encode categorical columns and align with training
    categorical_cols = ["protocol_type", "service", "flag"]
    df_test_cat = pd.get_dummies(df_test[categorical_cols], prefix=categorical_cols)
    # Align columns with training
    df_test_cat = df_test_cat.reindex(columns=[c for c in feature_columns if c not in df_test.columns], fill_value=0)
    df_test_num = df_test.drop(columns=categorical_cols)
    df_test_full = pd.concat([df_test_num.reset_index(drop=True), df_test_cat.reset_index(drop=True)], axis=1)
    X_test = df_test_full[feature_columns].to_numpy(dtype=np.float32)
    Y_test = df_test_full["label"].to_numpy(dtype=int)

    # Scale
    X_test_scaled = scaler.transform(X_test)

    # Predict
    y_pred = model.predict(X_test_scaled)
    y_proba = model.predict_proba(X_test_scaled)

    # Metrics
    accuracy = accuracy_score(Y_test, y_pred) * 100
    precision = precision_score(Y_test, y_pred, average='weighted') * 100
    recall = recall_score(Y_test, y_pred, average='weighted') * 100
    f1 = f1_score(Y_test, y_pred, average='weighted') * 100
    conf_matrix = confusion_matrix(Y_test, y_pred).tolist()

    # Multiclass ROC curve (one-vs-rest)
    Y_test_bin = label_binarize(Y_test, classes=keep_classes)
    roc_fpr = []
    roc_tpr = []
    roc_labels = CLASS_NAMES
    auc_scores = []
    for i in range(len(keep_classes)):
        fpr, tpr, _ = roc_curve(Y_test_bin[:, i], y_proba[:, i])
        roc_fpr.append(fpr.tolist())
        roc_tpr.append(tpr.tolist())
        auc_scores.append(auc(fpr, tpr))
    auc_score = np.mean(auc_scores)

    # PR curve for all classes (optional, not shown)
    pr_precision, pr_recall, _ = precision_recall_curve((Y_test > 0).astype(int), y_proba.max(axis=1))
    pr_avg_precision = average_precision_score((Y_test > 0).astype(int), y_proba.max(axis=1))

    # Per-class metrics
    class_precision, class_recall, class_f1, class_support = precision_recall_fscore_support(
        Y_test, y_pred, labels=keep_classes, zero_division=0
    )
    class_precision = class_precision.tolist()
    class_recall = class_recall.tolist()
    class_f1 = class_f1.tolist()
    class_support = class_support.tolist()

    # Optionally, print classification report to console
    print(classification_report(Y_test, y_pred, digits=4, labels=keep_classes, target_names=CLASS_NAMES))

    metrics = {
        'accuracy': round(accuracy, 2),
        'precision': round(precision, 2),
        'recall': round(recall, 2),
        'f1': round(f1, 2),
        'confusion_matrix': conf_matrix,
        'roc_fpr': roc_fpr,
        'roc_tpr': roc_tpr,
        'roc_labels': roc_labels,
        'auc': round(auc_score, 4),
        'pr_recall': pr_recall.tolist(),
        'pr_precision': pr_precision.tolist(),
        'pr_avg_precision': round(pr_avg_precision, 4),
        'class_names': CLASS_NAMES,
        'class_precision': class_precision,
        'class_recall': class_recall,
        'class_f1': class_f1,
        'class_support': class_support
    }
    return render_template('model_metrics.html', **metrics)

def get_recent_info_alerts():
    # ... (same logic as before for info_alerts aggregation) ...
    return info_alerts

def get_recent_detected_alerts():
    # Detected alerts from threat_alerts.csv
    log_path = os.path.join('logs', 'threat_alerts.csv')
    detected_alerts = []
    if os.path.exists(log_path):
        with open(log_path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in sorted(reader, key=lambda r: r['timestamp'], reverse=True)[:20]:
                msg = f"[{row['timestamp']}] [DETECTED] {row['alert_type']} src={row['src_ip']} dst={row['dst_ip']}"
                detected_alerts.append(msg)
    return detected_alerts

@app.route('/dashboard/info_alerts')
@login_required
def dashboard_info_alerts():
    info_alerts = get_recent_info_alerts()
    detected_alerts = get_recent_detected_alerts()
    return jsonify({'info_alerts': info_alerts, 'detected_alerts': detected_alerts})

if __name__ == '__main__':
    import os
    # Only start simulation in the main process, not the reloader
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true" or not app.debug:
        monitor_thread = threading.Thread(target=start_ids_monitor, daemon=True)
        monitor_thread.start()
    socketio.run(app, debug=True, use_reloader=False, host='0.0.0.0', port=8080) 