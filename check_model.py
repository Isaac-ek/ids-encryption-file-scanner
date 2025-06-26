#!/usr/bin/env python3
"""
Check the model's performance on actual test data.
"""

import numpy as np
import pandas as pd
import joblib
import os
from config import MODEL_DIR, DATA_DIR
from sklearn.metrics import classification_report, confusion_matrix

# Load the trained model and scaler
model = joblib.load(os.path.join(MODEL_DIR, "ids_model_full.joblib"))
scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
feature_columns = joblib.load(os.path.join(MODEL_DIR, "feature_columns.joblib"))

# Load test data
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
    "neptune": 1, "back": 1, "land": 1, "pod": 1, "smurf": 1, "teardrop": 1,
    "mailbomb": 1, "apache2": 1, "processtable": 1, "udpstorm": 1, "worm": 1,
    "ipsweep": 2, "nmap": 2, "portsweep": 2, "satan": 2, "mscan": 2, "saint": 2,
    "ftp_write": 3, "guess_passwd": 3, "imap": 3, "multihop": 3, "phf": 3,
    "spy": 3, "warezclient": 3, "warezmaster": 3, "sendmail": 3, "named": 3,
    "snmpgetattack": 3, "snmpguess": 3, "xlock": 3, "xsnoop": 3, "httptunnel": 3,
    "buffer_overflow": 4, "loadmodule": 4, "perl": 4, "rootkit": 4,
    "ps": 4, "sqlattack": 4, "xterm": 4
}

test_csv = os.path.join(DATA_DIR, "NSL_KDD_Test.csv")
df_test = pd.read_csv(test_csv, names=col_names, header=None)
df_test['label'] = df_test['label'].replace(label_map)

# Only keep Normal, DoS, Probe, and R2L classes
keep_classes = [0, 1, 2, 3]
df_test = df_test[df_test['label'].isin(keep_classes)].copy()

print("Test data distribution:")
print(df_test['label'].value_counts().sort_index())
print()

# Extract labels first
Y_test = df_test["label"].to_numpy(dtype=int)

# Apply feature engineering
for col in ['src_bytes', 'dst_bytes']:
    df_test[col] = np.log1p(df_test[col])

df_test['src_dst_ratio'] = df_test['src_bytes'] / (df_test['dst_bytes'] + 1)

# Preprocess test data (features only)
categorical_cols = ["protocol_type", "service", "flag"]
df_test_cat = pd.get_dummies(df_test[categorical_cols], prefix=categorical_cols)
df_test_num = df_test.drop(columns=categorical_cols + ["label"])  # Drop label too
df_test_full = pd.concat([df_test_num.reset_index(drop=True), df_test_cat.reset_index(drop=True)], axis=1)

# Ensure columns match training
df_test_full = df_test_full.reindex(columns=feature_columns, fill_value=0)

# Extract features
X_test = df_test_full[feature_columns].to_numpy(dtype=np.float32)

# Scale features
X_test_scaled = scaler.transform(X_test)

# Make predictions
y_pred = model.predict(X_test_scaled)

print("Model performance on test data:")
print("=" * 50)
print(classification_report(Y_test, y_pred, target_names=['Normal', 'DoS', 'Probe', 'R2L', 'U2R']))
print()

print("Confusion Matrix:")
print(confusion_matrix(Y_test, y_pred, labels=[0,1,2,3,4]))
print()

# Check some specific examples
print("Sample predictions from test data:")
print("=" * 50)
for i in range(10):
    true_label = Y_test[i]
    pred_label = y_pred[i]
    true_name = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'][true_label]
    pred_name = ['Normal', 'DoS', 'Probe', 'R2L', 'U2R'][pred_label]
    
    # Get some key features
    duration = df_test.iloc[i]['duration']
    src_bytes = df_test.iloc[i]['src_bytes']
    serror_rate = df_test.iloc[i]['serror_rate']
    num_failed_logins = df_test.iloc[i]['num_failed_logins']
    
    print(f"Sample {i+1}: True={true_name}, Pred={pred_name}")
    print(f"  Features: duration={duration:.2f}, src_bytes={src_bytes:.2f}, serror_rate={serror_rate:.2f}, failed_logins={num_failed_logins}")
    print() 