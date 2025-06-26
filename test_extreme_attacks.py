#!/usr/bin/env python3
"""
Test script to generate extreme attack patterns that should definitely trigger detection.
"""

import numpy as np
import pandas as pd
import joblib
import os
from config import MODEL_DIR

# Load the trained model and scaler
model = joblib.load(os.path.join(MODEL_DIR, "ids_model_full.joblib"))
scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
feature_columns = joblib.load(os.path.join(MODEL_DIR, "feature_columns.joblib"))

# Label mapping
label_map_rev = {0: "Normal", 1: "DoS", 2: "Probe", 3: "R2L"}

# Categorical columns for one-hot encoding
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

def create_extreme_dos_attack():
    """Create an extreme DoS attack pattern."""
    features = {
        "duration": 30.0,  # Very long duration
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 2000,  # Very high source bytes
        "dst_bytes": 0,     # Zero destination bytes
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 5,        # Maximum urgent
        "hot": 3,           # Maximum hot
        "num_failed_logins": 5,
        "logged_in": 0,
        "num_compromised": 2,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 10,
        "srv_count": 10,
        "serror_rate": 1.0,  # Maximum error rate
        "srv_serror_rate": 1.0,
        "rerror_rate": 1.0,
        "srv_rerror_rate": 1.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 20,
        "dst_host_srv_count": 20,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 1.0,
        "dst_host_srv_serror_rate": 1.0,
        "dst_host_rerror_rate": 1.0,
        "dst_host_srv_rerror_rate": 1.0,
    }
    
    # Apply feature engineering
    features["src_bytes"] = np.log1p(features["src_bytes"])
    features["dst_bytes"] = np.log1p(features["dst_bytes"])
    features["src_dst_ratio"] = features["src_bytes"] / (features["dst_bytes"] + 1)
    
    return features

def create_extreme_r2l_attack():
    """Create an extreme R2L attack pattern."""
    features = {
        "duration": 0.1,    # Very short duration
        "protocol_type": "tcp",
        "service": "ftp",
        "flag": "SF",
        "src_bytes": 10,    # Very low source bytes
        "dst_bytes": 5,     # Very low destination bytes
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 20,  # Very high failed logins
        "logged_in": 0,
        "num_compromised": 3,     # High compromised
        "root_shell": 1,          # Root shell obtained
        "su_attempted": 1,        # SU attempted
        "num_root": 3,            # High root attempts
        "num_file_creations": 5,  # High file creations
        "num_shells": 3,          # High shells
        "num_access_files": 8,    # High file access
        "num_outbound_cmds": 3,   # High outbound commands
        "is_host_login": 1,
        "is_guest_login": 1,
        "count": 1,
        "srv_count": 1,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 1,
        "dst_host_srv_count": 1,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 1.0,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }
    
    # Apply feature engineering
    features["src_bytes"] = np.log1p(features["src_bytes"])
    features["dst_bytes"] = np.log1p(features["dst_bytes"])
    features["src_dst_ratio"] = features["src_bytes"] / (features["dst_bytes"] + 1)
    
    return features

def test_extreme_attacks():
    """Test extreme attack patterns."""
    
    print("Testing extreme DoS attack pattern...")
    dos_features = create_extreme_dos_attack()
    
    # Process features
    df = pd.DataFrame([dos_features])
    df_cat = pd.get_dummies(df[CATEGORICAL_COLS], prefix=CATEGORICAL_COLS)
    
    train_dummy_cols = [
        col for col in feature_columns
        if any(col.startswith(prefix + '_') for prefix in CATEGORICAL_COLS)
    ]
    df_cat = df_cat.reindex(columns=train_dummy_cols, fill_value=0)
    
    df_num = df.drop(columns=CATEGORICAL_COLS, errors='ignore')
    df_full = pd.concat([df_num.reset_index(drop=True), df_cat.reset_index(drop=True)], axis=1)
    df_full = df_full.reindex(columns=feature_columns, fill_value=0)
    
    X = df_full.to_numpy(dtype=np.float32)
    X_scaled = scaler.transform(X)
    
    pred = model.predict(X_scaled)[0]
    print(f"DoS attack classified as: {label_map_rev[pred]} (pred={pred})")
    print(f"Key features: duration={dos_features['duration']}, src_bytes={dos_features['src_bytes']:.4f}, serror_rate={dos_features['serror_rate']}")
    print()
    
    print("Testing extreme R2L attack pattern...")
    r2l_features = create_extreme_r2l_attack()
    
    # Process features
    df = pd.DataFrame([r2l_features])
    df_cat = pd.get_dummies(df[CATEGORICAL_COLS], prefix=CATEGORICAL_COLS)
    df_cat = df_cat.reindex(columns=train_dummy_cols, fill_value=0)
    
    df_num = df.drop(columns=CATEGORICAL_COLS, errors='ignore')
    df_full = pd.concat([df_num.reset_index(drop=True), df_cat.reset_index(drop=True)], axis=1)
    df_full = df_full.reindex(columns=feature_columns, fill_value=0)
    
    X = df_full.to_numpy(dtype=np.float32)
    X_scaled = scaler.transform(X)
    
    pred = model.predict(X_scaled)[0]
    print(f"R2L attack classified as: {label_map_rev[pred]} (pred={pred})")
    print(f"Key features: num_failed_logins={r2l_features['num_failed_logins']}, num_root={r2l_features['num_root']}, root_shell={r2l_features['root_shell']}")
    print()

if __name__ == "__main__":
    test_extreme_attacks() 