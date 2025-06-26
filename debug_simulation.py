#!/usr/bin/env python3
"""
Debug script to test the simulation and see what attack types are being generated.
"""

import numpy as np
import pandas as pd
import joblib
import os
from network_monitor import generate_random_features
from config import MODEL_DIR

# Load the trained model and scaler
model = joblib.load(os.path.join(MODEL_DIR, "ids_model_full.joblib"))
scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
feature_columns = joblib.load(os.path.join(MODEL_DIR, "feature_columns.joblib"))

# Label mapping
label_map_rev = {0: "Normal", 1: "DoS", 2: "Probe", 3: "R2L"}

# Categorical columns for one-hot encoding
CATEGORICAL_COLS = ["protocol_type", "service", "flag"]

def test_simulation():
    """Test the simulation and see what attack types are generated."""
    
    attack_counts = {"Normal": 0, "DoS": 0, "Probe": 0, "R2L": 0}
    total_tests = 100
    
    print(f"Testing {total_tests} simulated attacks...")
    print("=" * 50)
    
    for i in range(total_tests):
        # Generate random features
        features = generate_random_features()
        
        # Process features like in the real IDS
        df = pd.DataFrame([features])
        df_cat = pd.get_dummies(df[CATEGORICAL_COLS], prefix=CATEGORICAL_COLS)
        
        # Determine dummy columns that were used in training
        train_dummy_cols = [
            col for col in feature_columns
            if any(col.startswith(prefix + '_') for prefix in CATEGORICAL_COLS)
        ]
        df_cat = df_cat.reindex(columns=train_dummy_cols, fill_value=0)
        
        # Drop original categorical cols, then concatenate numeric + dummy
        df_num = df.drop(columns=CATEGORICAL_COLS, errors='ignore')
        df_full = pd.concat([df_num.reset_index(drop=True), df_cat.reset_index(drop=True)], axis=1)
        
        # Reindex to exactly feature_columns (fill missing with 0)
        df_full = df_full.reindex(columns=feature_columns, fill_value=0)
        
        # Convert to NumPy array & scale
        X = df_full.to_numpy(dtype=np.float32)
        X_scaled = scaler.transform(X)
        
        # Predict
        pred = model.predict(X_scaled)[0]
        attack_type = label_map_rev[pred]
        attack_counts[attack_type] += 1
        
        # Print first 10 results for debugging
        if i < 10:
            print(f"Test {i+1}: {attack_type} (pred={pred})")
            print(f"  src_bytes: {features['src_bytes']:.4f}, dst_bytes: {features['dst_bytes']:.4f}")
            print(f"  src_dst_ratio: {features['src_dst_ratio']:.4f}")
            print(f"  serror_rate: {features['serror_rate']:.4f}, rerror_rate: {features['rerror_rate']:.4f}")
            print(f"  num_failed_logins: {features['num_failed_logins']}")
            print()
    
    print("=" * 50)
    print("FINAL RESULTS:")
    for attack_type, count in attack_counts.items():
        percentage = (count / total_tests) * 100
        print(f"{attack_type}: {count} ({percentage:.1f}%)")
    
    print("\nFeature engineering check:")
    print(f"src_bytes range: {features['src_bytes']:.4f}")
    print(f"dst_bytes range: {features['dst_bytes']:.4f}")
    print(f"src_dst_ratio: {features['src_dst_ratio']:.4f}")
    print(f"Feature columns count: {len(feature_columns)}")
    print(f"First 10 feature columns: {feature_columns[:10]}")

if __name__ == "__main__":
    test_simulation() 