#!/usr/bin/env python3
import joblib
import os
import numpy as np
from config import MODEL_DIR, DATA_DIR
from sklearn.metrics import classification_report, confusion_matrix
from ids_features import CLASS_NAMES, build_feature_frame, load_dataset

# Load the trained model and scaler
model = joblib.load(os.path.join(MODEL_DIR, "ids_model_full.joblib"))
scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.joblib"))
feature_columns = joblib.load(os.path.join(MODEL_DIR, "feature_columns.joblib"))

df_test = load_dataset("NSL_KDD_Test.csv")
keep_classes = [0, 1, 2, 3]
df_test = df_test[df_test["label"].isin(keep_classes)].copy()

print("Test data distribution:")
print(df_test['label'].value_counts().sort_index())
print()

Y_test = df_test["label"].to_numpy(dtype=int)
df_test_full = build_feature_frame(df_test, feature_columns=feature_columns)
X_test = df_test_full[feature_columns].to_numpy(dtype=np.float32)

X_test_scaled = scaler.transform(X_test)
y_pred = model.predict(X_test_scaled)

print("Model performance on test data:")
print("=" * 50)
print(classification_report(Y_test, y_pred, labels=keep_classes, target_names=CLASS_NAMES[:4], zero_division=0))
print()

print("Confusion Matrix:")
print(confusion_matrix(Y_test, y_pred, labels=keep_classes))
print()

# Check some specific examples
print("Sample predictions from test data:")
print("=" * 50)
for i in range(10):
    true_label = Y_test[i]
    pred_label = y_pred[i]
    true_name = CLASS_NAMES[true_label]
    pred_name = CLASS_NAMES[pred_label]
    
    # Get some key features
    duration = df_test.iloc[i]['duration']
    src_bytes = df_test.iloc[i]['src_bytes']
    serror_rate = df_test.iloc[i]['serror_rate']
    num_failed_logins = df_test.iloc[i]['num_failed_logins']
    
    print(f"Sample {i+1}: True={true_name}, Pred={pred_name}")
    print(f"  Features: duration={duration:.2f}, src_bytes={src_bytes:.2f}, serror_rate={serror_rate:.2f}, failed_logins={num_failed_logins}")
    print() 
