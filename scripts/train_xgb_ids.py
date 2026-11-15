import sys
import os
import joblib
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import ADASYN
from imblearn.under_sampling import TomekLinks
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'legacy'))

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(project_root, 'dataset')
MODEL_DIR = os.path.join(project_root, 'models2')

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

def preprocess(df_train, df_test):
    df_train = df_train.copy()
    df_test = df_test.copy()

    df_train["label"] = df_train["label"].replace(label_map)
    df_test["label"] = df_test["label"].replace(label_map)

    # Filter out U2R (class 4) if ADASYN generates too few, or keep classes 0, 1, 2, 3, 4
    # The original implementation maps: keep Normal, DoS, Probe, R2L, U2R

    categorical_cols = ["protocol_type", "service", "flag"]

    df_train_cat = pd.get_dummies(df_train[categorical_cols], prefix=categorical_cols)
    df_test_cat = pd.get_dummies(df_test[categorical_cols], prefix=categorical_cols)
    df_test_cat = df_test_cat.reindex(columns=df_train_cat.columns, fill_value=0)

    df_train_num = df_train.drop(columns=categorical_cols)
    df_test_num = df_test.drop(columns=categorical_cols)

    df_train_full = pd.concat([df_train_num.reset_index(drop=True), df_train_cat.reset_index(drop=True)], axis=1)
    df_test_full = pd.concat([df_test_num.reset_index(drop=True), df_test_cat.reset_index(drop=True)], axis=1)

    feature_columns = [col for col in df_train_full.columns if col != "label"]

    X_train = df_train_full[feature_columns].to_numpy(dtype=np.float32)
    Y_train = df_train_full["label"].to_numpy(dtype=int)

    X_test = df_test_full[feature_columns].to_numpy(dtype=np.float32)
    Y_test = df_test_full["label"].to_numpy(dtype=int)

    return X_train, Y_train, X_test, Y_test, feature_columns

def train():
    train_csv = os.path.join(DATA_DIR, "NSL_KDD_Train.csv")
    test_csv = os.path.join(DATA_DIR, "NSL_KDD_Test.csv")

    print("Loading datasets...")
    df_train = pd.read_csv(train_csv, names=col_names, header=None)
    df_test = pd.read_csv(test_csv, names=col_names, header=None)

    X_train, Y_train, X_test, Y_test, feature_columns = preprocess(df_train, df_test)

    print("Scaling features...")
    scaler = StandardScaler().fit(X_train)
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("Oversampling minority classes with ADASYN...")
    # Resample classes 3 (R2L) and 4 (U2R) to build robust ensembles
    adasyn = ADASYN(sampling_strategy={3: 5000, 4: 1000}, random_state=42)
    X_res, Y_res = adasyn.fit_resample(X_train_scaled, Y_train)

    print("Undersampling noisy links with TomekLinks...")
    tomek = TomekLinks(sampling_strategy="not minority")
    X_res, Y_res = tomek.fit_resample(X_res, Y_res)

    print(f"Resampled training counts: {np.bincount(Y_res)}")

    print("Training XGBoost Classifier (Best Tabular Algorithm)...")
    clf = XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.15,
        objective="multi:softprob",
        num_class=5,
        n_jobs=-1,
        random_state=42
    )

    clf.fit(X_res, Y_res)

    print(f"Saving XGBoost model artifacts to {MODEL_DIR}...")
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, os.path.join(MODEL_DIR, "ids_model_full.joblib"))
    joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.joblib"))
    joblib.dump(feature_columns, os.path.join(MODEL_DIR, "feature_columns.joblib"))

    print("Evaluating XGBoost model on test dataset...")
    y_pred = clf.predict(X_test_scaled)
    print("Accuracy :", accuracy_score(Y_test, y_pred))
    print("Confusion Matrix :\n", confusion_matrix(Y_test, y_pred))
    print("Classification Report :\n", classification_report(Y_test, y_pred, digits=4))

if __name__ == "__main__":
    train()
