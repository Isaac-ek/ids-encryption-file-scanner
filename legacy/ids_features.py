import os

import numpy as np
import pandas as pd

from api.settings import ROOT
DATA_DIR = str(ROOT / "dataset")

COL_NAMES = [
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

LABEL_MAP = {
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

CATEGORICAL_COLS = ["protocol_type", "service", "flag"]
CLASS_NAMES = ["Normal", "DoS", "Probe", "R2L", "U2R"]
PRIMARY_MODEL_FILENAME = "ids_model_full.joblib"
SPECIALIST_MODEL_FILENAME = "ids_model_specialist.joblib"
SCALER_FILENAME = "scaler.joblib"
FEATURE_COLUMNS_FILENAME = "feature_columns.joblib"
SPECIALIST_CONFIG_FILENAME = "ids_specialist_config.joblib"


def load_dataset(filename):
    path = os.path.join(DATA_DIR, filename)
    df = pd.read_csv(path, names=COL_NAMES, header=None)
    df["label"] = df["label"].replace(LABEL_MAP).astype(int)
    return df


def engineer_features(df):
    engineered = df.copy()
    for col in ["src_bytes", "dst_bytes"]:
        engineered[col] = np.log1p(engineered[col])
    engineered["src_dst_ratio"] = engineered["src_bytes"] / (engineered["dst_bytes"] + 1)
    return engineered


def build_feature_frame(df, feature_columns=None):
    engineered = engineer_features(df)
    categorical = pd.get_dummies(engineered[CATEGORICAL_COLS], prefix=CATEGORICAL_COLS)
    numeric = engineered.drop(columns=CATEGORICAL_COLS)
    full = pd.concat([numeric.reset_index(drop=True), categorical.reset_index(drop=True)], axis=1)

    if feature_columns is None:
        feature_columns = [col for col in full.columns if col != "label"]

    return full.reindex(columns=feature_columns + ["label"] if "label" in full.columns else feature_columns, fill_value=0)


def prepare_feature_matrices(train_filename="NSL_KDD_Train.csv", test_filename="NSL_KDD_Test.csv"):
    df_train = load_dataset(train_filename)
    df_test = load_dataset(test_filename)
    train_frame = build_feature_frame(df_train)
    feature_columns = [col for col in train_frame.columns if col != "label"]
    test_frame = build_feature_frame(df_test, feature_columns=feature_columns)
    x_train = train_frame[feature_columns].to_numpy(dtype=np.float32)
    y_train = train_frame["label"].to_numpy(dtype=int)
    x_test = test_frame[feature_columns].to_numpy(dtype=np.float32)
    y_test = test_frame["label"].to_numpy(dtype=int)
    return x_train, y_train, x_test, y_test, feature_columns


def combine_predictions(
    primary_pred,
    primary_proba,
    specialist_pred=None,
    specialist_proba=None,
    specialist_config=None,
):
    final_pred = np.array(primary_pred, copy=True)
    if specialist_pred is None or specialist_proba is None or not specialist_config:
        return final_pred

    override_base_classes = set(specialist_config.get("override_base_classes", [0]))
    max_primary_confidence = specialist_config.get("max_primary_confidence", 0.8)
    thresholds = specialist_config.get("thresholds", {})
    specialist_classes = specialist_config.get("specialist_classes", [0, 3, 4])
    class_to_index = {label: idx for idx, label in enumerate(specialist_classes)}

    for i, base_label in enumerate(primary_pred):
        candidate = int(specialist_pred[i])
        if candidate not in thresholds:
            continue

        specialist_index = class_to_index.get(candidate)
        if specialist_index is None:
            continue

        candidate_score = float(specialist_proba[i][specialist_index])
        base_confidence = float(np.max(primary_proba[i]))
        if (
            base_label in override_base_classes
            and base_confidence <= max_primary_confidence
            and candidate_score >= thresholds[candidate]
        ):
            final_pred[i] = candidate

    return final_pred
