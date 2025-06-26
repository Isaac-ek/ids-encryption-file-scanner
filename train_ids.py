# train_ids.py

import os
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler

from imblearn.over_sampling import ADASYN
from imblearn.under_sampling import TomekLinks

from config import DATA_DIR, MODEL_DIR

# 1.1 Define NSL-KDD column names (last column is “label”)
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

# 1.2 Label → numeric mapping for the various attack names
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

# 2. Load the train/test CSVs from data/
train_csv = os.path.join(DATA_DIR, "NSL_KDD_Train.csv")
test_csv  = os.path.join(DATA_DIR, "NSL_KDD_Test.csv")

df_train = pd.read_csv(train_csv, names=col_names, header=None)
df_test  = pd.read_csv(test_csv, names=col_names, header=None)


import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, OneHotEncoder

# (Keep your label_map dict exactly as before.)

def preprocess(df_train: pd.DataFrame, df_test: pd.DataFrame):
    """
    1) Map string labels → integers.
    2) Use pandas.get_dummies() to one-hot encode the three categorical columns on TRAIN, then align TEST.
    3) Drop the original categorical columns.
    4) Horizontally concat numeric + dummy columns for both train and test.
    5) Return (X_train, Y_train, X_test, Y_test, None, None, feature_columns).
       We return None for le_dict and ohe since we’re no longer using them.
    """

    df_train = df_train.copy()
    df_test  = df_test.copy()

    # Step 1: Replace string “label” with numeric via label_map
    df_train["label"] = df_train["label"].replace(label_map)
    df_test["label"]  = df_test["label"].replace(label_map)

    # Define the three categorical columns exactly as in NSL-KDD
    categorical_cols = ["protocol_type", "service", "flag"]

    # Step 2: One-hot encode the three categorical columns using pandas.get_dummies
    #
    #    - On TRAIN: pd.get_dummies(...) will create columns like
    #        protocol_type_tcp, protocol_type_udp, …, service_http, service_ftp, …, flag_SF, flag_REJ, etc.
    #    - On TEST: we call get_dummies(...) the same way, then reindex() to match TRAIN’s dummy columns,
    #      filling any missing columns with 0 (i.e. if TEST has a category TRAIN never saw).
    #
    df_train_cat = pd.get_dummies(df_train[categorical_cols], prefix=categorical_cols)
    df_test_cat  = pd.get_dummies(df_test[categorical_cols], prefix=categorical_cols)

    # Ensure TEST’s dummy columns align with TRAIN’s:
    df_test_cat = df_test_cat.reindex(columns=df_train_cat.columns, fill_value=0)

    # Step 3: Drop the original categorical columns from both DataFrames
    df_train_num = df_train.drop(columns=categorical_cols)
    df_test_num  = df_test.drop(columns=categorical_cols)

    # Step 4: Concatenate numeric columns + one-hot columns (for TRAIN and TEST separately)
    df_train_full = pd.concat([df_train_num.reset_index(drop=True),
                                df_train_cat.reset_index(drop=True)], axis=1)
    df_test_full  = pd.concat([df_test_num.reset_index(drop=True),
                                df_test_cat.reset_index(drop=True)], axis=1)

    # Now build feature_columns: all columns except “label”
    feature_columns = [col for col in df_train_full.columns if col != "label"]

    # Extract X and Y arrays for TRAIN and TEST
    X_train = df_train_full[feature_columns].to_numpy(dtype=np.float32)   # shape (n_train, N_features)
    Y_train = df_train_full["label"].to_numpy(dtype=int)

    X_test  = df_test_full[feature_columns].to_numpy(dtype=np.float32)    # shape (n_test, N_features)
    Y_test  = df_test_full["label"].to_numpy(dtype=int)

    return X_train, Y_train, X_test, Y_test, None, None, feature_columns





def prepare_multiclass(df_train_proc: pd.DataFrame, df_test_proc: pd.DataFrame):
    """
    3) Split features vs labels.
    4) StandardScale X_train,X_test.
    5) ADASYN oversample only R2L (3)→3000, U2R (4)→500, then TomekLinks.
    """

    X_train = df_train_proc.drop(columns=["label"]).values
    Y_train = df_train_proc["label"].astype(int).values

    X_test  = df_test_proc.drop(columns=["label"]).values
    Y_test  = df_test_proc["label"].astype(int).values

    # 3.1 Scale
    scaler = StandardScaler().fit(X_train)
    X_train_scaled = scaler.transform(X_train)
    X_test_scaled  = scaler.transform(X_test)

    # 3.2 ADASYN + Tomek on TRAIN only
    adasyn = ADASYN(sampling_strategy={3: 3000, 4: 500}, random_state=42)
    X_res, Y_res = adasyn.fit_resample(X_train_scaled, Y_train)
    tomek = TomekLinks(sampling_strategy="not minority")
    X_res, Y_res = tomek.fit_resample(X_res, Y_res)

    print("Resampled class counts:", np.bincount(Y_res))

    return X_res, Y_res, X_test_scaled, Y_test, scaler


def train_and_save():
    # 1) Preprocess → X_train, Y_train, X_test, Y_test, le_dict=None, ohe=None, feature_columns
    X_train, Y_train, X_test, Y_test, _, _, feature_columns = preprocess(df_train, df_test)

    # 2) Scale all features (numeric + one-hot)
    scaler_obj = StandardScaler().fit(X_train)
    X_train_scaled = scaler_obj.transform(X_train)
    X_test_scaled  = scaler_obj.transform(X_test)

    # 3) Resample TRAIN only
    adasyn = ADASYN(sampling_strategy={3: 3000, 4: 500}, random_state=42)
    X_res, Y_res = adasyn.fit_resample(X_train_scaled, Y_train)
    tomek = TomekLinks(sampling_strategy="not minority")
    X_res, Y_res = tomek.fit_resample(X_res, Y_res)

    # 4) Train cost-sensitive RandomForest
    class_weights = {0: 1, 1: 1, 2: 1, 3: 10, 4: 20}
    clf = RandomForestClassifier(
        n_estimators=100,
        class_weight=class_weights,
        n_jobs=-1,
        random_state=42
    )
    clf.fit(X_res, Y_res)

    # 5) Save model, scaler, and feature_columns
    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, os.path.join(MODEL_DIR, "ids_model_full.joblib"))
    joblib.dump(scaler_obj, os.path.join(MODEL_DIR, "scaler.joblib"))
    joblib.dump(feature_columns, os.path.join(MODEL_DIR, "feature_columns.joblib"))

    # 6) (Optional) Evaluate on hold-out TEST
    from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
    y_pred = clf.predict(X_test_scaled)
    print("Accuracy  :", accuracy_score(Y_test, y_pred))
    print("Confusion :\n", confusion_matrix(Y_test, y_pred))
    print("Report    :\n", classification_report(Y_test, y_pred, digits=4))



if __name__ == "__main__":
    train_and_save()
