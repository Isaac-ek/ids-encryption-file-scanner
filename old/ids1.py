import pandas as pd
import numpy as np
import os
import sys
import sklearn
import io
import random
import joblib

from collections import namedtuple
from sklearn.feature_selection import RFE
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler

# --- New Imports for Resampling and Metrics ---
from imblearn.over_sampling import ADASYN
from imblearn.under_sampling import TomekLinks
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix,
)

from config import DATA_DIR, MODEL_DIR, LOG_DIR

# === Column Names for NSL-KDD ===
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

# === Read Training and Testing Data ===
testing_data = pd.read_csv(
    os.path.join(DATA_DIR, "NSL_KDD_Test.csv"),
    names=col_names,
    header=None
)  # NSL-KDD test set ©
training_data = pd.read_csv(
    os.path.join(DATA_DIR, "NSL_KDD_Train.csv"),
    names=col_names,
    header=None
)  # NSL-KDD train set ©

# === Namedtuple Definitions for Clarity ===
ScaledData = namedtuple(
    "ScaledData",
    [
        "X_DoS", "X_DoS_test", "X_Probe", "X_Probe_test",
        "X_R2L", "X_R2L_test", "X_U2R", "X_U2R_test",
        "Y_DoS", "Y_DoS_test", "Y_Probe", "Y_Probe_test",
        "Y_R2L", "Y_R2L_test", "Y_U2R", "Y_U2R_test",
        "X_rfeDoS", "X_rfeProbe", "X_rfeR2L", "X_rfeU2R"
    ]
)

ClassifierDict = namedtuple(
    "ClassifierDict",
    [
        "clf_DoS", "clf_Probe", "clf_R2L", "clf_U2R",
        "clf_rfeDoS", "clf_rfeProbe", "clf_rfeR2L", "clf_rfeU2R"
    ]
)

class IDS:
    def __init__(self, training_data: pd.DataFrame, testing_data: pd.DataFrame):
        self.training_data = training_data
        self.testing_data = testing_data

        # For multiclass aggregation
        self.newdf = None
        self.newdf_test = None

        # For original four-model partitioning
        self.DoS_df = None
        self.Probe_df = None
        self.R2L_df = None
        self.U2R_df = None
        self.DoS_df_test = None
        self.Probe_df_test = None
        self.R2L_df_test = None
        self.U2R_df_test = None

    def preprocess_data(self):
        """
        1) Print categorical counts
        2) Label encode protocol_type, service, flag
        3) One-hot encode, align train & test
        """
        print("Preprocessing data...")
        print("Training Set (categorical distributions):")
        for col_name in self.training_data.columns:
            if self.training_data[col_name].dtype == "object":
                unique_cat = len(self.training_data[col_name].unique())
                print(f"Feature '{col_name}' has {unique_cat} categories")  # ©

        print("\nTop 10 'service' categories (train):")
        print(self.training_data["service"].value_counts().sort_values(ascending=False).head(10))  # ©

        print("\nTesting Set (categorical distributions):")
        for col_name in self.testing_data.columns:
            if self.testing_data[col_name].dtype == "object":
                unique_cat = len(self.testing_data[col_name].unique())
                print(f"Feature '{col_name}' has {unique_cat} categories")  # ©

        # Label encode protocol_type, service, flag
        print("\nLabel encoding categorical features...")
        categorical_cols = ["protocol_type", "service", "flag"]
        df_cat_vals = self.training_data[categorical_cols]
        df_cat_vals_test = self.testing_data[categorical_cols]

        # Create one-hot column names for train
        unique_protocol = sorted(self.training_data["protocol_type"].unique())
        protocol_cols = [f"Protocol_type_{p}" for p in unique_protocol]

        unique_service = sorted(self.training_data["service"].unique())
        service_cols = [f"service_{s}" for s in unique_service]

        unique_flag = sorted(self.training_data["flag"].unique())
        flag_cols = [f"flag_{f}" for f in unique_flag]

        all_unique_cols = protocol_cols + service_cols + flag_cols

        # One-hot column names for test
        unique_service_test = sorted(self.testing_data["service"].unique())
        service_test_cols = [f"service_{s}" for s in unique_service_test]
        all_unique_test_cols = protocol_cols + service_test_cols + flag_cols

        # Label encode both sets
        training_data_encoded = df_cat_vals.apply(LabelEncoder().fit_transform)
        print(training_data_encoded.head())  # ©
        testing_data_encoded = df_cat_vals_test.apply(LabelEncoder().fit_transform)

        # One-hot encode
        print("\nOne-hot encoding...")
        encoder = OneHotEncoder(categories="auto")
        train_oh = encoder.fit_transform(training_data_encoded)
        df_cat_train = pd.DataFrame(train_oh.toarray(), columns=all_unique_cols)

        test_oh = encoder.fit_transform(testing_data_encoded)
        df_cat_test = pd.DataFrame(test_oh.toarray(), columns=all_unique_test_cols)

        # Align test with train columns: add missing service columns (train > test)
        train_services = set(self.training_data["service"].unique())
        test_services = set(self.testing_data["service"].unique())
        diff_services = train_services - test_services

        for svc in diff_services:
            col_name = f"service_{svc}"
            df_cat_test[col_name] = 0  # Add missing column with zeros  # [Springer 2023](#cite　本_turn0search3)

        # Join one-hot to original and drop original categorical cols
        newdf = self.training_data.join(df_cat_train)
        newdf.drop(["protocol_type","service","flag"], axis=1, inplace=True)

        newdf_test = self.testing_data.join(df_cat_test)
        newdf_test.drop(["protocol_type","service","flag"], axis=1, inplace=True)

        self.newdf = newdf
        self.newdf_test = newdf_test
        return newdf, newdf_test

    def partion_dateset(self, newdf: pd.DataFrame, newdf_test: pd.DataFrame):
        """
        1) Map labels {'normal':0, DOS attacks:1, Probe:2, R2L:3, U2R:4}
        2) Partition into DoS_df, Probe_df, R2L_df, U2R_df (train & test)
        """
        print("\n=============== Partition Dataset ===============")

        label_map = {
            "normal": 0, "neptune": 1, "back": 1, "land": 1, "pod": 1, "smurf": 1,
            "teardrop": 1, "mailbomb": 1, "apache2": 1, "processtable": 1,
            "udpstorm": 1, "worm": 1, "ipsweep": 2, "nmap": 2, "portsweep": 2,
            "satan": 2, "mscan": 2, "saint": 2, "ftp_write": 3, "guess_passwd": 3,
            "imap": 3, "multihop": 3, "phf": 3, "spy": 3, "warezclient": 3,
            "warezmaster": 3, "sendmail": 3, "named": 3, "snmpgetattack": 3,
            "snmpguess": 3, "xlock": 3, "xsnoop": 3, "httptunnel": 3,
            "buffer_overflow": 4, "loadmodule": 4, "perl": 4, "rootkit": 4,
            "ps": 4, "sqlattack": 4, "xterm": 4
        }

        # Replace labels
        newdf["label"] = newdf["label"].replace(label_map)
        newdf_test["label"] = newdf_test["label"].replace(label_map)

        # Indices to keep per category
        to_keep_DoS = [0, 1]
        to_keep_Probe = [0, 2]
        to_keep_R2L = [0, 3]
        to_keep_U2R = [0, 4]

        # Filter train
        DoS_df = newdf[newdf["label"].isin(to_keep_DoS)]
        Probe_df = newdf[newdf["label"].isin(to_keep_Probe)]
        R2L_df = newdf[newdf["label"].isin(to_keep_R2L)]
        U2R_df = newdf[newdf["label"].isin(to_keep_U2R)]

        # Filter test
        DoS_df_test = newdf_test[newdf_test["label"].isin(to_keep_DoS)]
        Probe_df_test = newdf_test[newdf_test["label"].isin(to_keep_Probe)]
        R2L_df_test = newdf_test[newdf_test["label"].isin(to_keep_R2L)]
        U2R_df_test = newdf_test[newdf_test["label"].isin(to_keep_U2R)]

        print("Train shapes:", 
              "DoS:", DoS_df.shape, 
              "Probe:", Probe_df.shape, 
              "R2L:", R2L_df.shape, 
              "U2R:", U2R_df.shape)  # ©
        print("Test shapes:",
              "DoS:", DoS_df_test.shape,
              "Probe:", Probe_df_test.shape,
              "R2L:", R2L_df_test.shape,
              "U2R:", U2R_df_test.shape)  # ©

        # Store partitions
        self.DoS_df = DoS_df
        self.Probe_df = Probe_df
        self.R2L_df = R2L_df
        self.U2R_df = U2R_df

        self.DoS_df_test = DoS_df_test
        self.Probe_df_test = Probe_df_test
        self.R2L_df_test = R2L_df_test
        self.U2R_df_test = U2R_df_test

        return [
            DoS_df, Probe_df, R2L_df, U2R_df,
            DoS_df_test, Probe_df_test, R2L_df_test, U2R_df_test
        ]

    def feature_scaling_and_selection(self):
        """
        1) Scale each category’s feature set (StandardScaler)
        2) Perform RFE (13 features) on each category separately
        3) Return 20 arrays packaged in a namedtuple
        """
        # Extract X, y per category
        X_DoS = self.DoS_df.drop("label", axis=1); Y_DoS = self.DoS_df["label"]
        X_Probe = self.Probe_df.drop("label", axis=1); Y_Probe = self.Probe_df["label"]
        X_R2L = self.R2L_df.drop("label", axis=1); Y_R2L = self.R2L_df["label"]
        X_U2R = self.U2R_df.drop("label", axis=1); Y_U2R = self.U2R_df["label"]

        X_DoS_test = self.DoS_df_test.drop("label", axis=1); Y_DoS_test = self.DoS_df_test["label"]
        X_Probe_test = self.Probe_df_test.drop("label", axis=1); Y_Probe_test = self.Probe_df_test["label"]
        X_R2L_test = self.R2L_df_test.drop("label", axis=1); Y_R2L_test = self.R2L_df_test["label"]
        X_U2R_test = self.U2R_df_test.drop("label", axis=1); Y_U2R_test = self.U2R_df_test["label"]

        # Scale each category separately
        scaler1 = StandardScaler().fit(X_DoS);    X_DoS = scaler1.transform(X_DoS)
        scaler2 = StandardScaler().fit(X_Probe);  X_Probe = scaler2.transform(X_Probe)
        scaler3 = StandardScaler().fit(X_R2L);    X_R2L = scaler3.transform(X_R2L)
        scaler4 = StandardScaler().fit(X_U2R);    X_U2R = scaler4.transform(X_U2R)

        scaler5 = StandardScaler().fit(X_DoS_test);   X_DoS_test = scaler5.transform(X_DoS_test)
        scaler6 = StandardScaler().fit(X_Probe_test); X_Probe_test = scaler6.transform(X_Probe_test)
        scaler7 = StandardScaler().fit(X_R2L_test);   X_R2L_test = scaler7.transform(X_R2L_test)
        scaler8 = StandardScaler().fit(X_U2R_test);   X_U2R_test = scaler8.transform(X_U2R_test)

        # RFE selection (n_features_to_select=13)
        base_clf = RandomForestClassifier(n_estimators=10, n_jobs=2)
        rfe = RFE(estimator=base_clf, n_features_to_select=13, step=1)

        rfe.fit(X_DoS, Y_DoS.astype(int));   X_rfeDoS = rfe.transform(X_DoS)
        rfe.fit(X_Probe, Y_Probe.astype(int)); X_rfeProbe = rfe.transform(X_Probe)
        rfe.fit(X_R2L, Y_R2L.astype(int));   X_rfeR2L = rfe.transform(X_R2L)
        rfe.fit(X_U2R, Y_U2R.astype(int));   X_rfeU2R = rfe.transform(X_U2R)

        print("RFE shapes:", X_rfeDoS.shape, X_rfeProbe.shape, X_rfeR2L.shape, X_rfeU2R.shape)  # ©

        return ScaledData(
            X_DoS, X_DoS_test, X_Probe, X_Probe_test,
            X_R2L, X_R2L_test, X_U2R, X_U2R_test,
            Y_DoS, Y_DoS_test, Y_Probe, Y_Probe_test,
            Y_R2L, Y_R2L_test, Y_U2R, Y_U2R_test,
            X_rfeDoS, X_rfeProbe, X_rfeR2L, X_rfeU2R
        )

    def model_build(self,
                    X_DoS, X_DoS_test, X_Probe, X_Probe_test,
                    X_R2L, X_R2L_test, X_U2R, X_U2R_test,
                    Y_DoS, Y_DoS_test, Y_Probe, Y_Probe_test,
                    Y_R2L, Y_R2L_test, Y_U2R, Y_U2R_test,
                    X_rfeDoS, X_rfeProbe, X_rfeR2L, X_rfeU2R):
        """
        1) Train four RandomForests on all features
        2) Train four RandomForests on RFE‐selected features
        """
        clf_DoS = RandomForestClassifier(n_estimators=10, n_jobs=2)
        clf_Probe = RandomForestClassifier(n_estimators=10, n_jobs=2)
        clf_R2L = RandomForestClassifier(n_estimators=10, n_jobs=2)
        clf_U2R = RandomForestClassifier(n_estimators=10, n_jobs=2)

        clf_DoS.fit(X_DoS, Y_DoS.astype(int))
        clf_Probe.fit(X_Probe, Y_Probe.astype(int))
        clf_R2L.fit(X_R2L, Y_R2L.astype(int))
        clf_U2R.fit(X_U2R, Y_U2R.astype(int))

        clf_rfeDoS = RandomForestClassifier(n_estimators=10, n_jobs=2)
        clf_rfeProbe = RandomForestClassifier(n_estimators=10, n_jobs=2)
        clf_rfeR2L = RandomForestClassifier(n_estimators=10, n_jobs=2)
        clf_rfeU2R = RandomForestClassifier(n_estimators=10, n_jobs=2)

        clf_rfeDoS.fit(X_rfeDoS, Y_DoS.astype(int))
        clf_rfeProbe.fit(X_rfeProbe, Y_Probe.astype(int))
        clf_rfeR2L.fit(X_rfeR2L, Y_R2L.astype(int))
        clf_rfeU2R.fit(X_rfeU2R, Y_U2R.astype(int))

        return ClassifierDict(
            clf_DoS, clf_Probe, clf_R2L, clf_U2R,
            clf_rfeDoS, clf_rfeProbe, clf_rfeR2L, clf_rfeU2R
        )

    def model_evaluation(self, clfs: dict, scaled_dict: dict):
        """
        Evaluate the unified multiclass model (full features and RFE features).
        Expects:
        - clfs: a dict with keys "clf_all" and "clf_all_rfe"
        - scaled_dict: a dict containing:
            "X_all", "Y_all", "X_all_test", "Y_all_test", "X_all_rfe", "X_all_test_rfe"
        """
        # 1) Full‐feature model evaluation
        print("\n=== Multiclass (all features) Evaluation ===")
        y_true = scaled_dict["Y_all_test"]
        y_pred = clfs["clf_all"].predict(scaled_dict["X_all_test"])  # access via dict key :contentReference[oaicite:1]{index=1}

        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        print("Confusion Matrix (all features):\n", cm)  # © scikit-learn docs :contentReference[oaicite:2]{index=2}

        # Accuracy
        acc = accuracy_score(y_true, y_pred)
        print(f"Accuracy (all features): {acc:.4f}")  # © scikit-learn docs :contentReference[oaicite:3]{index=3}

        # Per‐class precision, recall, F1
        precision, recall, f1, support = precision_recall_fscore_support(
            y_true,
            y_pred,
            labels=[0, 1, 2, 3, 4],
            zero_division=0
        )  # © scikit-learn docs :contentReference[oaicite:4]{index=4}
        for i, cls in enumerate([0, 1, 2, 3, 4]):
            print(
                f"Class {cls:<2} — Precision: {precision[i]:.3f}, "
                f"Recall: {recall[i]:.3f}, F1: {f1[i]:.3f}, Support: {support[i]}"
            )

        # Classification report
        print("\nClassification Report (all features):")
        print(
            classification_report(
                y_true,
                y_pred,
                labels=[0, 1, 2, 3, 4],
                target_names=["Normal", "DoS", "Probe", "R2L", "U2R"],
                digits=4
            )
        )  # © scikit-learn docs :contentReference[oaicite:5]{index=5}

        # 2) RFE‐feature model evaluation
        print("\n=== Multiclass (RFE features) Evaluation ===")
        y_pred_rfe = clfs["clf_all_rfe"].predict(scaled_dict["X_all_test_rfe"])  # dict key access :contentReference[oaicite:6]{index=6}

        cm_rfe = confusion_matrix(y_true, y_pred_rfe)
        print("Confusion Matrix (RFE features):\n", cm_rfe)

        acc_rfe = accuracy_score(y_true, y_pred_rfe)
        print(f"Accuracy (RFE features): {acc_rfe:.4f}")

        precision_rfe, recall_rfe, f1_rfe, support_rfe = precision_recall_fscore_support(
            y_true,
            y_pred_rfe,
            labels=[0, 1, 2, 3, 4],
            zero_division=0
        )  # © scikit-learn docs :contentReference[oaicite:7]{index=7}
        for i, cls in enumerate([0, 1, 2, 3, 4]):
            print(
                f"Class {cls:<2} (RFE) — Precision: {precision_rfe[i]:.3f}, "
                f"Recall: {recall_rfe[i]:.3f}, F1: {f1_rfe[i]:.3f}, Support: {support_rfe[i]}"
            )

        print("\nClassification Report (RFE features):")
        print(
            classification_report(
                y_true,
                y_pred_rfe,
                labels=[0, 1, 2, 3, 4],
                target_names=["Normal", "DoS", "Probe", "R2L", "U2R"],
                digits=4
            )
        )  


    # === New Methods for Unified Multiclass with Resampling & Cost Sensitivity ===

    def feature_scaling_and_selection_multiclass(self):
        """
        1) Take newdf (all records with label {0..4}) and newdf_test
        2) Split into X_all, Y_all and X_all_test, Y_all_test
        3) Scale via StandardScaler
        4) Perform ADASYN + TomekLink on training data
        5) (Optional) RFE to select top 13 features
        """
        # a) Build feature/label arrays
        X_all = self.newdf.drop("label", axis=1).values
        Y_all = self.newdf["label"].astype(int).values

        X_all_test = self.newdf_test.drop("label", axis=1).values
        Y_all_test = self.newdf_test["label"].astype(int).values

        # b) Scale
        scaler = StandardScaler().fit(X_all)
        X_all_scaled = scaler.transform(X_all)
        X_all_test_scaled = scaler.transform(X_all_test)

        # c) ADASYN oversampling for minority classes (3: R2L, 4: U2R)
        adasyn = ADASYN(
            sampling_strategy={3: 3000, 4: 500},  # boost R2L->3000, U2R->500 ©  
            random_state=42
        )  # [He et al. 2008](#cite　本_turn0search0)

        # d) TomekLinks undersampling to clean noisy overlaps
        tomek = TomekLinks(sampling_strategy="not minority")

        # e) Pipeline: oversample → undersample
        X_res, Y_res = adasyn.fit_resample(X_all_scaled, Y_all)  # ©  
        X_res, Y_res = tomek.fit_resample(X_res, Y_res)  # ©

        print("Post-ADASYN+Tomek class counts:",
              np.bincount(Y_res))  # Check new class distribution  # [Springer 2023](#cite　本_turn0search3)  

        # f) Optional: RFE on the resampled data
        base_clf = RandomForestClassifier(n_estimators=10, n_jobs=2, random_state=42)
        rfe = RFE(estimator=base_clf, n_features_to_select=13, step=1)
        rfe.fit(X_res, Y_res)

        X_all_rfe = rfe.transform(X_res)
        X_all_test_rfe = rfe.transform(X_all_test_scaled)

        return {
            "X_all": X_res,
            "Y_all": Y_res,
            "X_all_test": X_all_test_scaled,
            "Y_all_test": Y_all_test,
            "X_all_rfe": X_all_rfe,
            "X_all_test_rfe": X_all_test_rfe
        }

    def train_multiclass_model(self, scaled_dict):
        """
        1) Train cost-sensitive RandomForest on resampled data
        2) Weights: {0:1, 1:1, 2:1, 3:10, 4:20} to boost minority classes
        3) Train RFE-based RandomForest for comparison
        """

        # 1) Instantiate and fit scaler on the resampled training set
        scaler = StandardScaler().fit(scaled_dict["X_all"])           # X_res is your ADASYN+Tomek resampled features :contentReference[oaicite:6]{index=6}
        X_res_scaled = scaler.transform(scaled_dict["X_all"])         # Transform training set
        X_test_scaled = scaler.transform(scaled_dict["X_all_test"])  # Transform test set :contentReference[oaicite:7]{index=7}

        # 2) Persist the fitted scaler for production
        joblib.dump(scaler, "scaler.joblib", compress=3)
        print("[INFO] Fitted StandardScaler saved to scaler.joblib") 

        class_weights = {0: 1, 1: 1, 2: 1, 3: 10, 4: 20}  # severe penalty for R2L/U2R  # [ScienceDirect 2021](#cite　本_turn0search1)

        # Full-feature RandomForest
        clf_all = RandomForestClassifier(
            n_estimators=100,
            class_weight=class_weights,
            n_jobs=-1,
            random_state=42
        )
        clf_all.fit(X_res_scaled, scaled_dict["Y_all"])  # Y_res are the resampled labels :contentReference[oaicite:9]{index=9}

        # RFE-reduced RandomForest
        clf_all_rfe = RandomForestClassifier(
            n_estimators=100,
            class_weight=class_weights,
            n_jobs=-1,
            random_state=42
        )
        clf_all_rfe.fit(scaled_dict["X_all_rfe"], scaled_dict["Y_all"])

        # clf_all: trained RandomForestClassifier (unified IDS model)
        joblib_filename = "ids_model_full.joblib"
        joblib.dump(clf_all, joblib_filename, compress=3)  # compress=3 balances size & speed :contentReference[oaicite:2]{index=2}
        print(f"Model saved to {joblib_filename}")

        return {"clf_all": clf_all, "clf_all_rfe": clf_all_rfe}

    def evaluate_multiclass_model(self, clfs, scaled_dict):
        """
        1) Compute predictions on X_all_test and X_all_test_rfe
        2) Print confusion matrices, accuracy, precision, recall, F1, classification report
        """
        y_true = scaled_dict["Y_all_test"]
        print("\n=== Multiclass (all features) Evaluation ===")

        # a) Full-feature model
        y_pred = clfs["clf_all"].predict(scaled_dict["X_all_test"])
        cm = confusion_matrix(y_true, y_pred)
        print("Confusion Matrix (all features):\n", cm)  # [scikit-learn docs](#cite　本_turn0search8)

        acc = accuracy_score(y_true, y_pred)
        print(f"Accuracy (all features): {acc:.4f}")  # © [scikit-learn docs](#cite　本_turn0search6)

        precision, recall, f1, support = precision_recall_fscore_support(
            y_true, y_pred,
            labels=[0, 1, 2, 3, 4],
            zero_division=0
        )
        for i, cls in enumerate([0, 1, 2, 3, 4]):
            print(f"Class {cls:<2} — Precision: {precision[i]:.3f}, "
                  f"Recall: {recall[i]:.3f}, F1: {f1[i]:.3f}, Support: {support[i]}")

        print("\nClassification Report (all features):")
        print(classification_report(
            y_true, y_pred,
            labels=[0, 1, 2, 3, 4],
            target_names=["Normal", "DoS", "Probe", "R2L", "U2R"],
            digits=4
        ))  # © [scikit-learn docs](#cite　本_turn0search8)

        # b) RFE-reduced model
        print("\n=== Multiclass (RFE features) Evaluation ===")
        y_pred_rfe = clfs["clf_all_rfe"].predict(scaled_dict["X_all_test_rfe"])
        cm_rfe = confusion_matrix(y_true, y_pred_rfe)
        print("Confusion Matrix (RFE features):\n", cm_rfe)

        acc_rfe = accuracy_score(y_true, y_pred_rfe)
        print(f"Accuracy (RFE features): {acc_rfe:.4f}")  # ©

        precision_rfe, recall_rfe, f1_rfe, support_rfe = precision_recall_fscore_support(
            y_true, y_pred_rfe,
            labels=[0, 1, 2, 3, 4],
            zero_division=0
        )
        for i, cls in enumerate([0, 1, 2, 3, 4]):
            print(f"Class {cls:<2} (RFE) — Precision: {precision_rfe[i]:.3f}, "
                  f"Recall: {recall_rfe[i]:.3f}, F1: {f1_rfe[i]:.3f}, Support: {support_rfe[i]}")

        print("\nClassification Report (RFE features):")
        print(classification_report(
            y_true, y_pred_rfe,
            labels=[0, 1, 2, 3, 4],
            target_names=["Normal", "DoS", "Probe", "R2L", "U2R"],
            digits=4
        ))



# Instantiate IDS
ids = IDS(training_data, testing_data)

# 1) Preprocess (label & one-hot encode)
data = ids.preprocess_data()

# 2) Partition into four binary splits
dfs = ids.partion_dateset(data[0], data[1])

# 3) Four-model pipeline (unchanged) – optional
scaled_four = ids.feature_scaling_and_selection()
clfs_four = ids.model_build(
    scaled_four.X_DoS, scaled_four.X_DoS_test,
    scaled_four.X_Probe, scaled_four.X_Probe_test,
    scaled_four.X_R2L, scaled_four.X_R2L_test,
    scaled_four.X_U2R, scaled_four.X_U2R_test,
    scaled_four.Y_DoS, scaled_four.Y_DoS_test,
    scaled_four.Y_Probe, scaled_four.Y_Probe_test,
    scaled_four.Y_R2L, scaled_four.Y_R2L_test,
    scaled_four.Y_U2R, scaled_four.Y_U2R_test,
    scaled_four.X_rfeDoS, scaled_four.X_rfeProbe,
    scaled_four.X_rfeR2L, scaled_four.X_rfeU2R
)

# 2) Build the resampled + scaled multiclass data
scaled_multi = ids.feature_scaling_and_selection_multiclass()

# 3) Train the cost-sensitive RF (full + RFE)
clfs_multi = ids.train_multiclass_model(scaled_multi)

ids.model_evaluation(clfs_multi, scaled_multi)


ids.evaluate_multiclass_model(clfs_multi, scaled_multi)
