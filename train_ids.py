import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import RandomOverSampler

from config import MODEL_DIR
from ids_features import CLASS_NAMES, build_feature_frame, load_dataset


def train_and_save():
    df_train = load_dataset("NSL_KDD_Train.csv")
    df_test = load_dataset("NSL_KDD_Test.csv")

    train_frame = build_feature_frame(df_train)
    feature_columns = [col for col in train_frame.columns if col != "label"]
    test_frame = build_feature_frame(df_test, feature_columns=feature_columns)

    x_train = train_frame[feature_columns].to_numpy(dtype=np.float32)
    y_train = train_frame["label"].to_numpy(dtype=int)
    x_test = test_frame[feature_columns].to_numpy(dtype=np.float32)
    y_test = test_frame["label"].to_numpy(dtype=int)

    scaler_obj = StandardScaler().fit(x_train)
    x_train_scaled = scaler_obj.transform(x_train)
    x_test_scaled = scaler_obj.transform(x_test)

    oversampler = RandomOverSampler(
        sampling_strategy={3: 6000, 4: 1200},
        random_state=42
    )
    x_resampled, y_resampled = oversampler.fit_resample(x_train_scaled, y_train)

    class_weights = {0: 1, 1: 1, 2: 2, 3: 20, 4: 40}
    clf = RandomForestClassifier(
        n_estimators=300,
        min_samples_leaf=2,
        class_weight=class_weights,
        n_jobs=-1,
        random_state=42
    )
    clf.fit(x_resampled, y_resampled)

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, os.path.join(MODEL_DIR, "ids_model_full.joblib"))
    joblib.dump(scaler_obj, os.path.join(MODEL_DIR, "scaler.joblib"))
    joblib.dump(feature_columns, os.path.join(MODEL_DIR, "feature_columns.joblib"))

    y_pred = clf.predict(x_test_scaled)
    print("Accuracy  :", accuracy_score(y_test, y_pred))
    print("Confusion :\n", confusion_matrix(y_test, y_pred))
    print("Report    :\n", classification_report(y_test, y_pred, digits=4, target_names=CLASS_NAMES, zero_division=0))



if __name__ == "__main__":
    train_and_save()
