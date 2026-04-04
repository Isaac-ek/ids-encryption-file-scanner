import os
import joblib
import numpy as np
from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from imblearn.over_sampling import RandomOverSampler
from config import MODEL_DIR
from ids_features import (
    CLASS_NAMES,
    FEATURE_COLUMNS_FILENAME,
    PRIMARY_MODEL_FILENAME,
    SCALER_FILENAME,
    SPECIALIST_CONFIG_FILENAME,
    SPECIALIST_MODEL_FILENAME,
    combine_predictions,
    prepare_feature_matrices,
)


def train_and_save():
    x_train, y_train, x_test, y_test, feature_columns = prepare_feature_matrices()

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

    specialist_mask = np.isin(y_train, [0, 3, 4])
    x_specialist = x_train_scaled[specialist_mask]
    y_specialist = y_train[specialist_mask]
    specialist_oversampler = RandomOverSampler(
        sampling_strategy={3: 9000, 4: 3000},
        random_state=42
    )
    x_specialist_resampled, y_specialist_resampled = specialist_oversampler.fit_resample(
        x_specialist,
        y_specialist
    )
    specialist = ExtraTreesClassifier(
        n_estimators=320,
        min_samples_leaf=2,
        class_weight={0: 1, 3: 18, 4: 35},
        n_jobs=-1,
        random_state=42,
    )
    specialist.fit(x_specialist_resampled, y_specialist_resampled)

    specialist_config = {
        "specialist_classes": [0, 3, 4],
        "override_base_classes": [0],
        "max_primary_confidence": 0.82,
        "thresholds": {
            3: 0.34,
            4: 0.22,
        },
    }

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(clf, os.path.join(MODEL_DIR, PRIMARY_MODEL_FILENAME))
    joblib.dump(specialist, os.path.join(MODEL_DIR, SPECIALIST_MODEL_FILENAME))
    joblib.dump(scaler_obj, os.path.join(MODEL_DIR, SCALER_FILENAME))
    joblib.dump(feature_columns, os.path.join(MODEL_DIR, FEATURE_COLUMNS_FILENAME))
    joblib.dump(specialist_config, os.path.join(MODEL_DIR, SPECIALIST_CONFIG_FILENAME))

    primary_pred = clf.predict(x_test_scaled)
    primary_proba = clf.predict_proba(x_test_scaled)
    specialist_pred = specialist.predict(x_test_scaled)
    specialist_proba = specialist.predict_proba(x_test_scaled)
    y_pred = combine_predictions(
        primary_pred=primary_pred,
        primary_proba=primary_proba,
        specialist_pred=specialist_pred,
        specialist_proba=specialist_proba,
        specialist_config=specialist_config,
    )
    print("Accuracy  :", accuracy_score(y_test, y_pred))
    print("Confusion :\n", confusion_matrix(y_test, y_pred))
    print("Report    :\n", classification_report(y_test, y_pred, digits=4, target_names=CLASS_NAMES, zero_division=0))



if __name__ == "__main__":
    train_and_save()
