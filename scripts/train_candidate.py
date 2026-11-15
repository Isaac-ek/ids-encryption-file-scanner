"""Train and evaluate an isolated candidate; never modify the active bundle."""
import argparse, hashlib, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from xgboost import XGBClassifier, __version__ as xgboost_version
from api.settings import ROOT, MODEL_ROOT
from legacy.ids_features import COL_NAMES, LABEL_MAP, CLASS_NAMES, CATEGORICAL_COLS


def load(path):
    frame = pd.read_csv(path, names=COL_NAMES, header=None)
    frame["label"] = frame.label.map(LABEL_MAP)
    if frame.label.isna().any():
        raise ValueError("Dataset has an unknown class label")
    return frame


def encode(frame, columns=None):
    result = pd.get_dummies(frame.drop(columns="label"), columns=CATEGORICAL_COLS)
    if columns is not None:
        result = result.reindex(columns=columns, fill_value=0)
    return result.astype(np.float32)


def metrics(truth, prediction):
    report = classification_report(truth, prediction, labels=range(5), target_names=CLASS_NAMES, output_dict=True, zero_division=0)
    cm = confusion_matrix(truth, prediction, labels=range(5)).tolist()
    return {"accuracy": accuracy_score(truth, prediction), "macro_f1": report["macro avg"]["f1-score"], "normal_false_positive_rate": 1 - report["Normal"]["recall"], "classification": report, "confusion_matrix": cm}


def train(output):
    output = Path(output).resolve()
    if output == MODEL_ROOT or MODEL_ROOT in output.parents:
        raise ValueError("Candidate output must be separate from the active model directory")
    output.mkdir(parents=True, exist_ok=False)
    train_path = ROOT / "dataset/NSL_KDD_Train.csv"
    test_path = ROOT / "dataset/NSL_KDD_Test.csv"
    original = load(train_path)
    # Keep duplicate feature vectors together by retaining one representative.
    training = original.drop_duplicates(subset=COL_NAMES[:-1]).reset_index(drop=True)
    fitting, validation = train_test_split(training, test_size=.2, random_state=42, stratify=training.label)
    frame = encode(fitting); columns = list(frame.columns)
    scaler = StandardScaler().fit(frame.to_numpy())
    x = scaler.transform(frame.to_numpy())
    xv = scaler.transform(encode(validation, columns).to_numpy())
    y = fitting.label.to_numpy(dtype=int)
    candidates = []
    for name in ["random-forest", "xgb-unweighted", "xgb-weighted"]:
        if name == "random-forest":
            model = RandomForestClassifier(n_estimators=160, min_samples_leaf=2, class_weight="balanced_subsample", n_jobs=4, random_state=42)
            model.fit(x, y)
        else:
            model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=.08, objective="multi:softprob", num_class=5, tree_method="hist", n_jobs=4, random_state=42, early_stopping_rounds=25, eval_metric="mlogloss")
            counts = np.bincount(y)
            weights = np.sqrt(len(y) / (5 * counts))[y] if name == "xgb-weighted" else np.ones(len(y))
            model.fit(x, y, sample_weight=weights, eval_set=[(xv, validation.label)], verbose=False)
        result = metrics(validation.label, model.predict(xv))
        candidates.append((name, model, result))
        print(json.dumps({"candidate": name, "validation_macro_f1": result["macro_f1"], "normal_false_positive_rate": result["normal_false_positive_rate"]}), flush=True)
    eligible = [item for item in candidates if item[2]["normal_false_positive_rate"] <= .05]
    if not eligible:
        raise ValueError("No candidate meets the predeclared validation false-alert limit; no test selection performed")
    name, model, selected = max(eligible, key=lambda item: item[2]["macro_f1"])
    # Only the selected candidate is measured on the held-out test set.
    test = load(test_path)
    test_metrics = metrics(test.label, model.predict(scaler.transform(encode(test, columns).to_numpy())))
    joblib.dump(model, output / "ids_model_full.joblib")
    joblib.dump(scaler, output / "scaler.joblib")
    joblib.dump(columns, output / "feature_columns.joblib")
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    baseline = json.loads((MODEL_ROOT / "evaluation.json").read_text())
    old = baseline["metrics"]["classification"]
    gates = {"normal_false_alerts_at_most_5_percent": test_metrics["normal_false_positive_rate"] <= .05,
             "macro_f1_improves": test_metrics["macro_f1"] > old["macro avg"]["f1-score"],
             "r2l_recall_improves": test_metrics["classification"]["R2L"]["recall"] > old["R2L"]["recall"],
             "u2r_recall_improves": test_metrics["classification"]["U2R"]["recall"] > old["U2R"]["recall"]}
    import platform
    from importlib.metadata import version
    report = {"model_type": type(model).__name__, "selected_candidate": name, "selection": "training-only stratified validation, duplicate feature rows removed before split; macro F1 with Normal FPR <= 5%", "training_records": len(fitting), "validation_records": len(validation), "removed_training_duplicates": len(original)-len(training), "seed": 42,
              "training_sha256": sha(train_path), "dataset": test_path.name, "dataset_sha256": sha(test_path), "records": len(test), "bundle_sha256": {p.name: sha(p) for p in output.glob("*.joblib")},
              "validation_candidates": [{"name": n, **m} for n, _, m in candidates], "metrics": test_metrics,
              "release_gates": gates, "eligible_for_promotion": all(gates.values()), "promoted": False,
              "environment": {"python": platform.python_version(), "libraries": {n: xgboost_version if n == "xgboost" else version(n) for n in ["scikit-learn", "xgboost", "numpy", "pandas"]}},
              "limitations": ["Offline NSL-KDD measurement; not evidence of live-network effectiveness.", "A previously inspected test set is not a new untouched real-world holdout.", "No hyperparameters or thresholds were selected using test results."]}
    (output / "evaluation.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({"selected": name, "macro_f1": test_metrics["macro_f1"], "gates": gates, "promoted": False}), flush=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    train(parser.parse_args().output)
