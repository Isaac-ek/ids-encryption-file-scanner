# Model training direction

The active model is the existing XGBoost bundle. Consolidation does not fit a new model or overwrite its scaler/feature columns. `python scripts/evaluate_model.py` evaluates the preserved bundle against the existing held-out NSL-KDD test file and saves its report with artifact and dataset hashes.

For future experiments, retain Random Forest as a baseline and compare it with class-weighted XGBoost and the existing ADASYN/Tomek approach. Build validation folds from training data only. Fit categorical vocabularies, scaling and resampling inside each training fold. Use validation-based early stopping and make selection decisions using macro F1, per-class recall and the false-positive rate on Normal records. Do not select hyperparameters using the held-out test file.

Offline performance is not a live-network detection guarantee. Validate packet-to-feature extraction and evaluate representative authorized captures before making operational claims. Neither the website scanner's findings nor replayed attack labels replace actual detector predictions.

The training scripts intentionally remain separate from the web app. Record package versions, data hashes, feature schema, model type and artifact hashes with each future training run. Never allow uploaded pickle/joblib files to be loaded as models.

Primary references: [scikit-learn: common pitfalls](https://scikit-learn.org/stable/common_pitfalls.html), [XGBoost Python API](https://xgboost.readthedocs.io/en/stable/python/python_api.html).

The preserved bundle was evaluated with Python 3.12, scikit-learn 1.6.1 and XGBoost 3.0.2. On 22,544 NSL-KDD test records, accuracy is 77.78% and macro F1 is 0.5693. R2L recall is 12.89% and U2R recall is 13.43%; improving those classes while controlling false alerts is the priority for a future training comparison. The complete report includes package versions, per-class metrics, confusion matrix, and hashes for the model, scaler, columns and dataset.

The first isolated comparison has now run; its selected candidate failed the rare-class and macro-F1 release gates, so the active bundle remains unchanged. See [detector validation](detector-validation.md) for the reproducible command and full report.
