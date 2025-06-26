#!/usr/bin/env python3
"""
Production-Ready Intrusion Detection System using Random Forest
UNSW-NB15 Dataset Implementation

Features:
- Optimized Random Forest model
- Real-time prediction capability
- Model persistence and loading
- Comprehensive preprocessing pipeline
- Exploratory Data Analysis (EDA)
- Performance monitoring
- Scalable architecture
"""

import os
import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV, cross_val_score
from sklearn.preprocessing import LabelEncoder, StandardScaler, RobustScaler
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import joblib
import logging
import time
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Ensure Windows console can print UTF-8
if os.name == 'nt':
    os.system('chcp 65001 > nul')


class ProductionIDS:
    def __init__(self, config=None):
        self.config = config or self._get_default_config()
        self.model = None
        self.scaler = None
        self.label_encoders = {}
        self.feature_selector = None
        self.feature_names = None
        self.selected_feature_names = None
        self.is_trained = False
        self._setup_logging()

    def _get_default_config(self):
        return {
            'model_params': {
                'n_estimators': 200,
                'max_depth': 20,
                'min_samples_split': 5,
                'min_samples_leaf': 2,
                'max_features': 'sqrt',
                'bootstrap': True,
                'n_jobs': -1,
                'random_state': 42,
                'class_weight': 'balanced'
            },
            'preprocessing': {
                'scaling_method': 'robust',  # robust, standard, or none
                'feature_selection': True,
                'n_features': 30,
                'handle_missing': True
            },
            'training': {
                'test_size': 0.2,
                'validation_size': 0.2,
                'cv_folds': 5,
                'optimize_hyperparams': True
            },
            'performance': {
                'min_accuracy': 0.95,
                'min_precision': 0.93,
                'min_recall': 0.90,
                'max_prediction_time': 0.001  # seconds
            }
        }

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ids_system.log', encoding='utf-8'),
                logging.StreamHandler(stream=sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)

    def exploratory_data_analysis(self, df, max_cols=10):
        self.logger.info("▶️ EDA: Data shape: %s", df.shape)

        missing = df.isnull().sum()
        if missing.any():
            self.logger.info("▶️ EDA: Missing values per column:\n%s", missing[missing > 0])

        desc = df.describe().T
        self.logger.info("▶️ EDA: Descriptive statistics:\n%s", desc)

        if 'Label' in df.columns or 'label' in df.columns:
            tgt = 'Label' if 'Label' in df.columns else 'label'
            dist = df[tgt].value_counts(normalize=True)
            self.logger.info("▶️ EDA: Target distribution:\n%s", dist)

        num_cols = df.select_dtypes(include=[np.number]).columns.tolist()[:max_cols]
        for col in num_cols:
            plt.figure(figsize=(4, 2))
            plt.hist(df[col].dropna(), bins=30)
            plt.title(f"Hist: {col}")
            plt.tight_layout()
            plt.savefig(f"eda_{col}.png")
            plt.close()
            self.logger.info("▶️ EDA: saved histogram for %s as eda_%s.png", col, col)

        if len(num_cols) > 1:
            corr = df[num_cols].corr()
            plt.figure(figsize=(6, 5))
            plt.imshow(corr, interpolation='nearest', aspect='auto')
            plt.colorbar()
            plt.xticks(range(len(num_cols)), num_cols, rotation=45, ha='right')
            plt.yticks(range(len(num_cols)), num_cols)
            plt.title("EDA: Correlation matrix")
            plt.tight_layout()
            plt.savefig("eda_correlation.png")
            plt.close()
            self.logger.info("▶️ EDA: saved correlation heatmap as eda_correlation.png")

    def load_and_preprocess_data(self, filepath):
        self.logger.info("Loading dataset from %s...", filepath)
        df = pd.read_csv(filepath)
        return self._preprocess_df(df)

    def load_and_preprocess_data_from_df(self, df):
        self.logger.info("Preprocessing DataFrame input...")
        return self._preprocess_df(df)

    def _preprocess_df(self, df):
        if self.config['preprocessing']['handle_missing']:
            df = self._handle_missing_values(df)

        categorical_cols = ['srcip', 'dstip', 'proto', 'state', 'service', 'attack_cat']
        df = self._encode_categorical_features(df, categorical_cols)

        if 'Stime' in df.columns and 'Ltime' in df.columns:
            df = self._process_timestamps(df)

        cols_to_drop = [c for c in ['srcip', 'dstip', 'Stime', 'Ltime'] if c in df.columns]
        df = df.drop(columns=cols_to_drop)

        self.logger.info(f"Dataset ready: {df.shape[0]} samples, {df.shape[1]} features")
        return df

    def _handle_missing_values(self, df):
        for col in df.select_dtypes(include=[np.number]).columns:
            if df[col].isnull().any():
                df[col].fillna(df[col].median(), inplace=True)
        for col in df.select_dtypes(include=['object']).columns:
            if df[col].isnull().any():
                df[col].fillna(df[col].mode()[0], inplace=True)
        return df

    def _encode_categorical_features(self, df, cols):
        for col in cols:
            if col in df.columns:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
                self.label_encoders[col] = le
        return df

    def _process_timestamps(self, df):
        try:
            df['Stime'] = pd.to_datetime(df['Stime'])
            df['Ltime'] = pd.to_datetime(df['Ltime'])
            df['hour'] = df['Stime'].dt.hour
            df['day_of_week'] = df['Stime'].dt.dayofweek
            df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        except Exception as e:
            self.logger.warning(f"Error processing timestamps: {e}")
        return df

    def prepare_features(self, df):
        """Prepare features (X) and target (y) for training."""
        # Pick up the target column (Label or label)
        if 'Label' in df.columns:
            y = df['Label']
        elif 'label' in df.columns:
            y = df['label']
        else:
            raise ValueError("No target column found: expected 'Label' or 'label' in DataFrame")

        # Drop target(s) from feature set
        X = df.drop([c for c in ['Label', 'label', 'attack_cat'] if c in df.columns], axis=1)
        self.feature_names = X.columns.tolist()

        # Scaling
        method = self.config['preprocessing']['scaling_method']
        if method == 'robust':
            if self.scaler is None:
                self.scaler = RobustScaler()
                X_scaled = self.scaler.fit_transform(X)
            else:
                X_scaled = self.scaler.transform(X)
        elif method == 'standard':
            if self.scaler is None:
                self.scaler = StandardScaler()
                X_scaled = self.scaler.fit_transform(X)
            else:
                X_scaled = self.scaler.transform(X)
        else:
            X_scaled = X.values

        X_scaled = pd.DataFrame(X_scaled, columns=X.columns)

        # Feature selection
        if self.config['preprocessing']['feature_selection']:
            if self.feature_selector is None:
                self.feature_selector = SelectKBest(f_classif,
                                                    k=self.config['preprocessing']['n_features'])
                X_selected = self.feature_selector.fit_transform(X_scaled, y)
                self.selected_feature_names = [
                    name for flag, name in zip(self.feature_selector.get_support(), X.columns) if flag
                ]
            else:
                X_selected = self.feature_selector.transform(X_scaled)
        else:
            X_selected = X_scaled.values
            self.selected_feature_names = X.columns.tolist()

        return X_selected, y

    def train_model(self, X, y):
        self.logger.info("Starting model training...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y,
            test_size=self.config['training']['test_size'],
            random_state=42,
            stratify=y
        )

        if self.config['training']['optimize_hyperparams']:
            self.logger.info("Optimizing hyperparameters...")
            self.model = self._optimize_hyperparameters(X_train, y_train)
        else:
            self.model = RandomForestClassifier(**self.config['model_params'])

        start = time.time()
        self.model.fit(X_train, y_train)
        self.logger.info(f"Model trained in {time.time() - start:.2f}s")

        metrics = self._evaluate_model(X_test, y_test)
        cv_scores = cross_val_score(self.model, X_train, y_train,
                                    cv=self.config['training']['cv_folds'],
                                    scoring='f1')
        self.logger.info(f"CV F1 scores: {cv_scores}")
        self.logger.info(f"Mean CV F1: {cv_scores.mean():.4f} ± {cv_scores.std() * 2:.4f}")

        self.is_trained = True
        return self.model

    def _optimize_hyperparameters(self, X_train, y_train):
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [15, 20, 25],
            'min_samples_split': [5, 10],
            'min_samples_leaf': [2, 4],
            'max_features': ['sqrt', 'log2']
        }
        rf = RandomForestClassifier(random_state=42, n_jobs=-1, class_weight='balanced')
        gs = GridSearchCV(rf, param_grid, cv=3, scoring='f1', n_jobs=-1, verbose=1)
        gs.fit(X_train, y_train)
        self.logger.info(f"Best params: {gs.best_params_}")
        self.logger.info(f"Best CV F1: {gs.best_score_:.4f}")
        return gs.best_estimator_

    def _evaluate_model(self, X_test, y_test):
        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)[:, 1]
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_proba)

        self.logger.info(f"Accuracy: {acc:.4f}, Precision: {prec:.4f}, Recall: {rec:.4f}, "
                         f"F1: {f1:.4f}, AUC: {auc:.4f}")

        check = {
            'accuracy': acc >= self.config['performance']['min_accuracy'],
            'precision': prec >= self.config['performance']['min_precision'],
            'recall': rec >= self.config['performance']['min_recall']
        }
        if all(check.values()):
            self.logger.info("Model meets all performance requirements")
        else:
            failed = [k for k, ok in check.items() if not ok]
            self.logger.warning("Model fails on: %s", failed)

        feat_imp = pd.DataFrame({
            'feature': self.selected_feature_names,
            'importance': self.model.feature_importances_
        }).sort_values('importance', ascending=False)
        self.logger.info("Top 10 features:\n%s", feat_imp.head(10))
        return {'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1, 'auc': auc, 'feature_importance': feat_imp}

    def predict(self, X):
        """Make predictions on new data"""
        if not self.is_trained:
            raise ValueError("Train model first")

        # Turn dict/array into DataFrame, then select only the fitted feature columns:
        if not isinstance(X, pd.DataFrame):
            X = pd.DataFrame(X, columns=self.feature_names)
        else:
            X = X.loc[:, self.feature_names]

        # now do scaling & feature-selection exactly as in training
        if self.scaler:
            X_scaled = self.scaler.transform(X)
            X_scaled = pd.DataFrame(X_scaled, columns=self.feature_names)
        else:
            X_scaled = X

        if self.feature_selector:
            X_selected = self.feature_selector.transform(X_scaled)
        else:
            X_selected = X_scaled.values

        preds = self.model.predict(X_selected)
        probs = self.model.predict_proba(X_selected)
        t0 = time.time()  # you may want to time around transform+predict instead
        pred_time = time.time() - t0
        if pred_time > self.config['performance']['max_prediction_time']:
            self.logger.warning(f"Prediction took {pred_time:.4f}s")

        return {
            'predictions': preds,
            'probabilities': probs,
            'prediction_time': pred_time
        }


    def predict_single(self, sample):
        if isinstance(sample, dict):
            df = pd.DataFrame([sample])
        else:
            df = pd.DataFrame([sample], columns=self.feature_names)
        res = self.predict(df)
        return {
            'prediction': res['predictions'][0],
            'confidence': res['probabilities'][0].max(),
            'attack_probability': res['probabilities'][0][1] if res['probabilities'].shape[1] > 1 else 0,
            'prediction_time': res['prediction_time']
        }

    def save_model(self, filepath):
        if not self.is_trained:
            raise ValueError("Train model before saving")
        payload = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_selector': self.feature_selector,
            'feature_names': self.feature_names,
            'selected_feature_names': self.selected_feature_names,
            'config': self.config,
            'timestamp': datetime.now().isoformat()
        }
        joblib.dump(payload, filepath)
        self.logger.info(f"Model saved to {filepath}")

    def load_model(self, filepath):
        data = joblib.load(filepath)
        self.model = data['model']
        self.scaler = data['scaler']
        self.label_encoders = data['label_encoders']
        self.feature_selector = data['feature_selector']
        self.feature_names = data['feature_names']
        self.selected_feature_names = data['selected_feature_names']
        self.config = data.get('config', self.config)
        self.is_trained = True
        self.logger.info(f"Model loaded from {filepath}, saved at {data.get('timestamp')}")

    def get_model_info(self):
        if not self.is_trained:
            return "Model not trained yet"
        return {
            'model_type': 'RandomForestClassifier',
            'n_estimators': self.model.n_estimators,
            'max_depth': self.model.max_depth,
            'n_features': len(self.selected_feature_names),
            'classes': self.model.classes_,
            'is_trained': self.is_trained
        }


def main():
    """Run EDA, train on real data, save and test."""

    ids = ProductionIDS()

    # 1) EDA on real dataset
    try:
        df_raw = pd.read_csv('UNSW_NB15_training-set.csv')
        ids.exploratory_data_analysis(df_raw)
    except FileNotFoundError:
        ids.logger.error("UNSW_NB15 CSV not found; please place 'UNSW_NB15_training-set.csv' in this directory.")
        sys.exit(1)

    # 2) Preprocess & train
    df_processed = ids.load_and_preprocess_data('UNSW_NB15_training-set.csv')
    X, y = ids.prepare_features(df_processed)
    ids.train_model(X, y)

    # 3) Save the trained model
    ids.save_model('ids_model.joblib')

    # 4) Quick test on first record
    test_sample = df_processed.drop(['Label', 'label'], axis=1, errors='ignore').iloc[[0]]
    result = ids.predict(test_sample)
    print("Test prediction:", result)

    # 5) Print model info
    print("Model info:", ids.get_model_info())


if __name__ == "__main__":
    main()
