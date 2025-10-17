import pandas as pd
import numpy as np
import pickle
import json
import logging
from datetime import datetime
import os
import hashlib
from urllib.parse import unquote, urlparse
import re

# ML Libraries
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import (classification_report, accuracy_score, 
                             confusion_matrix, roc_auc_score, f1_score)
from sklearn.pipeline import Pipeline
import xgboost as xgb
from sklearn.base import BaseEstimator, TransformerMixin

# Deep Learning (optional for autoencoder)
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense, Dropout
from tensorflow.keras.optimizers import Adam

import warnings
warnings.filterwarnings('ignore')

# Ensure reproducibility
np.random.seed(42)

class MasterThreatModelV2:
    def __init__(self, config=None):
        self.config = config or self._default_config()
        self.setup_logging()
        self.text_pipeline = None
        self.anomaly_model = None
        self.scaler = None
        self.label_encoder = None
        self.is_trained = False
        self.performance_metrics = {}
        self.feature_columns = [
            'request_size', 'response_time', 'requests_per_minute',
            'error_rate', 'unique_endpoints', 'payload_length',
            'entropy', 'num_special_chars', 'num_digits', 'url_depth'
        ]
        
    def _default_config(self):
        return {
            'text_model': {
                'n_estimators': 300,
                'max_depth': 20,
                'class_weight': 'balanced_subsample'
            },
            'anomaly_model': {
                'contamination': 0.1,
                'n_estimators': 200
            },
            'dataset': {
                'text_samples_per_class': 5000,  # <<<<< HUGE increase
                'anomaly_samples_normal': 50000,
                'anomaly_samples_attack': 10000
            },
            'features': {
                'use_entropy': True,
                'use_url_depth': True,
                'use_char_ngrams': True
            }
        }

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - MASTER_MODEL_V2 - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    # ======================
    # 📊 DATA GENERATION
    # ======================

    def _calculate_entropy(self, s):
        if not s:
            return 0
        prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
        entropy = - sum([p * np.log2(p) for p in prob])
        return entropy

    def _extract_lexical_features(self, texts):
        features = []
        for text in texts:
            decoded = unquote(str(text))
            features.append({
                'entropy': self._calculate_entropy(decoded),
                'num_special_chars': len(re.findall(r'[^a-zA-Z0-9\s]', decoded)),
                'num_digits': sum(c.isdigit() for c in decoded),
                'url_depth': len(urlparse(decoded).path.split('/')) - 1 if decoded.startswith('http') else 0
            })
        return pd.DataFrame(features)

    def generate_training_data(self):
        self.logger.info("📊 Generating LARGE-SCALE Training Data (50K+ samples)")

        # Load real-world payloads (you can expand this with files from SecLists, etc.)
        real_payloads = {
            'sql_injection': [
                "' OR '1'='1'--", "admin'--", "' OR 1=1--", "'; DROP TABLE users--",
                "' UNION SELECT null,version()--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' OR pg_sleep(5)--", "' WAITFOR DELAY '0:0:5'--", 
                # Add 100+ more from https://github.com/payloadbox/sql-injection-payload-list
            ] * 100,
            'xss': [
                "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>", "javascript:alert(1)", 
                # Add from XSS polyglots
            ] * 100,
            'path_traversal': [
                "../../../etc/passwd", "../../../../windows/win.ini",
                "..%2f..%2f..%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"
            ] * 100,
            'command_injection': [
                "; ls", "| cat /etc/passwd", "& whoami", "`id`", "$(cat /etc/passwd)"
            ] * 100,
            'ssrf': [
                "http://169.254.169.254/latest/meta-data/", "http://localhost:8080/admin",
                "http://127.0.0.1:22", "file:///etc/passwd"
            ] * 100,
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
                '<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZXh0ZXJuYWwgeWVz"> %init; ]>'
            ] * 100,
            'normal': [
                "login", "search?q=python", "/api/v1/users", "GET /index.html",
                "POST /auth", "user_id=123", "page=2", "sort=name"
            ] * 1000  # More normal traffic
        }

        # Expand each class to 5000 samples using augmentation
        training_data = []
        for label, base_patterns in real_payloads.items():
            augmented = self._augment_payloads(base_patterns, target_size=self.config['dataset']['text_samples_per_class'])
            for payload in augmented:
                training_data.append({
                    'text': payload,
                    'label': label,
                    'is_malicious': 1 if label != 'normal' else 0
                })

        df = pd.DataFrame(training_data)
        self.logger.info(f"✅ Generated {len(df)} text samples across {df['label'].nunique()} classes")
        return df

    def _augment_payloads(self, payloads, target_size=5000):
        """Augment payloads via encoding, obfuscation, and noise injection"""
        augmented = set(payloads)
        while len(augmented) < target_size:
            for p in payloads:
                if len(augmented) >= target_size:
                    break
                # URL encoding
                augmented.add(p.replace("'", "%27").replace(" ", "%20"))
                # Case variation
                augmented.add(p.swapcase())
                # Whitespace insertion
                augmented.add(p.replace(" ", "  "))
                # Comment insertion (for SQL/XSS)
                if "'" in p:
                    augmented.add(p.replace("'", "'/**/"))
                if "<" in p:
                    augmented.add(p.replace("<", "<!-- -->"))
        return list(augmented)[:target_size]

    def generate_anomaly_training_data(self):
        self.logger.info("📊 Generating Numerical Anomaly Data (60K+ samples)")
        np.random.seed(42)

        def generate_normal(n):
            return {
                'request_size': np.random.normal(1500, 300, n),
                'response_time': np.random.exponential(0.3, n),
                'requests_per_minute': np.random.poisson(15, n),
                'error_rate': np.random.beta(2, 50, n),
                'unique_endpoints': np.random.randint(5, 25, n),
                'payload_length': np.random.normal(200, 50, n)
            }

        def generate_attack(n):
            return {
                'request_size': np.concatenate([
                    np.random.normal(8000, 2000, n//5),   # Exfil
                    np.random.normal(50, 10, n//5),       # Probing
                    np.random.normal(1500, 300, 3*n//5)   # Mixed
                ]),
                'response_time': np.concatenate([
                    np.random.exponential(2.0, n//3),     # Slowloris
                    np.random.exponential(0.05, 2*n//3)   # Flooding
                ]),
                'requests_per_minute': np.concatenate([
                    np.random.poisson(200, n//2),         # DDoS-like
                    np.random.poisson(1, n//2)            # Low-slow
                ]),
                'error_rate': np.random.beta(15, 10, n),  # High errors
                'unique_endpoints': np.concatenate([
                    np.random.randint(1, 3, n//2),        # Targeted
                    np.random.randint(30, 60, n//2)       # Recon
                ]),
                'payload_length': np.concatenate([
                    np.random.normal(6000, 1500, n//3),
                    np.random.normal(30, 5, 2*n//3)
                ])
            }

        n_normal = self.config['dataset']['anomaly_samples_normal']
        n_attack = self.config['dataset']['anomaly_samples_attack']

        normal_df = pd.DataFrame(generate_normal(n_normal))
        normal_df['label'] = 'normal'
        normal_df['is_anomaly'] = 0

        attack_df = pd.DataFrame(generate_attack(n_attack))
        attack_df['label'] = 'attack'
        attack_df['is_anomaly'] = 1

        combined = pd.concat([normal_df, attack_df], ignore_index=True)
        self.logger.info(f"✅ Generated {len(combined)} numerical samples")
        return combined

    # ======================
    # 🤖 MODEL TRAINING
    # ======================

    def train_text_classifier(self, text_data):
        self.logger.info("🤖 Training ENSEMBLE Text Classifier (RF + XGBoost)")

        X_text = text_data['text']
        y_text = text_data['label']

        # Label encoding
        self.label_encoder = LabelEncoder()
        y_encoded = self.label_encoder.fit_transform(y_text)

        # Lexical features
        lexical_df = self._extract_lexical_features(X_text)
        lexical_features = lexical_df.values

        # TF-IDF
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 4),
            analyzer='char_wb',
            min_df=3,
            max_df=0.9,
            sublinear_tf=True
        )
        tfidf_features = self.vectorizer.fit_transform(X_text).toarray()

        # Combine features
        X_combined = np.hstack([tfidf_features, lexical_features])

        # Split
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
        )

        # Models
        rf = RandomForestClassifier(
            n_estimators=self.config['text_model']['n_estimators'],
            max_depth=self.config['text_model']['max_depth'],
            class_weight=self.config['text_model']['class_weight'],
            random_state=42,
            n_jobs=-1
        )
        xgb_model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=12,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            random_state=42,
            eval_metric='mlogloss'
        )

        # Ensemble
        ensemble = VotingClassifier(
            estimators=[('rf', rf), ('xgb', xgb_model)],
            voting='soft'
        )

        ensemble.fit(X_train, y_train)

        # Evaluate
        y_pred = ensemble.predict(X_test)
        y_proba = ensemble.predict_proba(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred, average='weighted')
        report = classification_report(y_test, y_pred, target_names=self.label_encoder.classes_)

        self.logger.info(f"✅ Text Ensemble - Accuracy: {accuracy:.4f}, F1: {f1:.4f}")
        self.text_pipeline = ensemble

        return {
            'accuracy': float(accuracy),
            'f1_score': float(f1),
            'classification_report': report,
            'classes': self.label_encoder.classes_.tolist()
        }

    def train_anomaly_detector(self, anomaly_data):
        self.logger.info("🔍 Training Advanced Anomaly Detector")

        X = anomaly_data[self.feature_columns]
        y = anomaly_data['is_anomaly']

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )

        self.anomaly_model = IsolationForest(
            contamination=self.config['anomaly_model']['contamination'],
            n_estimators=self.config['anomaly_model']['n_estimators'],
            random_state=42,
            n_jobs=-1
        )
        self.anomaly_model.fit(X_train)

        y_pred = (self.anomaly_model.predict(X_test) == -1).astype(int)
        accuracy = accuracy_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)

        self.logger.info(f"✅ Anomaly Model - Accuracy: {accuracy:.4f}, F1: {f1:.4f}")
        return {'accuracy': float(accuracy), 'f1_score': float(f1)}

    def train_complete_model(self):
        self.logger.info("🚀 Starting FULL Training Pipeline")

        text_data = self.generate_training_data()
        anomaly_data = self.generate_anomaly_training_data()

        text_metrics = self.train_text_classifier(text_data)
        anomaly_metrics = self.train_anomaly_detector(anomaly_data)

        self.is_trained = True
        self.performance_metrics = {
            'text_classifier': text_metrics,
            'anomaly_detector': anomaly_metrics,
            'training_config': self.config,
            'training_date': datetime.now().isoformat(),
            'dataset_sizes': {
                'text_samples': len(text_data),
                'anomaly_samples': len(anomaly_data)
            }
        }

        self.logger.info("🎯 Training Complete!")
        return self.performance_metrics

    # ======================
    # 🧪 PREDICTION & UTILS
    # ======================

    def predict_threat(self, input_text):
        if not self.is_trained:
            raise ValueError("Model not trained!")

        lexical = self._extract_lexical_features([input_text])
        tfidf = self.vectorizer.transform([input_text]).toarray()
        combined = np.hstack([tfidf, lexical.values])

        pred_encoded = self.text_pipeline.predict(combined)[0]
        proba = self.text_pipeline.predict_proba(combined)[0]

        prediction = self.label_encoder.inverse_transform([pred_encoded])[0]
        confidence = np.max(proba)

        threat_levels = {
            'normal': 'LOW',
            'sql_injection': 'CRITICAL',
            'command_injection': 'CRITICAL',
            'xss': 'HIGH',
            'path_traversal': 'HIGH',
            'ssrf': 'HIGH',
            'xxe': 'HIGH'
        }

        return {
            'input': input_text,
            'prediction': prediction,
            'confidence': float(confidence),
            'threat_level': threat_levels.get(prediction, 'MEDIUM'),
            'is_malicious': prediction != 'normal'
        }

    def save_model(self, filepath='../models/master_threat_model_v2.pkl'):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        model_data = {
            'text_pipeline': self.text_pipeline,
            'vectorizer': self.vectorizer,
            'label_encoder': self.label_encoder,
            'anomaly_model': self.anomaly_model,
            'scaler': self.scaler,
            'performance_metrics': self.performance_metrics,
            'is_trained': self.is_trained,
            'feature_columns': self.feature_columns,
            'save_date': datetime.now().isoformat()
        }
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        self.logger.info(f"💾 Model saved to {filepath}")
        return filepath

    def load_model(self, filepath='../models/master_threat_model_v2.pkl'):
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
        for key, value in data.items():
            setattr(self, key, value)
        self.logger.info("📂 Model loaded successfully")
        return True

# ======================
# 🚀 TRAINING SCRIPT
# ======================

def train_and_save_enhanced_model():
    model = MasterThreatModelV2()
    print("🚀 Training ENHANCED Master Threat Model (Large Dataset + Ensemble)")
    
    metrics = model.train_complete_model()
    model.save_model()
    
    # Demo
    test_inputs = [
        "GET /search?q=hello",
        "' OR 1=1--",
        "<script>stealCookies()</script>",
        "http://169.254.169.254/",
        "../../../etc/shadow"
    ]
    
    print("\n🎯 Demo Predictions:")
    for inp in test_inputs:
        result = model.predict_threat(inp)
        status = "🚨 MALICIOUS" if result['is_malicious'] else "✅ NORMAL"
        print(f"{status} | {result['prediction']} | {result['confidence']:.3f} | {inp[:40]}...")

    return model

if __name__ == "__main__":
    train_and_save_enhanced_model()