import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
import pickle
import json
import logging
from datetime import datetime
import os
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - ANOMALY_DETECTOR - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AdvancedAnomalyDetector:
    def __init__(self):
        self.isolation_forest = None
        self.dbscan = None
        self.one_class_svm = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.model_path = self.get_model_path()
        
    def get_model_path(self):
        """Get the path for saving/loading models"""
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        return os.path.join(base_dir, 'models', 'anomaly_model.pkl')
    
    def generate_synthetic_data(self, n_samples=1000, n_features=10, contamination=0.1):
        """Generate synthetic data for training and testing"""
        try:
            # Generate normal data
            normal_data = np.random.normal(0, 1, (n_samples, n_features))
            
            # Generate some anomalous data
            n_anomalies = int(n_samples * contamination)
            anomalies = np.random.uniform(-5, 5, (n_anomalies, n_features))
            
            # Combine data
            X = np.vstack([normal_data, anomalies])
            y = np.hstack([np.zeros(n_samples), np.ones(n_anomalies)])
            
            # Shuffle the data
            indices = np.random.permutation(len(X))
            X = X[indices]
            y = y[indices]
            
            logger.info(f"✅ Generated synthetic data: {X.shape[0]} samples, {X.shape[1]} features")
            return X, y
            
        except Exception as e:
            logger.error(f"❌ Error generating synthetic data: {e}")
            return None, None
    
    def train_models(self, X=None, y=None):
        """Train multiple anomaly detection models"""
        try:
            if X is None or y is None:
                X, y = self.generate_synthetic_data()
                if X is None:
                    return False
            
            # Scale the data
            X_scaled = self.scaler.fit_transform(X)
            
            # Train Isolation Forest
            self.isolation_forest = IsolationForest(
                contamination=0.1, 
                random_state=42,
                n_estimators=100
            )
            self.isolation_forest.fit(X_scaled)
            
            # Train DBSCAN
            self.dbscan = DBSCAN(eps=0.5, min_samples=10)
            self.dbscan.fit(X_scaled)
            
            # Train One-Class SVM
            self.one_class_svm = OneClassSVM(nu=0.1, kernel='rbf', gamma=0.1)
            self.one_class_svm.fit(X_scaled)
            
            self.is_trained = True
            logger.info("✅ All anomaly detection models trained successfully")
            
            # Save models
            self.save_models()
            return True
            
        except Exception as e:
            logger.error(f"❌ Error training anomaly detection models: {e}")
            return False
    
    def detect_anomalies(self, X):
        """Detect anomalies using ensemble approach"""
        try:
            if not self.is_trained:
                logger.warning("⚠️ Models not trained. Training with synthetic data...")
                if not self.train_models():
                    return None
            
            X_scaled = self.scaler.transform(X)
            
            # Get predictions from all models
            if_anomalies = self.isolation_forest.predict(X_scaled)
            dbscan_anomalies = self.dbscan.fit_predict(X_scaled)
            svm_anomalies = self.one_class_svm.predict(X_scaled)
            
            # Convert to binary (1 = anomaly, 0 = normal)
            if_anomalies_binary = [1 if x == -1 else 0 for x in if_anomalies]
            dbscan_anomalies_binary = [1 if x == -1 else 0 for x in dbscan_anomalies]
            svm_anomalies_binary = [1 if x == -1 else 0 for x in svm_anomalies]
            
            # Ensemble voting
            ensemble_predictions = []
            confidence_scores = []
            
            for i in range(len(X)):
                votes = if_anomalies_binary[i] + dbscan_anomalies_binary[i] + svm_anomalies_binary[i]
                is_anomaly = 1 if votes >= 2 else 0
                confidence = votes / 3.0
                
                ensemble_predictions.append(is_anomaly)
                confidence_scores.append(confidence)
            
            results = {
                'predictions': ensemble_predictions,
                'confidence_scores': confidence_scores,
                'isolation_forest': if_anomalies_binary,
                'dbscan': dbscan_anomalies_binary,
                'one_class_svm': svm_anomalies_binary
            }
            
            logger.info(f"✅ Anomaly detection completed: {sum(ensemble_predictions)} anomalies found")
            return results
            
        except Exception as e:
            logger.error(f"❌ Error detecting anomalies: {e}")
            return None
    
    def save_models(self):
        """Save trained models to disk"""
        try:
            models_data = {
                'isolation_forest': self.isolation_forest,
                'dbscan': self.dbscan,
                'one_class_svm': self.one_class_svm,
                'scaler': self.scaler,
                'is_trained': self.is_trained,
                'timestamp': datetime.now().isoformat()
            }
            
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            with open(self.model_path, 'wb') as f:
                pickle.dump(models_data, f)
            
            logger.info(f"✅ Anomaly detection models saved to: {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error saving models: {e}")
            return False
    
    def load_models(self):
        """Load trained models from disk"""
        try:
            if not os.path.exists(self.model_path):
                logger.warning("⚠️ No saved models found. Need to train first.")
                return False
            
            with open(self.model_path, 'rb') as f:
                models_data = pickle.load(f)
            
            self.isolation_forest = models_data['isolation_forest']
            self.dbscan = models_data['dbscan']
            self.one_class_svm = models_data['one_class_svm']
            self.scaler = models_data['scaler']
            self.is_trained = models_data['is_trained']
            
            logger.info("✅ Anomaly detection models loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error loading models: {e}")
            return False
    
    def generate_report(self, X, results):
        """Generate comprehensive anomaly detection report"""
        try:
            if results is None:
                return None
            
            n_anomalies = sum(results['predictions'])
            total_samples = len(results['predictions'])
            anomaly_percentage = (n_anomalies / total_samples) * 100
            
            # Calculate model agreement
            agreements = []
            for i in range(total_samples):
                models_agree = (
                    results['isolation_forest'][i] == 
                    results['dbscan'][i] == 
                    results['one_class_svm'][i]
                )
                agreements.append(models_agree)
            
            agreement_rate = (sum(agreements) / total_samples) * 100
            
            report = {
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "Anomaly Detection",
                "summary": {
                    "total_samples": total_samples,
                    "anomalies_detected": n_anomalies,
                    "anomaly_percentage": round(anomaly_percentage, 2),
                    "model_agreement_rate": round(agreement_rate, 2),
                    "average_confidence": round(np.mean(results['confidence_scores']), 3)
                },
                "model_performance": {
                    "isolation_forest_anomalies": sum(results['isolation_forest']),
                    "dbscan_anomalies": sum(results['dbscan']),
                    "svm_anomalies": sum(results['one_class_svm']),
                    "models_used": ["Isolation Forest", "DBSCAN", "One-Class SVM"]
                },
                "details": {
                    "feature_count": X.shape[1] if len(X.shape) > 1 else 1,
                    "models_trained": self.is_trained,
                    "recommendations": [
                        "Investigate high-confidence anomalies first",
                        "Review model agreement for reliable detection",
                        "Retrain models with new data periodically"
                    ]
                }
            }
            
            # Save report
            reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
            os.makedirs(reports_dir, exist_ok=True)
            
            report_path = os.path.join(reports_dir, 'anomaly_detection_report.json')
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"📊 Anomaly detection report generated: {report_path}")
            return report
            
        except Exception as e:
            logger.error(f"❌ Error generating report: {e}")
            return None

def main():
    """Main function for testing the anomaly detector"""
    try:
        logger.info("🚀 Starting Advanced Anomaly Detection System")
        
        # Initialize detector
        detector = AdvancedAnomalyDetector()
        
        # Try to load existing models
        if not detector.load_models():
            logger.info("🔄 Training new anomaly detection models...")
            if not detector.train_models():
                logger.error("❌ Failed to train models")
                return
        
        # Generate test data
        test_data, _ = detector.generate_synthetic_data(n_samples=200, contamination=0.15)
        if test_data is None:
            logger.error("❌ Failed to generate test data")
            return
        
        # Detect anomalies
        results = detector.detect_anomalies(test_data)
        if results is None:
            logger.error("❌ Anomaly detection failed")
            return
        
        # Generate report
        report = detector.generate_report(test_data, results)
        if report:
            logger.info(f"✅ Anomaly Detection Completed Successfully!")
            logger.info(f"📈 Anomalies detected: {report['summary']['anomalies_detected']}/{report['summary']['total_samples']}")
            logger.info(f"📊 Anomaly percentage: {report['summary']['anomaly_percentage']}%")
        else:
            logger.error("❌ Failed to generate report")
        
    except Exception as e:
        logger.error(f"❌ Anomaly detection system failed: {e}")

if __name__ == "__main__":
    main()