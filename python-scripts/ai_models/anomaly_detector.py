import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import seaborn as sns
import json
import logging
from datetime import datetime

class AnomalyDetector:
    def __init__(self):
        self.logger = self.setup_logging()
        self.model = None
        self.scaler = None
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - ANOMALY_DETECTOR - %(levelname)s - %(message)s'
        )
        return logging.getLogger(__name__)
    
    def generate_traffic_data(self):
        """Generate simulated network traffic data"""
        np.random.seed(42)
        
        # Normal traffic patterns
        normal_traffic = {
            'request_size': np.random.normal(1500, 300, 1000),
            'response_time': np.random.normal(0.5, 0.2, 1000),
            'requests_per_minute': np.random.poisson(10, 1000),
            'error_rate': np.random.beta(2, 50, 1000),  # Low error rate
            'unique_endpoints': np.random.randint(5, 20, 1000)
        }
        
        # Attack traffic patterns
        attack_traffic = {
            'request_size': np.random.normal(5000, 1000, 50),  # Larger requests
            'response_time': np.random.normal(2.0, 1.0, 50),   # Slower responses
            'requests_per_minute': np.random.poisson(100, 50), # High rate
            'error_rate': np.random.beta(10, 5, 50),          # High error rate
            'unique_endpoints': np.random.randint(1, 5, 50)    # Few endpoints
        }
        
        normal_df = pd.DataFrame(normal_traffic)
        normal_df['label'] = 'normal'
        normal_df['is_attack'] = 0
        
        attack_df = pd.DataFrame(attack_traffic)
        attack_df['label'] = 'attack'
        attack_df['is_attack'] = 1
        
        combined_df = pd.concat([normal_df, attack_df], ignore_index=True)
        
        return combined_df
    
    def train_anomaly_detection(self):
        """Train isolation forest for anomaly detection"""
        self.logger.info("🤖 Training Anomaly Detection Model")
        
        # Generate data
        data = self.generate_traffic_data()
        
        # Prepare features
        feature_columns = ['request_size', 'response_time', 'requests_per_minute', 'error_rate', 'unique_endpoints']
        X = data[feature_columns]
        
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=0.05,  # Expected proportion of anomalies
            random_state=42,
            n_estimators=100
        )
        
        # Fit the model
        data['anomaly_score'] = self.model.fit_predict(X_scaled)
        data['anomaly'] = data['anomaly_score'] == -1
        
        # Calculate performance
        true_positives = ((data['anomaly'] == True) & (data['is_attack'] == 1)).sum()
        false_positives = ((data['anomaly'] == True) & (data['is_attack'] == 0)).sum()
        actual_attacks = (data['is_attack'] == 1).sum()
        
        detection_rate = true_positives / actual_attacks if actual_attacks > 0 else 0
        false_positive_rate = false_positives / (data['is_attack'] == 0).sum()
        
        self.logger.info(f"✅ Anomaly Detection Model Trained")
        self.logger.info(f"   Detection Rate: {detection_rate:.3f}")
        self.logger.info(f"   False Positive Rate: {false_positive_rate:.3f}")
        
        return data, detection_rate, false_positive_rate
    
    def visualize_anomalies(self, data):
        """Create visualization of detected anomalies"""
        self.logger.info("📊 Creating Anomaly Visualization")
        
        # Use PCA for visualization
        feature_columns = ['request_size', 'response_time', 'requests_per_minute', 'error_rate', 'unique_endpoints']
        X = data[feature_columns]
        X_scaled = self.scaler.transform(X)
        
        pca = PCA(n_components=2)
        X_pca = pca.fit_transform(X_scaled)
        
        data['pca1'] = X_pca[:, 0]
        data['pca2'] = X_pca[:, 1]
        
        # Create plot
        plt.figure(figsize=(12, 8))
        
        # Plot normal points
        normal_data = data[data['label'] == 'normal']
        plt.scatter(normal_data['pca1'], normal_data['pca2'], 
                   c='green', alpha=0.6, label='Normal', s=30)
        
        # Plot attack points
        attack_data = data[data['label'] == 'attack']
        plt.scatter(attack_data['pca1'], attack_data['pca2'], 
                   c='red', alpha=0.8, label='Attack', s=50, marker='x')
        
        # Plot detected anomalies
        anomalies = data[data['anomaly'] == True]
        plt.scatter(anomalies['pca1'], anomalies['pca2'],
                   facecolors='none', edgecolors='orange', 
                   s=200, linewidth=2, label='Detected Anomalies')
        
        plt.xlabel('Principal Component 1')
        plt.ylabel('Principal Component 2')
        plt.title('Anomaly Detection in Network Traffic\n(Isolation Forest)')
        plt.legend()
        plt.grid(True, alpha=0.3)
        
        # Save plot
        plt.savefig('../reports/anomaly_detection_plot.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        self.logger.info("✅ Anomaly visualization saved")
    
    def generate_anomaly_report(self):
        """Generate comprehensive anomaly detection report"""
        self.logger.info("📈 Generating Anomaly Detection Report")
        
        # Train model and get results
        data, detection_rate, false_positive_rate = self.train_anomaly_detection()
        
        # Create visualization
        self.visualize_anomalies(data)
        
        # Analyze feature importance
        feature_columns = ['request_size', 'response_time', 'requests_per_minute', 'error_rate', 'unique_endpoints']
        feature_importance = {}
        
        for feature in feature_columns:
            # Simple correlation with anomaly scores
            correlation = data[feature].corr(data['anomaly'].astype(int))
            feature_importance[feature] = abs(correlation)
        
        # Generate report
        report = {
            'timestamp': datetime.now().isoformat(),
            'model_performance': {
                'detection_rate': detection_rate,
                'false_positive_rate': false_positive_rate,
                'model_type': 'Isolation Forest',
                'contamination': 0.05
            },
            'feature_analysis': feature_importance,
            'anomaly_statistics': {
                'total_samples': len(data),
                'actual_attacks': (data['is_attack'] == 1).sum(),
                'detected_anomalies': data['anomaly'].sum(),
                'true_positives': ((data['anomaly'] == True) & (data['is_attack'] == 1)).sum(),
                'false_positives': ((data['anomaly'] == True) & (data['is_attack'] == 0)).sum()
            },
            'threat_hunting_insights': [
                "High request rates combined with high error rates are strong attack indicators",
                "Unusual request sizes may indicate data exfiltration attempts",
                "Consistent access to few endpoints might indicate targeted attacks",
                "Response time anomalies can reveal resource exhaustion attacks"
            ],
            'ai_recommendations': [
                "Implement real-time anomaly scoring for all network traffic",
                "Use ensemble methods for improved detection accuracy",
                "Continuously retrain models with new attack patterns",
                "Combine signature-based and anomaly-based detection"
            ]
        }
        
        with open('../reports/anomaly_detection_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info("✅ Anomaly Detection Report Generated")
        
        # Print summary
        print(f"\n🔍 ANOMALY DETECTION SUMMARY")
        print("=" * 50)
        print(f"Detection Rate: {detection_rate:.3f}")
        print(f"False Positive Rate: {false_positive_rate:.3f}")
        print(f"True Positives: {report['anomaly_statistics']['true_positives']}")
        print(f"False Positives: {report['anomaly_statistics']['false_positives']}")
        print(f"\nTop Features for Detection:")
        for feature, importance in sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:3]:
            print(f"  {feature}: {importance:.3f}")
        
        return report

if __name__ == "__main__":
    detector = AnomalyDetector()
    detector.generate_anomaly_report()