import pickle
import json
import logging
from datetime import datetime
import pandas as pd

class RealTimeThreatDetector:
    def __init__(self, model_path='../models/master_threat_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.setup_logging()
        self.load_model()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - REALTIME_DETECTOR - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def load_model(self):
        """Load the pre-trained model"""
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.text_model = model_data['text_model']
            self.vectorizer = model_data['vectorizer']
            self.anomaly_model = model_data['anomaly_model']
            self.scaler = model_data['scaler']
            
            self.logger.info("✅ Pre-trained model loaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Error loading model: {e}")
            return False
    
    def analyze_text(self, input_text):
        """Analyze text for threats in real-time"""
        try:
            # Transform input
            features = self.vectorizer.transform([input_text])
            
            # Get prediction
            prediction = self.text_model.predict(features)[0]
            probabilities = self.text_model.predict_proba(features)[0]
            confidence = max(probabilities)
            
            # Threat level mapping
            threat_levels = {
                'normal': 'LOW',
                'sql_injection': 'CRITICAL',
                'xss': 'HIGH',
                'path_traversal': 'HIGH',
                'command_injection': 'CRITICAL'
            }
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'input': input_text,
                'prediction': prediction,
                'confidence': float(confidence),
                'threat_level': threat_levels.get(prediction, 'MEDIUM'),
                'is_malicious': prediction != 'normal',
                'response_time_ms': 0  # Can be calculated
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing text: {e}")
            return None
    
    def analyze_traffic(self, traffic_features):
        """Analyze network traffic for anomalies"""
        try:
            feature_columns = ['request_size', 'response_time', 'requests_per_minute', 
                             'error_rate', 'unique_endpoints', 'payload_length']
            
            # Ensure all features are present
            features_array = np.array([[traffic_features.get(col, 0) for col in feature_columns]])
            
            # Scale features
            features_scaled = self.scaler.transform(features_array)
            
            # Detect anomaly
            anomaly_score = self.anomaly_model.decision_function(features_scaled)[0]
            is_anomaly = self.anomaly_model.predict(features_scaled)[0] == -1
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'is_anomaly': bool(is_anomaly),
                'anomaly_score': float(anomaly_score),
                'anomaly_confidence': float(1 / (1 + np.exp(-anomaly_score))),
                'threat_level': 'HIGH' if is_anomaly else 'LOW'
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing traffic: {e}")
            return None
    
    def process_attack_data(self, attack_data):
        """Process actual attack data from reports"""
        self.logger.info("🔍 Processing Actual Attack Data")
        
        results = []
        
        # Load SQL injection attacks
        try:
            with open('../reports/sql_injection_report.json', 'r') as f:
                sqli_data = json.load(f)
                for attack in sqli_data.get('detailed_results', []):
                    if 'payload' in attack:
                        analysis = self.analyze_text(attack['payload'])
                        if analysis:
                            analysis['source'] = 'sql_injection_report'
                            results.append(analysis)
        except FileNotFoundError:
            self.logger.warning("SQL Injection report not found")
        
        # Load XSS attacks
        try:
            with open('../reports/xss_attack_report.json', 'r') as f:
                xss_data = json.load(f)
                for attack in xss_data.get('detailed_results', []):
                    if 'payload' in attack:
                        analysis = self.analyze_text(attack['payload'])
                        if analysis:
                            analysis['source'] = 'xss_report'
                            results.append(analysis)
        except FileNotFoundError:
            self.logger.warning("XSS report not found")
        
        return results
    
    def generate_realtime_report(self):
        """Generate real-time threat analysis report"""
        self.logger.info("📊 Generating Real-time Threat Analysis")
        
        # Process actual attack data
        attack_analyses = self.process_attack_data()
        
        # Test with sample inputs
        test_inputs = [
            "normal user login",
            "SELECT * FROM users WHERE 1=1",
            "<script>document.location='http://evil.com'</script>",
            "../../../etc/passwd",
            "normal product search",
            "'; DROP TABLE products--",
            "<img src=x onerror=stealCookies()>"
        ]
        
        test_results = []
        for input_text in test_inputs:
            result = self.analyze_text(input_text)
            if result:
                test_results.append(result)
        
        report = {
            'generation_time': datetime.now().isoformat(),
            'model_status': 'ACTIVE',
            'attack_analysis_summary': {
                'total_attacks_processed': len(attack_analyses),
                'correctly_identified': len([a for a in attack_analyses if a['is_malicious']]),
                'false_negatives': len([a for a in attack_analyses if not a['is_malicious']])
            },
            'real_time_test_results': test_results,
            'system_recommendations': [
                "Deploy model in web application firewall",
                "Monitor for high-confidence threat predictions",
                "Implement auto-block for CRITICAL threats",
                "Log all threat detections for analysis"
            ]
        }
        
        # Save report
        with open('../reports/realtime_threat_analysis.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info("✅ Real-time threat analysis completed")
        
        # Print summary
        print(f"\n🎯 REAL-TIME THREAT DETECTION SUMMARY")
        print("=" * 60)
        print(f"Attacks Processed: {report['attack_analysis_summary']['total_attacks_processed']}")
        print(f"Correctly Identified: {report['attack_analysis_summary']['correctly_identified']}")
        print(f"False Negatives: {report['attack_analysis_summary']['false_negatives']}")
        
        print(f"\n📊 Real-time Test Results:")
        for result in test_results[:5]:  # Show first 5
            status = "🚨 BLOCK" if result['is_malicious'] else "✅ ALLOW"
            print(f"{status}: {result['input'][:40]}... -> {result['prediction']} (conf: {result['confidence']:.3f})")
        
        return report

# Global detector instance for continuous use
_detector_instance = None

def get_detector():
    """Get or create detector instance (singleton pattern)"""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = RealTimeThreatDetector()
    return _detector_instance

def quick_analyze(text_input):
    """Quick analysis function for immediate use"""
    detector = get_detector()
    return detector.analyze_text(text_input)

if __name__ == "__main__":
    # Demo the real-time detector
    detector = RealTimeThreatDetector()
    detector.generate_realtime_report()