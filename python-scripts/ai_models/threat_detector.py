import pandas as pd
import numpy as np
import json
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import logging
from datetime import datetime

class ThreatDetector:
    def __init__(self):
        self.logger = self.setup_logging()
        self.model = None
        self.vectorizer = None
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - AI_DETECTOR - %(levelname)s - %(message)s'
        )
        return logging.getLogger(__name__)
    
    def load_attack_data(self):
        """Load attack data from generated reports"""
        attack_data = []
        
        # SQL Injection patterns
        sql_patterns = [
            "OR 1=1", "UNION SELECT", "DROP TABLE", "';", "--", 
            "/*", "*/", "xp_", "EXEC", "WAITFOR DELAY"
        ]
        
        # XSS patterns
        xss_patterns = [
            "<script>", "</script>", "onerror=", "onload=", "onclick=",
            "javascript:", "alert(", "document.cookie", "<iframe>"
        ]
        
        # Path traversal patterns
        path_patterns = [
            "../", "..\\", "/etc/passwd", "/etc/shadow", "win.ini",
            "system32", "boot.ini", "../../", "....//"
        ]
        
        # Normal patterns (benign)
        normal_patterns = [
            "apple", "banana", "orange", "juice", "product",
            "search", "login", "user", "password", "email"
        ]
        
        # Create labeled dataset
        for pattern in sql_patterns:
            attack_data.append({'text': pattern, 'label': 'sql_injection', 'malicious': 1})
        
        for pattern in xss_patterns:
            attack_data.append({'text': pattern, 'label': 'xss', 'malicious': 1})
        
        for pattern in path_patterns:
            attack_data.append({'text': pattern, 'label': 'path_traversal', 'malicious': 1})
        
        for pattern in normal_patterns:
            attack_data.append({'text': pattern, 'label': 'normal', 'malicious': 0})
        
        return pd.DataFrame(attack_data)
    
    def extract_features(self, texts):
        """Extract features from text using TF-IDF"""
        if self.vectorizer is None:
            self.vectorizer = TfidfVectorizer(
                max_features=1000,
                stop_words='english',
                ngram_range=(1, 2),
                analyzer='char_wb'
            )
            features = self.vectorizer.fit_transform(texts)
        else:
            features = self.vectorizer.transform(texts)
        
        return features
    
    def train_model(self):
        """Train threat detection model"""
        self.logger.info("🤖 Training Threat Detection Model")
        
        # Load data
        df = self.load_attack_data()
        
        # Extract features
        X = self.extract_features(df['text'])
        y = df['malicious']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        self.model.fit(X_train, y_train)
        
        # Evaluate
        train_score = self.model.score(X_train, y_train)
        test_score = self.model.score(X_test, y_test)
        
        self.logger.info(f"✅ Model trained - Train Accuracy: {train_score:.3f}, Test Accuracy: {test_score:.3f}")
        
        return train_score, test_score
    
    def detect_threats(self, input_text):
        """Detect threats in input text"""
        if self.model is None:
            self.train_model()
        
        features = self.extract_features([input_text])
        prediction = self.model.predict(features)[0]
        probability = self.model.predict_proba(features)[0][1]
        
        return {
            'input': input_text,
            'malicious': bool(prediction),
            'confidence': probability,
            'threat_level': 'HIGH' if probability > 0.7 else 'MEDIUM' if probability > 0.3 else 'LOW'
        }
    
    def analyze_attack_patterns(self):
        """Analyze patterns from actual attack reports"""
        self.logger.info("🔍 Analyzing Attack Patterns from Reports")
        
        patterns_analysis = {}
        
        try:
            # Analyze SQL Injection patterns
            with open('../reports/sql_injection_report.json', 'r') as f:
                sqli_data = json.load(f)
                patterns_analysis['sql_injection'] = {
                    'successful_payloads': [
                        result['payload'] for result in sqli_data.get('detailed_results', [])
                        if result.get('success')
                    ],
                    'total_attempts': len(sqli_data.get('detailed_results', [])),
                    'success_rate': sqli_data.get('summary', {}).get('success_rate', 0)
                }
        except FileNotFoundError:
            self.logger.warning("SQL Injection report not found")
        
        try:
            # Analyze XSS patterns
            with open('../reports/xss_attack_report.json', 'r') as f:
                xss_data = json.load(f)
                patterns_analysis['xss'] = {
                    'successful_payloads': [
                        result['payload'] for result in xss_data.get('detailed_results', [])
                        if result.get('vulnerable') or result.get('submission_successful')
                    ],
                    'total_attempts': len(xss_data.get('detailed_results', [])),
                    'success_rate': xss_data.get('summary', {}).get('success_rate', 0)
                }
        except FileNotFoundError:
            self.logger.warning("XSS report not found")
        
        return patterns_analysis
    
    def generate_ai_report(self):
        """Generate AI-based threat analysis report"""
        self.logger.info("📊 Generating AI Threat Analysis Report")
        
        # Train model
        train_acc, test_acc = self.train_model()
        
        # Analyze patterns
        patterns = self.analyze_attack_patterns()
        
        # Test detection on sample inputs
        test_inputs = [
            "apple juice",  # Normal
            "' OR 1=1--",   # SQL Injection
            "<script>alert('xss')</script>",  # XSS
            "../../../etc/passwd",  # Path traversal
            "normal search query",  # Normal
        ]
        
        detection_results = []
        for test_input in test_inputs:
            result = self.detect_threats(test_input)
            detection_results.append(result)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'model_performance': {
                'training_accuracy': train_acc,
                'testing_accuracy': test_acc,
                'model_type': 'Random Forest',
                'features_used': 'TF-IDF of character n-grams'
            },
            'attack_patterns_analysis': patterns,
            'real_time_detection_demo': detection_results,
            'ai_recommendations': [
                "Implement ML-based input validation",
                "Use behavioral analysis for anomaly detection",
                "Deploy ensemble methods for better accuracy",
                "Continuously update model with new attack patterns"
            ]
        }
        
        with open('../reports/ai_threat_analysis_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info("✅ AI Threat Analysis Report Generated")
        
        # Print demo results
        print(f"\n🤖 AI THREAT DETECTION DEMO")
        print("=" * 50)
        for result in detection_results:
            status = "🚨 MALICIOUS" if result['malicious'] else "✅ NORMAL"
            print(f"{status}: {result['input']}")
            print(f"   Confidence: {result['confidence']:.3f} | Threat Level: {result['threat_level']}")
        
        return report

if __name__ == "__main__":
    detector = ThreatDetector()
    detector.generate_ai_report()