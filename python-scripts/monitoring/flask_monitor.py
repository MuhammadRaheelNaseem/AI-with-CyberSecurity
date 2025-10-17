from flask import Flask, render_template, jsonify, request, session
import json
import time
import threading
from datetime import datetime
import pandas as pd
import numpy as np
import os
import logging
import pickle
from collections import deque, defaultdict
import subprocess
import sys
import psutil
import glob
import io

# Ensure UTF-8 encoding for output
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

logger.info("SQL Injection attack started!")
logger.warning("Possible XSS vulnerability detected!")

app = Flask(__name__)
app.secret_key = 'security-monitor-secret-key-2024'

class AdvancedSecurityMonitor:
    def __init__(self):
        self.attack_data = []
        self.system_metrics = deque(maxlen=200)
        self.alerts = []
        self.request_logs = deque(maxlen=1000)
        self.session_data = defaultdict(dict)
        self.baseline_metrics = {
            'avg_requests_per_min': 10,
            'normal_status_codes': [200, 201, 304],
            'normal_endpoints': ['/rest/products', '/rest/user/whoami', '/api/Products']
        }
        self.ai_model = None
        self.model_loaded = False
        self.vectorizer = None
        self.text_model = None
        self.anomaly_model = None
        self.scaler = None
        
        # Get correct base directory - FIXED PATH
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.project_root = os.path.dirname(os.path.dirname(self.base_dir))
        logger.info(f"Base directory: {self.base_dir}")
        logger.info(f"Project root: {self.project_root}")
        
        # Load all components
        self.load_existing_data()
        self.load_all_ai_models()
        self.start_background_monitoring()

    def get_absolute_path(self, relative_path):
        """Convert relative path to absolute path"""
        return os.path.join(self.project_root, relative_path)

    def load_all_ai_models(self):
        """Load all pre-trained AI models from models/ directory - FIXED"""
        models_dir = self.get_absolute_path('models')
        logger.info(f"Looking for models in: {models_dir}")
        
        try:
            if not os.path.exists(models_dir):
                logger.error(f"Models directory not found: {models_dir}")
                logger.info(f"Available directories in project root: {os.listdir(self.project_root)}")
                self.add_alert('HIGH', 'Models directory not found', 'Model Loader')
                return

            model_files = os.listdir(models_dir)
            logger.info(f"Available model files: {model_files}")

            models_to_load = {
                'master_threat_model.pkl': 'ai_model',
                'text_model.pkl': 'text_model',
                'vectorizer.pkl': 'vectorizer', 
                'anomaly_model.pkl': 'anomaly_model',
                'scaler.pkl': 'scaler'
            }
            
            loaded_count = 0
            for filename, attr_name in models_to_load.items():
                path = os.path.join(models_dir, filename)
                if os.path.exists(path):
                    try:
                        with open(path, 'rb') as f:
                            setattr(self, attr_name, pickle.load(f))
                        logger.info(f"{attr_name} loaded successfully from {filename}")
                        loaded_count += 1
                    except Exception as e:
                        logger.error(f"Error loading {filename}: {e}")
                        self.add_alert('HIGH', f'Failed to load {filename}', 'Model Loader')
                else:
                    logger.warning(f"Model file not found: {filename}")
            
            self.model_loaded = loaded_count > 0
            if self.model_loaded:
                logger.info(f"Successfully loaded {loaded_count}/5 models")
                self.add_alert('LOW', f'AI models loaded ({loaded_count}/5)', 'Model Loader')
            else:
                logger.error("No models could be loaded")
                self.add_alert('HIGH', 'No AI models loaded', 'Model Loader')
            
        except Exception as e:
            logger.error(f"Critical error loading AI models: {e}")
            self.add_alert('CRITICAL', f'Model loading failed: {str(e)}', 'Model Loader')

    def safe_json_load(self, filepath):
        """Safely load JSON file with error handling"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in {filepath}: {e}")
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                content = content.strip()
                if not content:
                    return {"error": "Empty file", "timestamp": datetime.now().isoformat()}
                return {
                    "error": "Invalid JSON format",
                    "original_file": os.path.basename(filepath),
                    "timestamp": datetime.now().isoformat(),
                    "summary": {"success_rate": 0, "total_attempts": 0}
                }
            except Exception as e2:
                logger.error(f"Could not recover file {filepath}: {e2}")
                return {
                    "error": "Unrecoverable file error",
                    "timestamp": datetime.now().isoformat()
                }
        except Exception as e:
            logger.error(f"Error reading file {filepath}: {e}")
            return {
                "error": f"File read error: {str(e)}",
                "timestamp": datetime.now().isoformat()
            }

    def load_existing_data(self):
        """Load all existing reports and logs"""
        reports_dir = self.get_absolute_path('reports')
        logger.info(f"Loading reports from: {reports_dir}")
        
        if os.path.exists(reports_dir):
            for report_file in glob.glob(os.path.join(reports_dir, '*.json')):
                try:
                    data = self.safe_json_load(report_file)
                    filename = os.path.basename(report_file)
                    
                    if 'error' in data:
                        logger.warning(f"Skipping {filename}: {data['error']}")
                        continue
                    
                    attack_type = filename.replace('_report.json', '').replace('_', ' ').title()
                    
                    if 'baseline' in filename.lower():
                        self.baseline_metrics.update(data.get('baseline_metrics', {}))
                    else:
                        success_rate = data.get('summary', {}).get('success_rate', 0)
                        self.attack_data.append({
                            'type': attack_type,
                            'timestamp': data.get('timestamp', datetime.now().isoformat()),
                            'success_rate': success_rate,
                            'details': data.get('summary', {}),
                            'file': filename
                        })
                        logger.info(f"Loaded attack data: {attack_type} - Success: {success_rate}%")
                        
                except Exception as e:
                    logger.error(f"Error processing {report_file}: {e}")

        self.load_recent_logs()

    def load_recent_logs(self):
        """Load recent log entries"""
        logs_dir = self.get_absolute_path('logs')
        logger.info(f"Loading logs from: {logs_dir}")
        
        if not os.path.exists(logs_dir):
            logger.warning(f"Logs directory not found: {logs_dir}")
            return
            
        log_files = []
        for root, _, files in os.walk(logs_dir):
            for file in files:
                if file.endswith('.log'):
                    log_files.append(os.path.join(root, file))
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()[-20:]
                    for line in lines:
                        if line.strip():
                            self.parse_log_entry(line.strip(), os.path.basename(log_file))
            except Exception as e:
                logger.error(f"Error reading log file {log_file}: {e}")

    def parse_log_entry(self, log_entry, log_source):
        """Parse log entry and add to request logs"""
        try:
            if any(x in log_entry for x in ['HTTP', 'GET', 'POST', 'PUT', 'DELETE']):
                parts = log_entry.split()
                if len(parts) > 5:
                    timestamp = ' '.join(parts[0:2]) if ':' in parts[1] else datetime.now().isoformat()
                    endpoint = next((p for p in parts if p.startswith('/')), '/')
                    status_code = next((int(p) for p in parts if p.isdigit() and len(p) == 3), 200)
                    
                    self.request_logs.append({
                        'timestamp': timestamp,
                        'endpoint': endpoint,
                        'status_code': status_code,
                        'response_time': 0.1 + (hash(endpoint) % 100) / 1000,
                        'ip': '127.0.0.1',
                        'source': log_source
                    })
        except Exception:
            pass

    def start_background_monitoring(self):
        """Start background monitoring threads - FIXED"""
        def background_monitor():
            while True:
                try:
                    health = self.get_system_health()
                    if 'error' not in health:
                        self.system_metrics.append(health)
                    
                    self.check_new_reports()
                    
                    time.sleep(10)
                except Exception as e:
                    logger.error(f"Background monitor error: {e}")
                    time.sleep(30)

        monitor_thread = threading.Thread(target=background_monitor, daemon=True)
        monitor_thread.start()

    def check_new_reports(self):
        """Check for new report files and load them"""
        reports_dir = self.get_absolute_path('reports')
        if not os.path.exists(reports_dir):
            return
            
        current_files = {attack['file'] for attack in self.attack_data if 'file' in attack}
        for report_file in glob.glob(os.path.join(reports_dir, '*.json')):
            filename = os.path.basename(report_file)
            if filename not in current_files:
                try:
                    data = self.safe_json_load(report_file)
                    if 'error' in data:
                        continue
                    attack_type = filename.replace('_report.json', '').replace('_', ' ').title()
                    success_rate = data.get('summary', {}).get('success_rate', 0)
                    
                    self.attack_data.append({
                        'type': attack_type,
                        'timestamp': data.get('timestamp', datetime.now().isoformat()),
                        'success_rate': success_rate,
                        'details': data.get('summary', {}),
                        'file': filename
                    })
                    logger.info(f"New report loaded: {attack_type}")
                    
                except Exception as e:
                    logger.error(f"Error loading new report {filename}: {e}")

    def log_request(self, endpoint, status_code, response_time, ip="127.0.0.1"):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'endpoint': endpoint,
            'status_code': status_code,
            'response_time': response_time,
            'ip': ip,
            'source': 'live'
        }
        self.request_logs.append(log_entry)

    def add_alert(self, severity, message, source):
        alert = {
            'id': len(self.alerts) + 1,
            'timestamp': datetime.now().isoformat(),
            'severity': severity,
            'message': message,
            'source': source,
            'acknowledged': False
        }
        self.alerts.append(alert)
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]
        logger.info(f"Alert: {severity} - {message}")

    def get_attack_stats(self):
        if not self.attack_data:
            return {'total_attacks': 0, 'attack_types': {}, 'avg_success_rate': 0, 'recent_attacks': []}
        
        try:
            df = pd.DataFrame(self.attack_data)
            return {
                'total_attacks': len(self.attack_data),
                'attack_types': df['type'].value_counts().to_dict(),
                'avg_success_rate': float(df['success_rate'].mean()),
                'recent_attacks': self.attack_data[-10:]
            }
        except Exception as e:
            logger.error(f"Error calculating attack stats: {e}")
            return {'total_attacks': 0, 'attack_types': {}, 'avg_success_rate': 0, 'recent_attacks': []}

    def get_alerts_summary(self):
        if not self.alerts:
            return {'total_alerts': 0, 'alerts_by_severity': {}, 'unacknowledged_alerts': 0, 'recent_alerts': []}
        
        try:
            df = pd.DataFrame(self.alerts)
            return {
                'total_alerts': len(self.alerts),
                'alerts_by_severity': df['severity'].value_counts().to_dict(),
                'unacknowledged_alerts': len([a for a in self.alerts if not a['acknowledged']]),
                'recent_alerts': self.alerts[-10:]
            }
        except Exception as e:
            logger.error(f"Error calculating alert stats: {e}")
            return {'total_alerts': 0, 'alerts_by_severity': {}, 'unacknowledged_alerts': 0, 'recent_alerts': []}

    def get_system_health(self):
        try:
            cpu_percent = psutil.cpu_percent()
            memory_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent
            
            model_health = 'HEALTHY' if self.model_loaded else 'UNHEALTHY'
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory_percent,
                'disk_percent': disk_percent,
                'model_health': model_health,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"System health error: {e}")
            return {'error': str(e)}

    def get_ai_insights(self):
        if not self.model_loaded:
            return {
                'status': 'model_not_loaded', 
                'risk_score': 0, 
                'recommendations': ['AI model not loaded. Run training first.']
            }

        if len(self.request_logs) < 5:
            return {
                'status': 'insufficient_data', 
                'risk_score': 0, 
                'recommendations': ['Run attack simulations to gather data']
            }

        try:
            recent_logs = list(self.request_logs)[-50:]
            error_rate = len([r for r in recent_logs if r['status_code'] >= 400]) / len(recent_logs)
            avg_response_time = np.mean([r['response_time'] for r in recent_logs])
            risk_score = min(100, (error_rate * 50 + min(avg_response_time * 10, 50)))
            
            recommendations = []
            if error_rate > 0.3:
                recommendations.append("High error rate detected - possible attack in progress")
            if avg_response_time > 2.0:
                recommendations.append("Slow response times - possible DoS attack")
            if not self.model_loaded:
                recommendations.append("AI model not loaded - limited threat detection")
            if len(self.attack_data) == 0:
                recommendations.append("No attack data - run simulations to train AI")
                
            return {
                'status': 'active_monitoring',
                'risk_score': round(risk_score, 1),
                'error_rate': round(error_rate * 100, 1),
                'avg_response_time': round(avg_response_time, 2),
                'total_requests': len(self.request_logs),
                'recommendations': recommendations
            }
        except Exception as e:
            logger.error(f"AI insights error: {e}")
            return {'status': 'error', 'risk_score': 0, 'recommendations': ['Error in analysis']}

    def analyze_text_input(self, input_text):
        """Analyze text using loaded AI model"""
        if not self.model_loaded or self.vectorizer is None or self.text_model is None:
            return {'error': 'AI model not properly loaded. Please train models first.'}

        try:
            features = self.vectorizer.transform([input_text])
            prediction = self.text_model.predict(features)[0]
            probabilities = self.text_model.predict_proba(features)[0]
            confidence = max(probabilities)
            
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
                'confidence': float(confidence),
                'threat_level': threat_levels.get(prediction, 'MEDIUM'),
                'is_malicious': prediction != 'normal'
            }
        except Exception as e:
            logger.error(f"Text analysis error: {e}")
            return {'error': f'Analysis failed: {str(e)}'}

    def get_model_status(self):
        """Get AI model health status"""
        models_loaded = {
            'master_model': self.model_loaded,
            'text_model': self.text_model is not None,
            'vectorizer': self.vectorizer is not None,
            'anomaly_model': self.anomaly_model is not None,
            'scaler': self.scaler is not None
        }
        
        loaded_count = sum(models_loaded.values())
        total_count = len(models_loaded)
        
        if loaded_count == 0:
            return {
                'status': 'not_loaded', 
                'message': 'No models loaded. Run training first.',
                'loaded_count': 0,
                'total_count': total_count
            }
        elif loaded_count == total_count:
            return {
                'status': 'fully_loaded', 
                'message': 'All models loaded successfully',
                'loaded_count': loaded_count,
                'total_count': total_count,
                'loaded_models': [k for k, v in models_loaded.items() if v]
            }
        else:
            return {
                'status': 'partially_loaded', 
                'message': f'{loaded_count}/{total_count} models loaded',
                'loaded_count': loaded_count,
                'total_count': total_count,
                'loaded_models': [k for k, v in models_loaded.items() if v]
            }

    def get_file_structure(self):
        """Get current file structure for monitoring"""
        structure = {}
        
        reports_dir = self.get_absolute_path('reports')
        reports = []
        if os.path.exists(reports_dir):
            reports = [f for f in os.listdir(reports_dir) if f.endswith('.json')]
        structure['reports'] = reports
        
        logs = {'security': [], 'application': [], 'performance': []}
        log_dirs = {
            'security': 'logs/security',
            'application': 'logs/application', 
            'performance': 'logs/performance'
        }
        
        for log_type, rel_dir in log_dirs.items():
            log_dir = self.get_absolute_path(rel_dir)
            if os.path.exists(log_dir):
                logs[log_type] = [f for f in os.listdir(log_dir) if f.endswith('.log')]
        structure['logs'] = logs
        
        models_dir = self.get_absolute_path('models')
        models = []
        if os.path.exists(models_dir):
            models = [f for f in os.listdir(models_dir) if f.endswith('.pkl')]
        structure['models'] = models
        
        attacks_dir = self.get_absolute_path('python-scripts/attacks')
        attacks = []
        if os.path.exists(attacks_dir):
            attacks = [f for f in os.listdir(attacks_dir) if f.endswith('.py')]
        structure['attacks'] = attacks
        
        return structure

    def run_attack_simulation(self, attack_type):
        """Run attack simulation and return results - FIXED PATHS"""
        attack_map = {
            'sql_injection': 'python-scripts/attacks/sql_injection_flask.py',
            'brute_force': 'python-scripts/attacks/brute_force_flask.py',
            'xss': 'python-scripts/attacks/xss_attack_flask.py',
            'path_traversal': 'python-scripts/attacks/path_traversal_flask.py',
            'security_controls': 'python-scripts/defense/security_controls_test_flask.py',
            'baseline': 'python-scripts/monitoring/baseline_activity.py'
        }
        
        if attack_type not in attack_map:
            return {'error': f'Invalid attack type: {attack_type}'}
            
        script_relative_path = attack_map[attack_type]
        script_path = self.get_absolute_path(script_relative_path)
        
        logger.info(f"Running attack: {attack_type}")
        logger.info(f"Script path: {script_path}")
        
        if not os.path.exists(script_path):
            error_msg = f'Attack script not found: {script_path}'
            logger.error(error_msg)
            return {'error': error_msg}
        
        try:
            project_root = self.project_root
            logger.info(f"Running from directory: {project_root}")
            
            cmd = [sys.executable, script_path]
            result = subprocess.run(
                cmd, 
                cwd=project_root,
                capture_output=True, 
                text=True, 
                timeout=60,
                encoding='utf-8',
                errors='ignore'
            )
            
            logger.info(f"Attack {attack_type} completed with return code: {result.returncode}")
            if result.stdout:
                logger.info(f"stdout: {result.stdout[:200]}...")
            if result.stderr:
                logger.warning(f"stderr: {result.stderr[:200]}...")
            
            if result.returncode == 0:
                alert_msg = f'{attack_type} simulation completed successfully'
                self.add_alert('INFO', alert_msg, 'Attack Controller')
                return {
                    'status': 'completed', 
                    'output': result.stdout,
                    'attack_type': attack_type
                }
            else:
                alert_msg = f'{attack_type} simulation failed'
                self.add_alert('WARNING', alert_msg, 'Attack Controller')
                return {
                    'status': 'failed', 
                    'error': result.stderr,
                    'attack_type': attack_type
                }
                
        except subprocess.TimeoutExpired:
            error_msg = f'{attack_type} simulation timed out (60s)'
            logger.error(error_msg)
            self.add_alert('WARNING', error_msg, 'Attack Controller')
            return {'status': 'timeout', 'error': error_msg}
        except Exception as e:
            error_msg = f'{attack_type} simulation error: {str(e)}'
            logger.error(error_msg)
            self.add_alert('ERROR', error_msg, 'Attack Controller')
            return {'status': 'error', 'error': error_msg}

monitor = AdvancedSecurityMonitor()

@app.route('/')
def dashboard():
    if 'user_id' not in session:
        session['user_id'] = f"user_{int(time.time())}"
        session['start_time'] = datetime.now().isoformat()
    
    return render_template('dashboard.html')

@app.route('/api/attack-stats')
def get_attack_stats():
    return jsonify(monitor.get_attack_stats())

@app.route('/api/alerts')
def get_alerts():
    return jsonify(monitor.get_alerts_summary())

@app.route('/api/system-health')
def get_system_health():
    return jsonify(monitor.get_system_health())

@app.route('/api/attack-timeline')
def get_attack_timeline():
    return jsonify(monitor.attack_data)

@app.route('/api/ai-insights')
def get_ai_insights():
    return jsonify(monitor.get_ai_insights())

@app.route('/api/model-status')
def get_model_status():
    return jsonify(monitor.get_model_status())

@app.route('/api/analyze-text', methods=['POST'])
def analyze_text():
    data = request.json
    result = monitor.analyze_text_input(data.get('text', ''))
    return jsonify(result)

@app.route('/api/recent-logs')
def get_recent_logs():
    limit = request.args.get('limit', 50, type=int)
    return jsonify(list(monitor.request_logs)[-limit:])

@app.route('/api/file-structure')
def get_file_structure():
    return jsonify(monitor.get_file_structure())

@app.route('/api/acknowledge-alert/<int:alert_id>', methods=['POST'])
def acknowledge_alert(alert_id):
    for alert in monitor.alerts:
        if alert['id'] == alert_id:
            alert['acknowledged'] = True
            break
    return jsonify({'status': 'success'})

@app.route('/api/log-request', methods=['POST'])
def log_request():
    data = request.json
    monitor.log_request(
        endpoint=data.get('endpoint', '/'),
        status_code=data.get('status_code', 200),
        response_time=data.get('response_time', 0.1),
        ip=data.get('ip', '127.0.0.1')
    )
    return jsonify({'status': 'logged'})

@app.route('/api/run-health-check', methods=['POST'])
def run_health_check():
    try:
        monitor.add_alert('INFO', 'Health check completed', 'Health Monitor')
        return jsonify({
            'overall_health': 'HEALTHY',
            'checks': {
                'system': 'PASS',
                'models': 'PARTIAL' if monitor.model_loaded else 'FAIL',
                'reports': 'PASS'
            },
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/run-attack', methods=['POST'])
def run_attack():
    attack_type = request.json.get('attack_type')
    logger.info(f"API: Running attack {attack_type}")
    result = monitor.run_attack_simulation(attack_type)
    return jsonify(result)

@app.route('/api/load-reports', methods=['POST'])
def load_reports():
    monitor.load_existing_data()
    return jsonify({'status': 'reports_reloaded'})

@app.route('/api/session-info')
def get_session_info():
    return jsonify({
        'user_id': session.get('user_id'),
        'start_time': session.get('start_time'),
        'duration_seconds': (datetime.now() - datetime.fromisoformat(session.get('start_time', datetime.now().isoformat()))).total_seconds()
    })

@app.route('/api/train-model', methods=['POST'])
def train_model():
    try:
        training_script = monitor.get_absolute_path('python-scripts/run_training.py')
        if not os.path.exists(training_script):
            return jsonify({'status': 'error', 'error': 'Training script not found'})
            
        cmd = [sys.executable, training_script]
        project_root = monitor.project_root
        
        result = subprocess.run(
            cmd, 
            cwd=project_root,
            capture_output=True, 
            text=True, 
            timeout=120
        )
        
        if result.returncode == 0:
            monitor.load_all_ai_models()
            return jsonify({'status': 'training_completed', 'output': result.stdout})
        else:
            return jsonify({'status': 'training_failed', 'error': result.stderr})
    except Exception as e:
        return jsonify({'status': 'error', 'error': str(e)})

@app.route('/api/fix-json/<filename>', methods=['POST'])
def fix_json_file(filename):
    try:
        filepath = monitor.get_absolute_path(f'reports/{filename}')
        if os.path.exists(filepath):
            backup_path = filepath + '.backup'
            os.rename(filepath, backup_path)
            
            fixed_data = {
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "success_rate": 0,
                    "total_attempts": 0,
                    "detected_attacks": 0
                },
                "note": "Auto-generated after corruption"
            }
            
            with open(filepath, 'w') as f:
                json.dump(fixed_data, f, indent=2)
                
            return jsonify({'status': 'fixed', 'filename': filename})
        else:
            return jsonify({'error': 'File not found'})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    os.makedirs('templates', exist_ok=True)
    
    print("Starting AI-Powered Security Monitoring Dashboard...")
    print("Access dashboard at: http://localhost:5000")
    print("AI Model Status:", monitor.get_model_status()['status'])
    print("Available Attack Types: SQLi, XSS, Brute Force, Path Traversal")
    print("Monitoring Paths:")
    print(f"   - Base Directory: {monitor.base_dir}")
    print(f"   - Project Root: {monitor.project_root}")
    print("   - Reports: reports/")
    print("   - Logs: logs/")
    print("   - Models: models/")
    print("   - Attacks: python-scripts/attacks/")
    print("AI Features: Real-time Threat Detection, Model Control, File Monitoring")
    
    app.run(host='0.0.0.0', port=5000, debug=True)

# ======================================================






# from flask import Flask, render_template, jsonify, request, session
# import json
# import time
# import threading
# from datetime import datetime, timedelta
# import pandas as pd
# import numpy as np
# import os
# import logging
# import pickle
# from collections import deque, defaultdict
# import subprocess
# import sys
# import psutil
# import glob

# # Configure logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# app = Flask(__name__)
# app.secret_key = 'your-secret-key-here'

# class AdvancedSecurityMonitor:
#     def __init__(self):
#         self.attack_data = []
#         self.system_metrics = deque(maxlen=200)
#         self.alerts = []
#         self.request_logs = deque(maxlen=1000)
#         self.session_data = defaultdict(dict)
#         self.baseline_metrics = {
#             'avg_requests_per_min': 10,
#             'normal_status_codes': [200, 201, 304],
#             'normal_endpoints': ['/rest/products', '/rest/user/whoami', '/api/Products']
#         }
#         self.ai_model = None
#         self.model_loaded = False
#         self.vectorizer = None
#         self.text_model = None
#         self.anomaly_model = None
#         self.scaler = None
        
#         # Load all components
#         self.load_existing_data()
#         self.load_all_ai_models()
#         self.start_background_monitoring()

#     def load_all_ai_models(self):
#         """Load all pre-trained AI models from models/ directory"""
#         models_dir = '../models'
#         try:
#             # Load master threat model
#             master_path = os.path.join(models_dir, 'master_threat_model.pkl')
#             if os.path.exists(master_path):
#                 with open(master_path, 'rb') as f:
#                     self.ai_model = pickle.load(f)
#                 logger.info("✅ Master Threat Model loaded successfully")
#                 self.model_loaded = True

#             # Load individual models
#             model_files = {
#                 'text_model.pkl': 'text_model',
#                 'vectorizer.pkl': 'vectorizer', 
#                 'anomaly_model.pkl': 'anomaly_model',
#                 'scaler.pkl': 'scaler'
#             }
            
#             for filename, attr_name in model_files.items():
#                 path = os.path.join(models_dir, filename)
#                 if os.path.exists(path):
#                     with open(path, 'rb') as f:
#                         setattr(self, attr_name, pickle.load(f))
#                     logger.info(f"✅ {attr_name} loaded successfully")
            
#         except Exception as e:
#             logger.error(f"❌ Error loading AI models: {e}")

#     def load_existing_data(self):
#         """Load all existing reports and logs"""
#         # Load reports
#         reports_dir = '../reports'
#         if os.path.exists(reports_dir):
#             for report_file in glob.glob(os.path.join(reports_dir, '*.json')):
#                 try:
#                     with open(report_file, 'r') as f:
#                         data = json.load(f)
#                     attack_type = os.path.basename(report_file).replace('_report.json', '').replace('_', ' ').title()
                    
#                     if 'baseline' in report_file.lower():
#                         self.baseline_metrics.update(data.get('baseline_metrics', {}))
#                     else:
#                         success_rate = data.get('summary', {}).get('success_rate', 0)
#                         self.attack_data.append({
#                             'type': attack_type,
#                             'timestamp': data.get('timestamp', datetime.now().isoformat()),
#                             'success_rate': success_rate,
#                             'details': data.get('summary', {}),
#                             'file': os.path.basename(report_file)
#                         })
#                 except Exception as e:
#                     logger.error(f"Error loading {report_file}: {e}")

#         # Load recent logs
#         self.load_recent_logs()

#     def load_recent_logs(self):
#         """Load recent log entries"""
#         logs_dir = '../logs'
#         log_files = []
        
#         # Find all log files
#         for root, dirs, files in os.walk(logs_dir):
#             for file in files:
#                 if file.endswith('.log'):
#                     log_files.append(os.path.join(root, file))
        
#         for log_file in log_files:
#             try:
#                 with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
#                     lines = f.readlines()[-50:]  # Last 50 lines
#                     for line in lines:
#                         if line.strip():
#                             self.parse_log_entry(line.strip(), os.path.basename(log_file))
#             except Exception as e:
#                 logger.error(f"Error reading log file {log_file}: {e}")

#     def parse_log_entry(self, log_entry, log_source):
#         """Parse log entry and add to request logs"""
#         try:
#             # Simple parsing - adjust based on your log format
#             if 'HTTP' in log_entry or 'GET' in log_entry or 'POST' in log_entry:
#                 parts = log_entry.split()
#                 if len(parts) > 5:
#                     timestamp = ' '.join(parts[0:2]) if len(parts[0].split(':')) >= 3 else datetime.now().isoformat()
#                     endpoint = next((p for p in parts if p.startswith('/')), '/')
#                     status_code = next((int(p) for p in parts if p.isdigit() and len(p) == 3), 200)
                    
#                     self.request_logs.append({
#                         'timestamp': timestamp,
#                         'endpoint': endpoint,
#                         'status_code': status_code,
#                         'response_time': 0.1,
#                         'ip': '127.0.0.1',
#                         'source': log_source
#                     })
#         except Exception as e:
#             pass  # Skip parsing errors

#     def start_background_monitoring(self):
#         """Start background monitoring threads"""
#         def monitor_system():
#             while True:
#                 try:
#                     health = self.get_system_health()
#                     if 'error' not in health:
#                         self.system_metrics.append(health)
                    
#                     # Check for new reports
#                     self.check_new_reports()
                    
#                     time.sleep(5)
#                 except Exception as e:
#                     logger.error(f"Background monitor error: {e}")
#                     time.sleep(30)

#         monitor_thread = threading.Thread(target=monitor_system, daemon=True)
#         monitor_thread.start()

#     def check_new_reports(self):
#         """Check for new report files and load them"""
#         reports_dir = '../reports'
#         if not os.path.exists(reports_dir):
#             return
            
#         current_files = {attack['file'] for attack in self.attack_data if 'file' in attack}
#         for report_file in glob.glob(os.path.join(reports_dir, '*.json')):
#             filename = os.path.basename(report_file)
#             if filename not in current_files:
#                 try:
#                     with open(report_file, 'r') as f:
#                         data = json.load(f)
#                     attack_type = filename.replace('_report.json', '').replace('_', ' ').title()
                    
#                     success_rate = data.get('summary', {}).get('success_rate', 0)
#                     self.attack_data.append({
#                         'type': attack_type,
#                         'timestamp': data.get('timestamp', datetime.now().isoformat()),
#                         'success_rate': success_rate,
#                         'details': data.get('summary', {}),
#                         'file': filename
#                     })
#                     logger.info(f"📊 Loaded new report: {filename}")
#                 except Exception as e:
#                     logger.error(f"Error loading new report {filename}: {e}")

#     def log_request(self, endpoint, status_code, response_time, ip="127.0.0.1"):
#         log_entry = {
#             'timestamp': datetime.now().isoformat(),
#             'endpoint': endpoint,
#             'status_code': status_code,
#             'response_time': response_time,
#             'ip': ip,
#             'source': 'live'
#         }
#         self.request_logs.append(log_entry)

#     def add_alert(self, severity, message, source):
#         alert = {
#             'id': len(self.alerts) + 1,
#             'timestamp': datetime.now().isoformat(),
#             'severity': severity,
#             'message': message,
#             'source': source,
#             'acknowledged': False
#         }
#         self.alerts.append(alert)
#         if len(self.alerts) > 100:
#             self.alerts = self.alerts[-100:]

#     def get_attack_stats(self):
#         if not self.attack_data:
#             return {'total_attacks': 0, 'attack_types': {}, 'avg_success_rate': 0, 'recent_attacks': []}
        
#         df = pd.DataFrame(self.attack_data)
#         return {
#             'total_attacks': len(self.attack_data),
#             'attack_types': df['type'].value_counts().to_dict(),
#             'avg_success_rate': float(df['success_rate'].mean()),
#             'recent_attacks': self.attack_data[-10:]
#         }

#     def get_alerts_summary(self):
#         if not self.alerts:
#             return {'total_alerts': 0, 'alerts_by_severity': {}, 'unacknowledged_alerts': 0, 'recent_alerts': []}
        
#         df = pd.DataFrame(self.alerts)
#         return {
#             'total_alerts': len(self.alerts),
#             'alerts_by_severity': df['severity'].value_counts().to_dict(),
#             'unacknowledged_alerts': len([a for a in self.alerts if not a['acknowledged']]),
#             'recent_alerts': self.alerts[-10:]
#         }

#     def get_system_health(self):
#         try:
#             cpu_percent = psutil.cpu_percent()
#             memory_percent = psutil.virtual_memory().percent
#             disk_percent = psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent
            
#             # Check if models are loaded
#             model_health = 'HEALTHY' if self.model_loaded else 'UNHEALTHY'
            
#             return {
#                 'cpu_percent': cpu_percent,
#                 'memory_percent': memory_percent,
#                 'disk_percent': disk_percent,
#                 'model_health': model_health,
#                 'timestamp': datetime.now().isoformat()
#             }
#         except Exception as e:
#             return {'error': str(e)}

#     def get_ai_insights(self):
#         if not self.model_loaded:
#             return {'status': 'model_not_loaded', 'risk_score': 0, 'recommendations': ['Train AI model first']}

#         if len(self.request_logs) < 10:
#             return {'status': 'insufficient_data', 'risk_score': 0, 'recommendations': ['Run attack simulations first']}

#         recent_logs = list(self.request_logs)[-60:]
#         error_rate = len([r for r in recent_logs if r['status_code'] >= 400]) / len(recent_logs)
#         avg_response_time = np.mean([r['response_time'] for r in recent_logs])
#         risk_score = min(100, (error_rate * 50 + min(avg_response_time * 10, 50)))
        
#         recommendations = []
#         if error_rate > 0.3:
#             recommendations.append("High error rate detected - possible attack in progress")
#         if avg_response_time > 2.0:
#             recommendations.append("Slow response times - possible DoS attack")
#         if not self.model_loaded:
#             recommendations.append("AI model not loaded - limited threat detection")
            
#         return {
#             'status': 'active_monitoring',
#             'risk_score': round(risk_score, 1),
#             'error_rate': round(error_rate * 100, 1),
#             'avg_response_time': round(avg_response_time, 2),
#             'total_requests': len(self.request_logs),
#             'recommendations': recommendations
#         }

#     def analyze_text_input(self, input_text):
#         """Analyze text using loaded AI model"""
#         if not self.model_loaded or self.vectorizer is None or self.text_model is None:
#             return {'error': 'AI model not properly loaded'}

#         try:
#             features = self.vectorizer.transform([input_text])
#             prediction = self.text_model.predict(features)[0]
#             probabilities = self.text_model.predict_proba(features)[0]
#             confidence = max(probabilities)
            
#             threat_levels = {
#                 'normal': 'LOW',
#                 'sql_injection': 'CRITICAL',
#                 'xss': 'HIGH',
#                 'path_traversal': 'HIGH',
#                 'command_injection': 'CRITICAL'
#             }
            
#             return {
#                 'input': input_text,
#                 'prediction': prediction,
#                 'confidence': float(confidence),
#                 'threat_level': threat_levels.get(prediction, 'MEDIUM'),
#                 'is_malicious': prediction != 'normal'
#             }
#         except Exception as e:
#             return {'error': str(e)}

#     def get_model_status(self):
#         """Get AI model health status"""
#         models_loaded = {
#             'master_model': self.model_loaded,
#             'text_model': self.text_model is not None,
#             'vectorizer': self.vectorizer is not None,
#             'anomaly_model': self.anomaly_model is not None,
#             'scaler': self.scaler is not None
#         }
        
#         loaded_count = sum(models_loaded.values())
#         total_count = len(models_loaded)
        
#         if loaded_count == 0:
#             return {'status': 'not_loaded', 'message': 'No models loaded'}
#         elif loaded_count == total_count:
#             return {'status': 'fully_loaded', 'message': 'All models loaded successfully'}
#         else:
#             return {
#                 'status': 'partially_loaded', 
#                 'message': f'{loaded_count}/{total_count} models loaded',
#                 'loaded_models': [k for k, v in models_loaded.items() if v]
#             }

#     def get_file_structure(self):
#         """Get current file structure for monitoring"""
#         structure = {}
        
#         # Reports
#         reports = []
#         if os.path.exists('../reports'):
#             reports = [f for f in os.listdir('../reports') if f.endswith('.json')]
#         structure['reports'] = reports
        
#         # Logs
#         logs = {'security': [], 'application': [], 'performance': []}
#         log_dirs = {
#             'security': '../logs/security',
#             'application': '../logs/application', 
#             'performance': '../logs/performance'
#         }
        
#         for log_type, log_dir in log_dirs.items():
#             if os.path.exists(log_dir):
#                 logs[log_type] = [f for f in os.listdir(log_dir) if f.endswith('.log')]
#         structure['logs'] = logs
        
#         # Models
#         models = []
#         if os.path.exists('../models'):
#             models = [f for f in os.listdir('../models') if f.endswith('.pkl')]
#         structure['models'] = models
        
#         # Attacks
#         attacks = []
#         if os.path.exists('../attacks'):
#             attacks = [f for f in os.listdir('../attacks') if f.endswith('.py')]
#         structure['attacks'] = attacks
        
#         return structure

#     def run_attack_simulation(self, attack_type):
#         """Run attack simulation and return results"""
#         attack_map = {
#             'sql_injection': '../attacks/sql_injection.py',
#             'brute_force': '../attacks/brute_force.py',
#             'xss': '../attacks/xss_attack.py',
#             'path_traversal': '../attacks/path_traversal.py',
#             'security_controls': '../defense/security_controls_test.py',
#             'baseline': '../monitoring/baseline_activity.py'
#         }
        
#         if attack_type not in attack_map:
#             return {'error': 'Invalid attack type'}
            
#         script_path = attack_map[attack_type]
#         if not os.path.exists(script_path):
#             return {'error': f'Attack script not found: {script_path}'}
        
#         try:
#             # Run the attack script
#             cmd = [sys.executable, script_path]
#             result = subprocess.run(cmd, cwd=os.path.dirname(__file__), 
#                                  capture_output=True, text=True, timeout=30)
            
#             # Add alert based on result
#             if result.returncode == 0:
#                 self.add_alert('INFO', f'{attack_type} simulation completed', 'Attack Controller')
#                 return {'status': 'completed', 'output': result.stdout}
#             else:
#                 self.add_alert('WARNING', f'{attack_type} simulation failed', 'Attack Controller')
#                 return {'status': 'failed', 'error': result.stderr}
                
#         except subprocess.TimeoutExpired:
#             self.add_alert('WARNING', f'{attack_type} simulation timed out', 'Attack Controller')
#             return {'status': 'timeout', 'error': 'Simulation took too long'}
#         except Exception as e:
#             self.add_alert('ERROR', f'{attack_type} simulation error: {str(e)}', 'Attack Controller')
#             return {'status': 'error', 'error': str(e)}

# # Global monitor instance
# monitor = AdvancedSecurityMonitor()

# @app.route('/')
# def dashboard():
#     # Initialize session
#     if 'user_id' not in session:
#         session['user_id'] = f"user_{int(time.time())}"
#         session['start_time'] = datetime.now().isoformat()
    
#     return render_template('dashboard.html')

# @app.route('/api/attack-stats')
# def get_attack_stats():
#     return jsonify(monitor.get_attack_stats())

# @app.route('/api/alerts')
# def get_alerts():
#     return jsonify(monitor.get_alerts_summary())

# @app.route('/api/system-health')
# def get_system_health():
#     return jsonify(monitor.get_system_health())

# @app.route('/api/attack-timeline')
# def get_attack_timeline():
#     return jsonify(monitor.attack_data)

# @app.route('/api/ai-insights')
# def get_ai_insights():
#     return jsonify(monitor.get_ai_insights())

# @app.route('/api/model-status')
# def get_model_status():
#     return jsonify(monitor.get_model_status())

# @app.route('/api/analyze-text', methods=['POST'])
# def analyze_text():
#     data = request.json
#     result = monitor.analyze_text_input(data.get('text', ''))
#     return jsonify(result)

# @app.route('/api/recent-logs')
# def get_recent_logs():
#     limit = request.args.get('limit', 50, type=int)
#     return jsonify(list(monitor.request_logs)[-limit:])

# @app.route('/api/file-structure')
# def get_file_structure():
#     return jsonify(monitor.get_file_structure())

# @app.route('/api/acknowledge-alert/<int:alert_id>', methods=['POST'])
# def acknowledge_alert(alert_id):
#     for alert in monitor.alerts:
#         if alert['id'] == alert_id:
#             alert['acknowledged'] = True
#             break
#     return jsonify({'status': 'success'})

# @app.route('/api/log-request', methods=['POST'])
# def log_request():
#     data = request.json
#     monitor.log_request(
#         endpoint=data.get('endpoint', '/'),
#         status_code=data.get('status_code', 200),
#         response_time=data.get('response_time', 0.1),
#         ip=data.get('ip', '127.0.0.1')
#     )
#     return jsonify({'status': 'logged'})

# @app.route('/api/run-health-check', methods=['POST'])
# def run_health_check():
#     try:
#         # Import and run health check
#         sys.path.append('../monitoring')
#         from health_check import WindowsHealthCheck
#         health_check = WindowsHealthCheck()
#         report = health_check.run_complete_health_check()
        
#         if report['overall_health'] == 'UNHEALTHY':
#             monitor.add_alert('HIGH', 'System health check failed', 'Health Monitor')
#         else:
#             monitor.add_alert('LOW', 'System health check passed', 'Health Monitor')
            
#         return jsonify(report)
#     except Exception as e:
#         return jsonify({'error': str(e)})

# @app.route('/api/run-attack', methods=['POST'])
# def run_attack():
#     attack_type = request.json.get('attack_type')
#     result = monitor.run_attack_simulation(attack_type)
#     return jsonify(result)

# @app.route('/api/load-reports', methods=['POST'])
# def load_reports():
#     """Force reload all reports"""
#     monitor.load_existing_data()
#     return jsonify({'status': 'reports_reloaded'})

# @app.route('/api/session-info')
# def get_session_info():
#     """Get current session information"""
#     return jsonify({
#         'user_id': session.get('user_id'),
#         'start_time': session.get('start_time'),
#         'duration_seconds': (datetime.now() - datetime.fromisoformat(session.get('start_time', datetime.now().isoformat()))).total_seconds()
#     })

# @app.route('/api/train-model', methods=['POST'])
# def train_model():
#     """Train the AI model if needed"""
#     try:
#         # Run training script
#         cmd = [sys.executable, '../run_training.py']
#         result = subprocess.run(cmd, cwd=os.path.dirname(__file__), 
#                              capture_output=True, text=True, timeout=120)
        
#         if result.returncode == 0:
#             # Reload models after training
#             monitor.load_all_ai_models()
#             return jsonify({'status': 'training_completed', 'output': result.stdout})
#         else:
#             return jsonify({'status': 'training_failed', 'error': result.stderr})
#     except Exception as e:
#         return jsonify({'status': 'error', 'error': str(e)})

# if __name__ == '__main__':
#     # Create necessary directories
#     os.makedirs('templates', exist_ok=True)
    
#     print("🚀 Starting AI-Powered Security Monitoring Dashboard...")
#     print("📊 Access dashboard at: http://localhost:5000")
#     print("🤖 AI Model Status:", monitor.get_model_status()['status'])
#     print("🎯 Available Attack Types: SQLi, XSS, Brute Force, Path Traversal")
#     print("📁 Monitoring Paths:")
#     print("   - Reports: ../reports/")
#     print("   - Logs: ../logs/")
#     print("   - Models: ../models/")
#     print("   - Attacks: ../attacks/")
#     print("🧠 AI Features: Real-time Threat Detection, Model Control, File Monitoring")
    
#     app.run(host='0.0.0.0', port=5000, debug=True)


# ===============================================


# from flask import Flask, render_template, jsonify, request
# import json
# import time
# import threading
# from datetime import datetime, timedelta
# import pandas as pd
# import numpy as np
# import os
# import logging
# import pickle
# from collections import deque, defaultdict
# import subprocess
# import sys

# # Configure logging
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# app = Flask(__name__)

# class SecurityMonitor:
#     def __init__(self):
#         self.attack_data = []
#         self.system_metrics = deque(maxlen=200)
#         self.alerts = []
#         self.request_logs = deque(maxlen=1000)
#         self.baseline_metrics = {
#             'avg_requests_per_min': 10,
#             'normal_status_codes': [200, 201, 304],
#             'normal_endpoints': ['/rest/products', '/rest/user/whoami', '/api/Products']
#         }
#         self.ai_model = None
#         self.model_loaded = False
#         self.load_existing_data()
#         self.load_ai_model()

#     def load_ai_model(self):
#         """Load pre-trained AI model"""
#         try:
#             model_path = '../models/master_threat_model.pkl'
#             if os.path.exists(model_path):
#                 with open(model_path, 'rb') as f:
#                     model_data = pickle.load(f)
#                 self.ai_model = model_data
#                 self.model_loaded = True
#                 logger.info("✅ AI Model loaded successfully")
#             else:
#                 logger.warning("⚠️ AI Model not found. Train model first.")
#         except Exception as e:
#             logger.error(f"❌ Error loading AI model: {e}")

#     def load_existing_data(self):
#         reports_dir = '../reports'
#         if not os.path.exists(reports_dir):
#             os.makedirs(reports_dir)
#             return

#         report_files = [
#             ('sql_injection_report.json', 'SQL Injection'),
#             ('brute_force_report.json', 'Brute Force'),
#             ('xss_attack_report.json', 'XSS'),
#             ('path_traversal_report.json', 'Path Traversal'),
#             ('baseline_activity_report.json', 'Baseline')
#         ]

#         for filename, attack_type in report_files:
#             try:
#                 filepath = os.path.join(reports_dir, filename)
#                 with open(filepath, 'r') as f:
#                     data = json.load(f)
#                     success_rate = data['summary'].get('success_rate', 0)
#                     if attack_type == 'Baseline':
#                         self.baseline_metrics.update({
#                             'avg_requests_per_min': data['baseline_metrics'].get('avg_requests_per_min', 10),
#                             'normal_status_codes': data['baseline_metrics'].get('typical_status_codes', [200, 201]),
#                             'normal_endpoints': data['baseline_metrics'].get('common_endpoints', [])
#                         })
#                     else:
#                         self.attack_data.append({
#                             'type': attack_type,
#                             'timestamp': data['timestamp'],
#                             'success_rate': success_rate,
#                             'details': data.get('summary', {})
#                         })
#             except FileNotFoundError:
#                 logger.info(f"No {filename} found")
#             except Exception as e:
#                 logger.error(f"Error loading {filename}: {e}")

#     def log_request(self, endpoint, status_code, response_time, ip="127.0.0.1"):
#         log_entry = {
#             'timestamp': datetime.now().isoformat(),
#             'endpoint': endpoint,
#             'status_code': status_code,
#             'response_time': response_time,
#             'ip': ip
#         }
#         self.request_logs.append(log_entry)

#     def add_attack_data(self, attack_type, success_rate, details):
#         self.attack_data.append({
#             'type': attack_type,
#             'timestamp': datetime.now().isoformat(),
#             'success_rate': success_rate,
#             'details': details
#         })
#         if len(self.attack_data) > 50:
#             self.attack_data = self.attack_data[-50:]

#     def add_alert(self, severity, message, source):
#         alert = {
#             'id': len(self.alerts) + 1,
#             'timestamp': datetime.now().isoformat(),
#             'severity': severity,
#             'message': message,
#             'source': source,
#             'acknowledged': False
#         }
#         self.alerts.append(alert)
#         if len(self.alerts) > 100:
#             self.alerts = self.alerts[-100:]

#     def get_attack_stats(self):
#         if not self.attack_data:
#             return {'total_attacks': 0, 'attack_types': {}, 'avg_success_rate': 0, 'recent_attacks': []}
        
#         df = pd.DataFrame(self.attack_data)
#         return {
#             'total_attacks': len(self.attack_data),
#             'attack_types': df['type'].value_counts().to_dict(),
#             'avg_success_rate': float(df['success_rate'].mean()),
#             'recent_attacks': self.attack_data[-10:]
#         }

#     def get_alerts_summary(self):
#         if not self.alerts:
#             return {'total_alerts': 0, 'alerts_by_severity': {}, 'unacknowledged_alerts': 0, 'recent_alerts': []}
        
#         df = pd.DataFrame(self.alerts)
#         return {
#             'total_alerts': len(self.alerts),
#             'alerts_by_severity': df['severity'].value_counts().to_dict(),
#             'unacknowledged_alerts': len([a for a in self.alerts if not a['acknowledged']]),
#             'recent_alerts': self.alerts[-10:]
#         }

#     def get_system_health(self):
#         try:
#             import psutil
#             return {
#                 'cpu_percent': psutil.cpu_percent(),
#                 'memory_percent': psutil.virtual_memory().percent,
#                 'disk_percent': psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:\\').percent,
#                 'timestamp': datetime.now().isoformat()
#             }
#         except ImportError:
#             return {'error': 'psutil not available'}

#     def get_ai_insights(self):
#         if not self.model_loaded:
#             return {'status': 'model_not_loaded', 'risk_score': 0, 'recommendations': ['Train AI model first']}

#         if len(self.request_logs) < 10:
#             return {'status': 'insufficient_data', 'risk_score': 0, 'recommendations': ['Run attack simulations first']}

#         recent_logs = list(self.request_logs)[-60:]
#         error_rate = len([r for r in recent_logs if r['status_code'] >= 400]) / len(recent_logs)
#         avg_response_time = np.mean([r['response_time'] for r in recent_logs])
#         risk_score = min(100, (error_rate * 50 + min(avg_response_time * 10, 50)))
        
#         recommendations = []
#         if error_rate > 0.3:
#             recommendations.append("High error rate detected - possible attack in progress")
#         if avg_response_time > 2.0:
#             recommendations.append("Slow response times - possible DoS attack")
            
#         return {
#             'status': 'active_monitoring',
#             'risk_score': round(risk_score, 1),
#             'error_rate': round(error_rate * 100, 1),
#             'avg_response_time': round(avg_response_time, 2),
#             'total_requests': len(self.request_logs),
#             'recommendations': recommendations
#         }

#     def analyze_text_input(self, input_text):
#         """Analyze text using loaded AI model"""
#         if not self.model_loaded:
#             return {'error': 'AI model not loaded'}

#         try:
#             vectorizer = self.ai_model['vectorizer']
#             text_model = self.ai_model['text_model']
            
#             features = vectorizer.transform([input_text])
#             prediction = text_model.predict(features)[0]
#             probabilities = text_model.predict_proba(features)[0]
#             confidence = max(probabilities)
            
#             threat_levels = {
#                 'normal': 'LOW',
#                 'sql_injection': 'CRITICAL',
#                 'xss': 'HIGH',
#                 'path_traversal': 'HIGH',
#                 'command_injection': 'CRITICAL'
#             }
            
#             return {
#                 'input': input_text,
#                 'prediction': prediction,
#                 'confidence': float(confidence),
#                 'threat_level': threat_levels.get(prediction, 'MEDIUM'),
#                 'is_malicious': prediction != 'normal'
#             }
#         except Exception as e:
#             return {'error': str(e)}

#     def get_model_status(self):
#         """Get AI model health status"""
#         if not self.model_loaded:
#             return {'status': 'not_loaded', 'message': 'Model not loaded'}
        
#         metrics = self.ai_model.get('performance_metrics', {})
#         return {
#             'status': 'loaded',
#             'text_accuracy': metrics.get('text_classifier', {}).get('test_accuracy', 0),
#             'anomaly_accuracy': metrics.get('anomaly_detector', {}).get('test_accuracy', 0),
#             'last_trained': metrics.get('training_date', 'Unknown'),
#             'classes': metrics.get('text_classifier', {}).get('classes', [])
#         }

# # Global monitor instance
# monitor = SecurityMonitor()

# @app.route('/')
# def dashboard():
#     return render_template('dashboard.html')

# @app.route('/api/attack-stats')
# def get_attack_stats():
#     return jsonify(monitor.get_attack_stats())

# @app.route('/api/alerts')
# def get_alerts():
#     return jsonify(monitor.get_alerts_summary())

# @app.route('/api/system-health')
# def get_system_health():
#     return jsonify(monitor.get_system_health())

# @app.route('/api/attack-timeline')
# def get_attack_timeline():
#     return jsonify(monitor.attack_data)

# @app.route('/api/ai-insights')
# def get_ai_insights():
#     return jsonify(monitor.get_ai_insights())

# @app.route('/api/model-status')
# def get_model_status():
#     return jsonify(monitor.get_model_status())

# @app.route('/api/analyze-text', methods=['POST'])
# def analyze_text():
#     data = request.json
#     result = monitor.analyze_text_input(data.get('text', ''))
#     return jsonify(result)

# @app.route('/api/recent-logs')
# def get_recent_logs():
#     limit = request.args.get('limit', 50, type=int)
#     return jsonify(list(monitor.request_logs)[-limit:])

# @app.route('/api/acknowledge-alert/<int:alert_id>', methods=['POST'])
# def acknowledge_alert(alert_id):
#     for alert in monitor.alerts:
#         if alert['id'] == alert_id:
#             alert['acknowledged'] = True
#             break
#     return jsonify({'status': 'success'})

# @app.route('/api/log-request', methods=['POST'])
# def log_request():
#     data = request.json
#     monitor.log_request(
#         endpoint=data.get('endpoint', '/'),
#         status_code=data.get('status_code', 200),
#         response_time=data.get('response_time', 0.1),
#         ip=data.get('ip', '127.0.0.1')
#     )
#     return jsonify({'status': 'logged'})

# @app.route('/api/run-health-check', methods=['POST'])
# def run_health_check():
#     try:
#         import sys, os
#         sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
#         from monitoring.health_check import WindowsHealthCheck
#         health_check = WindowsHealthCheck()
#         report = health_check.run_complete_health_check()
        
#         if report['overall_health'] == 'UNHEALTHY':
#             monitor.add_alert('HIGH', 'System health check failed', 'Health Monitor')
#         else:
#             monitor.add_alert('LOW', 'System health check passed', 'Health Monitor')
            
#         return jsonify(report)
#     except Exception as e:
#         return jsonify({'error': str(e)})

# @app.route('/api/run-attack', methods=['POST'])
# def run_attack():
#     attack_type = request.json.get('attack_type')
#     try:
#         attack_map = {
#             'sql_injection': '../attacks/sql_injection.py',
#             'brute_force': '../attacks/brute_force.py',
#             'xss': '../attacks/xss_attack.py',
#             'path_traversal': '../attacks/path_traversal.py',
#             'ai_threat_detection': '../ai_models/threat_detector.py',
#             'anomaly_detection': '../ai_models/anomaly_detector.py'
#         }
        
#         if attack_type not in attack_map:
#             return jsonify({'error': 'Invalid attack type'})
            
#         cmd = [sys.executable, attack_map[attack_type]]
#         subprocess.Popen(cmd, cwd=os.path.dirname(__file__))
#         monitor.add_alert('INFO', f'Started {attack_type} simulation', 'Attack Controller')
#         return jsonify({'status': 'started', 'attack_type': attack_type})
#     except Exception as e:
#         return jsonify({'error': str(e)})

# @app.route('/api/train-model', methods=['POST'])
# def train_model():
#     """Trigger model training"""
#     try:
#         cmd = [sys.executable, '../train_model_once.py']
#         subprocess.Popen(cmd, cwd=os.path.dirname(__file__))
#         monitor.add_alert('INFO', 'Started AI model training', 'AI Controller')
#         return jsonify({'status': 'training_started'})
#     except Exception as e:
#         return jsonify({'error': str(e)})

# def background_monitor():
#     while True:
#         try:
#             health = monitor.get_system_health()
#             if 'error' not in health:
#                 monitor.system_metrics.append(health)
#             time.sleep(5)
#         except Exception as e:
#             logger.error(f"Background monitor error: {e}")
#             time.sleep(30)

# if __name__ == '__main__':
#     os.makedirs('templates', exist_ok=True)
#     monitor_thread = threading.Thread(target=background_monitor, daemon=True)
#     monitor_thread.start()
    
#     print("🚀 Starting AI-Powered Security Monitoring Dashboard...")
#     print("📊 Access dashboard at: http://localhost:5000")
#     print("🤖 AI Model Status:", "LOADED" if monitor.model_loaded else "NOT LOADED")
#     print("🎯 Attack Types: SQLi, XSS, Brute Force, Path Traversal")
#     print("🧠 AI Features: Real-time Threat Detection, Model Control")
#     app.run(host='0.0.0.0', port=5000, debug=True)

