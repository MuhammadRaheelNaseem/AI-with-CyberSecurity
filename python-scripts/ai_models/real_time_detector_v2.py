import numpy as np
import pandas as pd
import logging
import json
import time
import threading
from datetime import datetime
import os
import sys
from collections import deque, defaultdict

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - REAL_TIME_DETECTOR - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class RealTimeThreatDetector:
    def __init__(self, window_size=100, threshold=0.7):
        self.window_size = window_size
        self.threshold = threshold
        self.request_buffer = deque(maxlen=window_size)
        self.alert_buffer = deque(maxlen=50)
        self.is_monitoring = False
        self.monitor_thread = None
        self.metrics = {
            'request_count': 0,
            'anomaly_count': 0,
            'last_alert_time': None
        }
        
        # Behavioral patterns
        self.suspicious_patterns = [
            r".*[';].*",  # SQL injection patterns
            r".*<script>.*",  # XSS patterns
            r".*\.\./.*",  # Path traversal
            r".*union.*select.*",  # SQL union
            r".*drop.*table.*",  # SQL drop
            r".*exec.*",  # Command execution
            r".*eval.*",  # Code evaluation
        ]
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.is_monitoring:
            logger.warning("⚠️ Real-time monitoring is already running")
            return False
        
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        logger.info("🚀 Real-time threat monitoring started")
        return True
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        logger.info("🛑 Real-time threat monitoring stopped")
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Analyze recent requests for threats
                if len(self.request_buffer) >= 10:
                    self._analyze_request_patterns()
                    self._check_behavioral_anomalies()
                    self._detect_brute_force_attempts()
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                logger.error(f"❌ Monitoring loop error: {e}")
                time.sleep(5)
    
    def log_request(self, endpoint, method, status_code, response_time, ip_address, user_agent=""):
        """Log a new request for analysis"""
        try:
            request_data = {
                'timestamp': datetime.now().isoformat(),
                'endpoint': endpoint,
                'method': method,
                'status_code': status_code,
                'response_time': response_time,
                'ip_address': ip_address,
                'user_agent': user_agent,
                'threat_score': 0,
                'threat_type': None,
                'is_malicious': False
            }
            
            # Analyze request for immediate threats
            threat_analysis = self._analyze_single_request(request_data)
            request_data.update(threat_analysis)
            
            self.request_buffer.append(request_data)
            self.metrics['request_count'] += 1
            
            if request_data['is_malicious']:
                self.metrics['anomaly_count'] += 1
                self._trigger_alert(request_data)
            
            return request_data
            
        except Exception as e:
            logger.error(f"❌ Error logging request: {e}")
            return None
    
    def _analyze_single_request(self, request_data):
        """Analyze a single request for threats"""
        threat_score = 0
        threat_type = None
        is_malicious = False
        
        try:
            endpoint = request_data['endpoint']
            user_agent = request_data['user_agent']
            ip_address = request_data['ip_address']
            
            # Check for SQL injection patterns
            if any(pattern in endpoint.lower() for pattern in ["'", ";", "union", "select", "drop"]):
                threat_score += 0.3
                threat_type = "SQL Injection Attempt"
            
            # Check for XSS patterns
            if any(pattern in endpoint.lower() for pattern in ["<script>", "javascript:", "onload=", "onerror="]):
                threat_score += 0.4
                threat_type = "XSS Attempt"
            
            # Check for path traversal
            if any(pattern in endpoint for pattern in ["../", "..\\", "/etc/", "/bin/"]):
                threat_score += 0.3
                threat_type = "Path Traversal Attempt"
            
            # Check for suspicious user agents
            if any(pattern in user_agent.lower() for pattern in ["sqlmap", "nikto", "metasploit", "nmap"]):
                threat_score += 0.5
                threat_type = "Scanning Tool Detected"
            
            # Check response time anomalies
            if request_data['response_time'] > 5.0:  # More than 5 seconds
                threat_score += 0.2
                threat_type = "Potential DoS/Resource Attack"
            
            # Check status code patterns
            if request_data['status_code'] in [401, 403, 404]:
                threat_score += 0.1
            
            # Determine if malicious
            is_malicious = threat_score >= self.threshold
            
            return {
                'threat_score': round(threat_score, 2),
                'threat_type': threat_type,
                'is_malicious': is_malicious
            }
            
        except Exception as e:
            logger.error(f"❌ Error analyzing single request: {e}")
            return {'threat_score': 0, 'threat_type': None, 'is_malicious': False}
    
    def _analyze_request_patterns(self):
        """Analyze patterns across multiple requests"""
        try:
            if len(self.request_buffer) < 5:
                return
            
            recent_requests = list(self.request_buffer)
            
            # Check for rapid successive requests (potential DoS)
            time_diffs = []
            for i in range(1, min(10, len(recent_requests))):
                time1 = datetime.fromisoformat(recent_requests[i-1]['timestamp'])
                time2 = datetime.fromisoformat(recent_requests[i]['timestamp'])
                diff = (time2 - time1).total_seconds()
                time_diffs.append(diff)
            
            if len(time_diffs) > 3:
                avg_time_diff = np.mean(time_diffs)
                if avg_time_diff < 0.1:  # Less than 100ms between requests
                    self._trigger_alert({
                        'threat_type': 'Potential DoS Attack',
                        'threat_score': 0.8,
                        'timestamp': datetime.now().isoformat(),
                        'details': f'Rapid requests detected: {avg_time_diff:.3f}s average interval'
                    })
            
            # Check for multiple failed authentication attempts
            failed_auth = [r for r in recent_requests if r['status_code'] in [401, 403]]
            if len(failed_auth) >= 5:
                self._trigger_alert({
                    'threat_type': 'Brute Force Attempt',
                    'threat_score': 0.7,
                    'timestamp': datetime.now().isoformat(),
                    'details': f'Multiple failed auth attempts: {len(failed_auth)}'
                })
                
        except Exception as e:
            logger.error(f"❌ Error analyzing request patterns: {e}")
    
    def _check_behavioral_anomalies(self):
        """Check for behavioral anomalies"""
        try:
            if len(self.request_buffer) < 20:
                return
            
            recent_requests = list(self.request_buffer)
            
            # Analyze endpoint access patterns
            endpoint_counts = defaultdict(int)
            ip_counts = defaultdict(int)
            
            for request in recent_requests[-20:]:
                endpoint_counts[request['endpoint']] += 1
                ip_counts[request['ip_address']] += 1
            
            # Check for unusual endpoint access patterns
            for endpoint, count in endpoint_counts.items():
                if count > 10:  # Same endpoint accessed more than 10 times in short period
                    self._trigger_alert({
                        'threat_type': 'Suspicious Endpoint Access Pattern',
                        'threat_score': 0.6,
                        'timestamp': datetime.now().isoformat(),
                        'details': f'Endpoint {endpoint} accessed {count} times rapidly'
                    })
            
            # Check for IP address anomalies
            for ip, count in ip_counts.items():
                if count > 15:  # Same IP making many requests
                    self._trigger_alert({
                        'threat_type': 'Suspicious IP Activity',
                        'threat_score': 0.5,
                        'timestamp': datetime.now().isoformat(),
                        'details': f'IP {ip} made {count} requests in short period'
                    })
                    
        except Exception as e:
            logger.error(f"❌ Error checking behavioral anomalies: {e}")
    
    def _detect_brute_force_attempts(self):
        """Detect brute force attack patterns"""
        try:
            if len(self.request_buffer) < 10:
                return
            
            recent_requests = list(self.request_buffer)
            
            # Group by IP and check for patterns
            ip_activity = defaultdict(list)
            for request in recent_requests:
                ip_activity[request['ip_address']].append(request)
            
            for ip, requests in ip_activity.items():
                if len(requests) >= 8:
                    # Check for rapid sequential requests
                    timestamps = [datetime.fromisoformat(r['timestamp']) for r in requests]
                    time_diffs = [(timestamps[i] - timestamps[i-1]).total_seconds() 
                                for i in range(1, len(timestamps))]
                    
                    if len(time_diffs) > 0 and np.mean(time_diffs) < 1.0:
                        self._trigger_alert({
                            'threat_type': 'Brute Force Attack Detected',
                            'threat_score': 0.9,
                            'timestamp': datetime.now().isoformat(),
                            'details': f'IP {ip} showing brute force patterns'
                        })
                        
        except Exception as e:
            logger.error(f"❌ Error detecting brute force attempts: {e}")
    
    def _trigger_alert(self, alert_data):
        """Trigger a security alert"""
        try:
            alert = {
                'id': len(self.alert_buffer) + 1,
                'timestamp': datetime.now().isoformat(),
                'threat_type': alert_data['threat_type'],
                'threat_score': alert_data['threat_score'],
                'details': alert_data.get('details', ''),
                'severity': 'HIGH' if alert_data['threat_score'] > 0.7 else 'MEDIUM',
                'acknowledged': False
            }
            
            self.alert_buffer.append(alert)
            self.metrics['last_alert_time'] = datetime.now().isoformat()
            
            logger.warning(f"🚨 SECURITY ALERT: {alert['threat_type']} (Score: {alert['threat_score']})")
            
        except Exception as e:
            logger.error(f"❌ Error triggering alert: {e}")
    
    def get_monitoring_stats(self):
        """Get current monitoring statistics"""
        return {
            'is_monitoring': self.is_monitoring,
            'total_requests': self.metrics['request_count'],
            'anomalies_detected': self.metrics['anomaly_count'],
            'current_buffer_size': len(self.request_buffer),
            'active_alerts': len(self.alert_buffer),
            'last_alert_time': self.metrics['last_alert_time'],
            'threshold': self.threshold
        }
    
    def get_recent_alerts(self, limit=10):
        """Get recent security alerts"""
        return list(self.alert_buffer)[-limit:]
    
    def generate_report(self):
        """Generate real-time monitoring report"""
        try:
            stats = self.get_monitoring_stats()
            recent_alerts = self.get_recent_alerts(5)
            
            report = {
                "timestamp": datetime.now().isoformat(),
                "analysis_type": "Real-Time Threat Detection",
                "summary": {
                    "monitoring_active": stats['is_monitoring'],
                    "total_requests_analyzed": stats['total_requests'],
                    "anomalies_detected": stats['anomalies_detected'],
                    "current_alerts": stats['active_alerts'],
                    "detection_threshold": stats['threshold']
                },
                "recent_alerts": recent_alerts,
                "system_metrics": {
                    "buffer_size": stats['current_buffer_size'],
                    "window_size": self.window_size,
                    "last_alert": stats['last_alert_time']
                },
                "details": {
                    "detection_techniques": [
                        "Pattern-based SQL Injection Detection",
                        "XSS Payload Detection", 
                        "Behavioral Anomaly Detection",
                        "Brute Force Pattern Recognition",
                        "DoS Attack Identification"
                    ],
                    "recommendations": [
                        "Review high-scoring alerts immediately",
                        "Adjust threshold based on normal traffic patterns",
                        "Implement IP blocking for repeated offenders",
                        "Monitor endpoint access patterns regularly"
                    ]
                }
            }
            
            # Save report
            reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
            os.makedirs(reports_dir, exist_ok=True)
            
            report_path = os.path.join(reports_dir, 'real_time_detection_report.json')
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"📊 Real-time detection report generated: {report_path}")
            return report
            
        except Exception as e:
            logger.error(f"❌ Error generating real-time report: {e}")
            return None

def main():
    """Main function for testing real-time detector"""
    try:
        logger.info("🚀 Starting Real-Time Threat Detection System")
        
        # Initialize detector
        detector = RealTimeThreatDetector(window_size=50, threshold=0.6)
        
        # Start monitoring
        detector.start_monitoring()
        
        # Simulate some requests
        logger.info("🔧 Simulating request traffic...")
        
        # Normal requests
        for i in range(20):
            detector.log_request(
                endpoint=f"/api/users/{i}",
                method="GET",
                status_code=200,
                response_time=0.1 + np.random.random() * 0.5,
                ip_address=f"192.168.1.{np.random.randint(1, 50)}",
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            )
            time.sleep(0.1)
        
        # Some suspicious requests
        suspicious_requests = [
            ("/api/users' OR '1'='1", "GET", 200, 0.2, "192.168.1.99", "sqlmap/1.0"),
            ("/api/data<script>alert('xss')</script>", "POST", 200, 0.3, "192.168.1.99", "Mozilla/5.0"),
            ("/../../../etc/passwd", "GET", 404, 0.1, "192.168.1.99", "nmap/7.80"),
        ]
        
        for endpoint, method, status, resp_time, ip, ua in suspicious_requests:
            detector.log_request(endpoint, method, status, resp_time, ip, ua)
            time.sleep(0.2)
        
        # Let the system process
        time.sleep(3)
        
        # Generate report
        report = detector.generate_report()
        if report:
            logger.info("✅ Real-Time Detection Test Completed!")
            logger.info(f"📈 Alerts triggered: {report['summary']['current_alerts']}")
            logger.info(f"📊 Anomalies detected: {report['summary']['anomalies_detected']}")
        else:
            logger.error("❌ Failed to generate report")
        
        # Stop monitoring
        detector.stop_monitoring()
        
    except Exception as e:
        logger.error(f"❌ Real-time detection test failed: {e}")

if __name__ == "__main__":
    main()