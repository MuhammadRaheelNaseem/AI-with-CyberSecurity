import requests
import time
import json
import logging
import os
from datetime import datetime
import psutil

class WindowsHealthCheck:
    def __init__(self, base_url="http://localhost:3000"):
        self.base_url = base_url
        self.logger = self.setup_logging()
        
    def setup_logging(self):
        """Setup comprehensive logging with directory creation and UTF-8 safety"""
        # Create necessary directories
        log_dirs = [
            '../logs/application',
            '../logs/security', 
            '../logs/performance',
            '../reports',
            '../data-captures/network',
            '../data-captures/logs',
            '../data-captures/metrics'
        ]
        
        for log_dir in log_dirs:
            os.makedirs(log_dir, exist_ok=True)
            print(f"✅ Created directory: {log_dir}")
        
        # Use UTF-8 encoding for log file to support emojis safely
        log_file_path = '../logs/application/health_check.log'
        file_handler = logging.FileHandler(log_file_path, encoding='utf-8')
        stream_handler = logging.StreamHandler()

        # Avoid emojis in console logs to prevent cp1252 errors on Windows
        # But keep them in file logs (which are UTF-8)
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[file_handler, stream_handler]
        )
        return logging.getLogger(__name__)
    
    def safe_log_info(self, message_with_emoji, plain_message=None):
        """Log emoji message to file, plain message to console (if needed)"""
        if plain_message is None:
            # Strip common emojis for fallback
            plain_message = (
                message_with_emoji
                .replace("🔍", "")
                .replace("📊", "")
                .replace("✅", "")
                .replace("⚠️", "")
                .replace("🚨", "")
                .strip()
            )
        # Log full message (with emoji) to file
        self.logger.info(message_with_emoji)
        # Print plain version to console to avoid UnicodeEncodeError
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - INFO - {plain_message}")

    def check_system_resources(self):
        """Check Windows system resources"""
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            # On Windows, disk root is usually C:
            disk = psutil.disk_usage('C:\\' if os.name == 'nt' else '/')
            
            return {
                'cpu_usage_percent': cpu_percent,
                'memory_usage_percent': memory.percent,
                'memory_available_gb': round(memory.available / (1024**3), 2),
                'disk_usage_percent': disk.percent,
                'disk_free_gb': round(disk.free / (1024**3), 2)
            }
        except Exception as e:
            self.logger.error(f"Error checking system resources: {e}")
            return {}
    
    def check_service_availability(self):
        """Check if Juice Shop is accessible"""
        try:
            start_time = time.time()
            response = requests.get(self.base_url, timeout=10)
            response_time = time.time() - start_time
            
            return {
                'status_code': response.status_code,
                'response_time_seconds': round(response_time, 2),
                'service_available': response.status_code == 200
            }
        except requests.exceptions.RequestException as e:
            error_msg = f"Service unavailable: {e}"
            self.logger.error(error_msg)
            return {
                'status_code': 0,
                'response_time_seconds': 0,
                'service_available': False,
                'error': str(e)
            }
    
    def check_critical_endpoints(self):
        """Check critical API endpoints"""
        endpoints = {
            'products': '/rest/products',
            'login': '/rest/user/login',
            'challenges': '/api/Challenges'
        }
        
        results = {}
        for name, endpoint in endpoints.items():
            try:
                response = requests.get(f"{self.base_url}{endpoint}", timeout=5)
                results[name] = {
                    'status_code': response.status_code,
                    'response_time': response.elapsed.total_seconds()
                }
            except Exception as e:
                results[name] = {'error': str(e)}
        
        return results
    
    def run_complete_health_check(self):
        """Run comprehensive health check"""
        self.safe_log_info("🔍 Starting Comprehensive Health Check...")

        health_report = {
            'timestamp': datetime.now().isoformat(),
            'system': self.check_system_resources(),
            'service': self.check_service_availability(),
            'endpoints': self.check_critical_endpoints()
        }
        
        # Determine overall health
        service_ok = health_report['service'].get('service_available', False)
        endpoints_ok = all(
            ep.get('status_code') == 200 
            for ep in health_report['endpoints'].values() 
            if 'status_code' in ep
        )
        
        health_report['overall_health'] = 'HEALTHY' if (service_ok and endpoints_ok) else 'UNHEALTHY'
        
        # Ensure reports directory exists
        os.makedirs('../reports', exist_ok=True)
        
        # Save report
        report_path = '../reports/health_report.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(health_report, f, indent=2, ensure_ascii=False)
        
        self.safe_log_info(
            f"📊 Health Check Completed: {health_report['overall_health']}",
            f"Health Check Completed: {health_report['overall_health']}"
        )
        
        # Print clean summary to console (no emojis in print statements)
        print(f"\n🏥 HEALTH CHECK SUMMARY:")
        print(f"   Overall Status: {health_report['overall_health']}")
        print(f"   Service Available: {service_ok}")
        print(f"   CPU Usage: {health_report['system'].get('cpu_usage_percent', 'N/A')}%")
        print(f"   Memory Usage: {health_report['system'].get('memory_usage_percent', 'N/A')}%")
        print(f"   Report Saved: {report_path}")
        
        return health_report

if __name__ == "__main__":
    print("🔧 Initializing Health Check with Auto-Directory Setup...")
    health_check = WindowsHealthCheck()
    report = health_check.run_complete_health_check()
    print(f"✅ Health Check Complete: {report['overall_health']}")