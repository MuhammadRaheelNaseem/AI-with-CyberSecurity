import os
import sys
import time
import json
import logging
import subprocess
import threading
from datetime import datetime

class TrainingSessionManager:
    def __init__(self):
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.setup_logging()
        
    def setup_logging(self):
        """Setup comprehensive logging"""
        log_dir = os.path.join(self.base_dir, 'logs', 'application')
        os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - TRAINING - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(log_dir, f'training_{self.session_id}.log')),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def run_command(self, command, description, cwd=None):
        """Run a command with proper logging"""
        self.logger.info(f"🚀 {description}")
        
        try:
            if cwd:
                result = subprocess.run(command, shell=True, cwd=cwd, capture_output=True, text=True)
            else:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
            
            if result.returncode == 0:
                self.logger.info(f"✅ {description} completed")
                return True
            else:
                self.logger.error(f"❌ {description} failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ {description} failed with exception: {e}")
            return False
    
    def start_juice_shop(self):
        """Start OWASP Juice Shop"""
        juice_shop_dir = os.path.join(self.base_dir, 'juice-shop-app')
        
        if not os.path.exists(juice_shop_dir):
            self.logger.error("Juice Shop directory not found")
            return False
        
        # Check if Juice Shop is already running
        try:
            import requests
            response = requests.get("http://localhost:3000", timeout=5)
            if response.status_code == 200:
                self.logger.info("✅ Juice Shop is already running")
                return True
        except:
            pass
        
        # Start Juice Shop in background thread
        def start_js():
            subprocess.run("npm start", shell=True, cwd=juice_shop_dir)
        
        js_thread = threading.Thread(target=start_js, daemon=True)
        js_thread.start()
        
        # Wait for Juice Shop to start
        self.logger.info("Waiting for Juice Shop to start...")
        for i in range(30):
            try:
                import requests
                response = requests.get("http://localhost:3000", timeout=5)
                if response.status_code == 200:
                    self.logger.info("✅ Juice Shop started successfully")
                    return True
            except:
                pass
            time.sleep(1)
        
        self.logger.error("❌ Juice Shop failed to start within 30 seconds")
        return False
    
    def run_health_check(self):
        """Run health check"""
        return self.run_command(
            "python monitoring/health_check.py",
            "Health Check",
            cwd=os.path.join(self.base_dir, 'python-scripts')
        )
    
    def run_sql_injection_attack(self):
        """Run SQL injection attack"""
        return self.run_command(
            "python attacks/sql_injection.py",
            "SQL Injection Attack",
            cwd=os.path.join(self.base_dir, 'python-scripts')
        )
    
    def run_brute_force_attack(self):
        """Run brute force attack"""
        return self.run_command(
            "python attacks/brute_force.py",
            "Brute Force Attack", 
            cwd=os.path.join(self.base_dir, 'python-scripts')
        )
    
    def start_monitoring_dashboard(self):
        """Start Flask monitoring dashboard"""
        # Start in background thread
        def start_dashboard():
            subprocess.run(
                "python monitoring/flask_monitor.py",
                shell=True,
                cwd=os.path.join(self.base_dir, 'python-scripts')
            )
        
        dashboard_thread = threading.Thread(target=start_dashboard, daemon=True)
        dashboard_thread.start()
        
        time.sleep(3)  # Give dashboard time to start
        self.logger.info("✅ Monitoring dashboard started at http://localhost:5000")
        return True
    
    def generate_session_report(self):
        """Generate training session report"""
        report = {
            'session_id': self.session_id,
            'timestamp': datetime.now().isoformat(),
            'components': {
                'juice_shop': 'Running at http://localhost:3000',
                'monitoring_dashboard': 'Running at http://localhost:5000',
                'attack_simulations': 'Completed',
                'health_checks': 'Completed'
            },
            'next_steps': [
                "1. Access Juice Shop: http://localhost:3000",
                "2. Monitor attacks: http://localhost:5000", 
                "3. Review reports in 'reports' directory",
                "4. Check logs in 'logs' directory",
                "5. Experiment with additional attack vectors"
            ]
        }
        
        reports_dir = os.path.join(self.base_dir, 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        with open(os.path.join(reports_dir, f'session_report_{self.session_id}.json'), 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def run_complete_session(self):
        """Run complete training session"""
        self.logger.info("🎯 Starting Comprehensive Security Training Session")
        
        try:
            # Phase 1: Environment Setup
            self.logger.info("PHASE 1: Environment Setup")
            if not self.start_juice_shop():
                return False
            
            # Phase 2: Health Check
            self.logger.info("PHASE 2: Health Check")
            self.run_health_check()
            
            # Phase 3: Monitoring Setup
            self.logger.info("PHASE 3: Monitoring Setup")
            self.start_monitoring_dashboard()
            
            # Phase 4: Attack Simulations
            self.logger.info("PHASE 4: Attack Simulations")
            self.run_sql_injection_attack()
            time.sleep(2)
            self.run_brute_force_attack()
            
            # Phase 5: Reporting
            self.logger.info("PHASE 5: Reporting")
            report = self.generate_session_report()
            
            self.logger.info("✅ Training session completed successfully!")
            
            # Print summary
            print("\n" + "="*60)
            print("🎯 SECURITY TRAINING SESSION COMPLETED!")
            print("="*60)
            print(f"Session ID: {self.session_id}")
            print(f"Juice Shop: http://localhost:3000")
            print(f"Monitoring: http://localhost:5000") 
            print(f"Reports: {os.path.join(self.base_dir, 'reports')}")
            print(f"Logs: {os.path.join(self.base_dir, 'logs')}")
            print("="*60)
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Training session failed: {e}")
            return False

if __name__ == "__main__":
    manager = TrainingSessionManager()
    success = manager.run_complete_session()
    
    if success:
        print("\n🎉 Training session is running!")
        print("💡 Keep this window open to maintain the services.")
        print("🛑 Press Ctrl+C to stop all services.")
        
        try:
            # Keep the script running
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping training session...")
    else:
        print("\n❌ Training session failed. Check the logs for details.")
        sys.exit(1)
