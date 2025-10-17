# python-scripts/attacks/brute_force.py
import requests
import time
import json
import logging
import sys
import os
from datetime import datetime

# Add the project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - BRUTE_FORCE - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BruteForceSimulator:
    def __init__(self):
        self.target_url = "http://localhost:3000"  # Change to your target
        self.successful_attempts = 0
        self.total_attempts = 0
        self.common_passwords = [
            "admin", "password", "123456", "password123", "admin123",
            "test", "guest", "root", "default", "pass"
        ]
        self.common_usernames = [
            "admin", "user", "test", "guest", "root",
            "administrator", "demo", "api", "system"
        ]

    def generate_credentials(self):
        """Generate credential pairs for testing"""
        credentials = []
        for username in self.common_usernames[:5]:
            for password in self.common_passwords[:5]:
                credentials.append((username, password))
        return credentials

    def test_credential(self, username, password):
        """Test a single credential pair"""
        try:
            # Simulate login attempt - in real scenario, this would be HTTP request
            self.total_attempts += 1
            
            # Simulate different response scenarios
            if username == "admin" and password == "admin123":
                self.successful_attempts += 1
                logger.info(f"✅ Successful login: {username}:{password}")
                return True
            elif username == "user" and password == "password123":
                self.successful_attempts += 1
                logger.info(f"✅ Successful login: {username}:{password}")
                return True
            else:
                logger.debug(f"❌ Failed login: {username}:{password}")
                return False
                
        except Exception as e:
            logger.error(f"Error testing {username}:{password} - {e}")
            return False

    def run_sequential_attack(self):
        """Run sequential brute force attack"""
        logger.info("🚀 Starting sequential brute force attack...")
        credentials = self.generate_credentials()
        
        for i, (username, password) in enumerate(credentials, 1):
            logger.info(f"🔑 Attempt {i}/{len(credentials)}: {username}:{password}")
            self.test_credential(username, password)
            time.sleep(0.1)  # Small delay to simulate real attack
            
        return self.successful_attempts, self.total_attempts

    def run_dictionary_attack(self):
        """Run dictionary-based attack"""
        logger.info("📚 Starting dictionary attack...")
        
        # Simulate dictionary attack with common passwords
        username = "admin"  # Target a specific user
        successful = 0
        
        for i, password in enumerate(self.common_passwords, 1):
            logger.info(f"📖 Dictionary attempt {i}/{len(self.common_passwords)}: {password}")
            if self.test_credential(username, password):
                successful += 1
            time.sleep(0.1)
            
        return successful, len(self.common_passwords)

    def generate_report(self):
        """Generate attack report"""
        success_rate = (self.successful_attempts / self.total_attempts * 100) if self.total_attempts > 0 else 0
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": "Brute Force",
            "summary": {
                "total_attempts": self.total_attempts,
                "successful_attempts": self.successful_attempts,
                "success_rate": success_rate,
                "common_passwords_tested": len(self.common_passwords),
                "common_usernames_tested": len(self.common_usernames)
            },
            "details": {
                "target_url": self.target_url,
                "techniques_used": ["Sequential", "Dictionary"],
                "recommendations": [
                    "Implement account lockout policies",
                    "Use strong password requirements",
                    "Enable multi-factor authentication",
                    "Monitor failed login attempts"
                ]
            }
        }
        
        return report

def main():
    try:
        logger.info("🚀 Starting Brute Force Attack Simulation")
        
        simulator = BruteForceSimulator()
        
        # Run sequential attack
        seq_success, seq_total = simulator.run_sequential_attack()
        
        # Run dictionary attack  
        dict_success, dict_total = simulator.run_dictionary_attack()
        
        # Generate report
        report = simulator.generate_report()
        
        # Save report
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        report_path = os.path.join(reports_dir, 'brute_force_report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📊 Brute Force Simulation Complete!")
        logger.info(f"📈 Success Rate: {report['summary']['success_rate']:.2f}%")
        logger.info(f"📄 Report saved to: {report_path}")
        
        # Exit successfully
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"❌ Brute Force Simulation Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()