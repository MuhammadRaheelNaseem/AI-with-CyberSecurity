# python-scripts/attacks/sql_injection.py
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
    format='%(asctime)s - SQL_INJECTION - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SQLInjectionSimulator:
    def __init__(self):
        self.successful_injections = 0
        self.total_attempts = 0
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' UNION SELECT 1,2,3 --",
            "' AND 1=1 --",
            "' AND 1=2 --",
            "' OR EXISTS(SELECT * FROM users) --",
            "' OR 1=1--"
        ]

    def test_payload(self, payload):
        """Test a SQL injection payload"""
        try:
            self.total_attempts += 1
            
            # Simulate different injection scenarios
            if any(pattern in payload for pattern in ["' OR '1'='1", "admin' --", "' OR 1=1--"]):
                self.successful_injections += 1
                logger.info(f"✅ SQL Injection successful: {payload}")
                return True
            else:
                logger.debug(f"❌ SQL Injection failed: {payload}")
                return False
                
        except Exception as e:
            logger.error(f"Error testing payload {payload} - {e}")
            return False

    def run_injection_attack(self):
        """Run SQL injection attack"""
        logger.info("💉 Starting SQL Injection attack...")
        
        for i, payload in enumerate(self.payloads, 1):
            logger.info(f"🛡️ Testing payload {i}/{len(self.payloads)}: {payload}")
            self.test_payload(payload)
            
        return self.successful_injections, self.total_attempts

    def generate_report(self):
        """Generate attack report"""
        success_rate = (self.successful_injections / self.total_attempts * 100) if self.total_attempts > 0 else 0
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": "SQL Injection",
            "summary": {
                "total_attempts": self.total_attempts,
                "successful_injections": self.successful_injections,
                "success_rate": success_rate,
                "payloads_tested": len(self.payloads)
            },
            "details": {
                "payloads_used": self.payloads,
                "vulnerabilities_found": [
                    "Boolean-based blind SQL injection",
                    "Union-based SQL injection"
                ],
                "recommendations": [
                    "Use parameterized queries",
                    "Implement input validation",
                    "Use stored procedures",
                    "Apply principle of least privilege",
                    "Regular security testing"
                ]
            }
        }
        
        return report

def main():
    try:
        logger.info("🚀 Starting SQL Injection Attack Simulation")
        
        simulator = SQLInjectionSimulator()
        
        # Run injection attack
        success, total = simulator.run_injection_attack()
        
        # Generate report
        report = simulator.generate_report()
        
        # Save report
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        report_path = os.path.join(reports_dir, 'sql_injection_report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📊 SQL Injection Simulation Complete!")
        logger.info(f"📈 Success Rate: {report['summary']['success_rate']:.2f}%")
        logger.info(f"📄 Report saved to: {report_path}")
        
        # Exit successfully
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"❌ SQL Injection Simulation Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()