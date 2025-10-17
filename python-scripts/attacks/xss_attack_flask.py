# python-scripts/attacks/xss_attack.py
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
    format='%(asctime)s - XSS_ATTACK - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class XSSSimulator:
    def __init__(self):
        self.successful_xss = 0
        self.total_attempts = 0
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<link rel=stylesheet href=javascript:alert('XSS')>"
        ]

    def test_payload(self, payload):
        """Test a XSS payload"""
        try:
            self.total_attempts += 1
            
            # Simulate XSS detection
            if any(pattern in payload for pattern in ["<script>", "onerror=", "onload=", "javascript:"]):
                self.successful_xss += 1
                logger.info(f"✅ XSS successful: {payload}")
                return True
            else:
                logger.debug(f"❌ XSS failed: {payload}")
                return False
                
        except Exception as e:
            logger.error(f"Error testing payload {payload} - {e}")
            return False

    def run_xss_attack(self):
        """Run XSS attack"""
        logger.info("🎯 Starting XSS Attack...")
        
        for i, payload in enumerate(self.payloads, 1):
            logger.info(f"🛡️ Testing payload {i}/{len(self.payloads)}: {payload[:50]}...")
            self.test_payload(payload)
            
        return self.successful_xss, self.total_attempts

    def generate_report(self):
        """Generate attack report"""
        success_rate = (self.successful_xss / self.total_attempts * 100) if self.total_attempts > 0 else 0
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": "XSS Attack",
            "summary": {
                "total_attempts": self.total_attempts,
                "successful_xss": self.successful_xss,
                "success_rate": success_rate,
                "payloads_tested": len(self.payloads)
            },
            "details": {
                "payload_types": ["Reflected XSS", "Stored XSS", "DOM-based XSS"],
                "vulnerabilities_found": [
                    "Unsanitized user input",
                    "Missing Content Security Policy",
                    "Inline JavaScript execution"
                ],
                "recommendations": [
                    "Implement input validation and sanitization",
                    "Use Content Security Policy (CSP)",
                    "Encode output properly",
                    "Use HTTPOnly cookies",
                    "Regular security testing"
                ]
            }
        }
        
        return report

def main():
    try:
        logger.info("🚀 Starting XSS Attack Simulation")
        
        simulator = XSSSimulator()
        
        # Run XSS attack
        success, total = simulator.run_xss_attack()
        
        # Generate report
        report = simulator.generate_report()
        
        # Save report
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        report_path = os.path.join(reports_dir, 'xss_attack_report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📊 XSS Simulation Complete!")
        logger.info(f"📈 Success Rate: {report['summary']['success_rate']:.2f}%")
        logger.info(f"📄 Report saved to: {report_path}")
        
        # Exit successfully
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"❌ XSS Simulation Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()