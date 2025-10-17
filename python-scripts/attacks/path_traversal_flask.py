# python-scripts/attacks/path_traversal.py
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
    format='%(asctime)s - PATH_TRAVERSAL - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PathTraversalSimulator:
    def __init__(self):
        self.successful_traversals = 0
        self.total_attempts = 0
        self.payloads = [
            "../../../etc/passwd",
            "../../../etc/hosts",
            "../../../../windows/win.ini",
            "....//....//....//etc/passwd",
            "../".repeat(10) + "etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd"
        ]

    def test_payload(self, payload):
        """Test a path traversal payload"""
        try:
            self.total_attempts += 1
            
            # Simulate path traversal detection
            if any(pattern in payload for pattern in ["../", "..\\", "..%2f", "....//"]):
                self.successful_traversals += 1
                logger.info(f"✅ Path Traversal successful: {payload}")
                return True
            else:
                logger.debug(f"❌ Path Traversal failed: {payload}")
                return False
                
        except Exception as e:
            logger.error(f"Error testing payload {payload} - {e}")
            return False

    def run_traversal_attack(self):
        """Run path traversal attack"""
        logger.info("📁 Starting Path Traversal Attack...")
        
        for i, payload in enumerate(self.payloads, 1):
            logger.info(f"🛡️ Testing payload {i}/{len(self.payloads)}: {payload}")
            self.test_payload(payload)
            
        return self.successful_traversals, self.total_attempts

    def generate_report(self):
        """Generate attack report"""
        success_rate = (self.successful_traversals / self.total_attempts * 100) if self.total_attempts > 0 else 0
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "attack_type": "Path Traversal",
            "summary": {
                "total_attempts": self.total_attempts,
                "successful_traversals": self.successful_traversals,
                "success_rate": success_rate,
                "payloads_tested": len(self.payloads)
            },
            "details": {
                "techniques_used": [
                    "Directory traversal",
                    "URL encoding bypass",
                    "Double encoding bypass"
                ],
                "vulnerabilities_found": [
                    "Unsanitized file paths",
                    "Missing input validation",
                    "Insecure file operations"
                ],
                "recommendations": [
                    "Validate and sanitize file paths",
                    "Use whitelist for allowed files",
                    "Implement proper access controls",
                    "Use secure file operations",
                    "Regular security testing"
                ]
            }
        }
        
        return report

def main():
    try:
        logger.info("🚀 Starting Path Traversal Attack Simulation")
        
        simulator = PathTraversalSimulator()
        
        # Run traversal attack
        success, total = simulator.run_traversal_attack()
        
        # Generate report
        report = simulator.generate_report()
        
        # Save report
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        report_path = os.path.join(reports_dir, 'path_traversal_report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📊 Path Traversal Simulation Complete!")
        logger.info(f"📈 Success Rate: {report['summary']['success_rate']:.2f}%")
        logger.info(f"📄 Report saved to: {report_path}")
        
        # Exit successfully
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"❌ Path Traversal Simulation Failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()