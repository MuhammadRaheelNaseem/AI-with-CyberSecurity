import requests
import json
import time
import logging
import os
from datetime import datetime

class SecurityControlsTester:
    def __init__(self, target_url="http://localhost:3000"):
        self.target_url = target_url
        self.session = requests.Session()
        self.results = {
            'authentication': {},
            'input_validation': {},
            'security_headers': {}
        }
        self.score = {
            'authentication': 0,
            'input_validation': 0,
            'security_headers': 0,
            'total': 0
        }

        # Ensure required directories exist
        os.makedirs('../logs/security', exist_ok=True)
        os.makedirs('../reports', exist_ok=True)

        # Setup logging (UTF-8 safe)
        log_file = '../logs/security/security_controls_test.log'
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        stream_handler = logging.StreamHandler()

        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - SECURITY - %(levelname)s - %(message)s',
            handlers=[file_handler, stream_handler]
        )
        self.logger = logging.getLogger(__name__)

    def safe_log(self, level, message_with_emoji, plain_message=None):
        """Log emoji to file, plain text to console to avoid cp1252 errors on Windows"""
        if plain_message is None:
            plain_message = (
                message_with_emoji
                .replace("🛡️", "")
                .replace("📊", "")
                .replace("✅", "")
                .replace("❌", "")
                .replace("⚠️", "")
                .strip()
            )
        getattr(self.logger, level)(message_with_emoji)
        level_upper = level.upper()
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - SECURITY - {level_upper} - {plain_message}")

    # ———————————————————————————————
    # PHASE 1: AUTHENTICATION CONTROLS
    # ———————————————————————————————
    def test_password_policy(self):
        """Test if weak passwords are accepted (should fail in secure app)"""
        self.safe_log('info', "   Testing Password Policy")
        weak_user = {
            "email": "weakuser@test.com",
            "password": "123",
            "passwordRepeat": "123",
            "securityQuestion": {"id": 1, "question": "Test?"},
            "securityAnswer": "test"
        }
        try:
            res = self.session.post(f"{self.target_url}/api/Users", json=weak_user, timeout=10)
            if res.status_code == 201:
                self.safe_log('warning', "❌ Weak password accepted – Password policy not enforced")
                self.results['authentication']['password_policy'] = 'WEAK'
            else:
                self.safe_log('info', "✅ Password policy enforced")
                self.results['authentication']['password_policy'] = 'ENFORCED'
                self.score['authentication'] += 10
        except Exception as e:
            self.safe_log('error', f"Error testing password policy: {e}")
            self.results['authentication']['password_policy'] = 'ERROR'

    def test_account_lockout(self):
        """Test if account lockout works after repeated failed logins"""
        self.safe_log('info', "   Testing Account Lockout Mechanism")
        for i in range(6):  # Try 6 bad logins
            try:
                res = self.session.post(
                    f"{self.target_url}/rest/user/login",
                    json={"email": "nonexistent@test.com", "password": "wrong"},
                    timeout=5
                )
                if res.status_code == 429:
                    self.safe_log('info', "✅ Account lockout / rate limiting triggered")
                    self.results['authentication']['lockout'] = 'ENFORCED'
                    self.score['authentication'] += 10
                    return
            except:
                pass
            time.sleep(0.5)
        self.safe_log('warning', "❌ No lockout or rate limiting detected")
        self.results['authentication']['lockout'] = 'MISSING'

    def test_session_management(self):
        """Check if session tokens are properly handled"""
        self.safe_log('info', "   Testing Session Management")
        # Register & login
        email = "session@test.com"
        pwd = "SecurePass123!"
        user = {
            "email": email,
            "password": pwd,
            "passwordRepeat": pwd,
            "securityQuestion": {"id": 1, "question": "Test?"},
            "securityAnswer": "test"
        }
        try:
            self.session.post(f"{self.target_url}/api/Users", json=user)
            login_res = self.session.post(f"{self.target_url}/rest/user/login", json={"email": email, "password": pwd})
            if login_res.status_code == 200:
                token = login_res.json().get('authentication', {}).get('token')
                if token:
                    # Try accessing protected endpoint
                    profile_res = self.session.get(f"{self.target_url}/rest/user/whoami")
                    if profile_res.status_code == 200:
                        self.safe_log('info', "✅ Session management working")
                        self.results['authentication']['session'] = 'SECURE'
                        self.score['authentication'] += 5
                    else:
                        self.results['authentication']['session'] = 'BROKEN'
                else:
                    self.results['authentication']['session'] = 'NO_TOKEN'
            else:
                self.results['authentication']['session'] = 'LOGIN_FAILED'
        except Exception as e:
            self.safe_log('error', f"Session test error: {e}")
            self.results['authentication']['session'] = 'ERROR'

    def test_auth_controls(self):
        self.safe_log('info', "Phase 1: Authentication Controls")
        self.test_password_policy()
        self.test_account_lockout()
        self.test_session_management()

    # ———————————————————————————————
    # PHASE 2: INPUT VALIDATION
    # ———————————————————————————————
    def test_input_validation(self):
        self.safe_log('info', "Phase 2: Input Validation")
        test_payloads = [
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "../../../../etc/passwd",
            "{{7*7}}"
        ]
        vulnerable_endpoints = 0
        for payload in test_payloads:
            try:
                res = self.session.get(f"{self.target_url}/rest/products/search", params={"q": payload}, timeout=5)
                if any(x in res.text.lower() for x in ['<script>', 'sql', 'root:', '49']):
                    vulnerable_endpoints += 1
            except:
                pass
        if vulnerable_endpoints == 0:
            self.safe_log('info', "✅ Input validation appears robust")
            self.score['input_validation'] = 25
            self.results['input_validation']['status'] = 'STRONG'
        elif vulnerable_endpoints <= 2:
            self.safe_log('warning', "⚠️ Partial input validation – some payloads reflected")
            self.score['input_validation'] = 10
            self.results['input_validation']['status'] = 'WEAK'
        else:
            self.safe_log('error', "❌ No input validation detected")
            self.results['input_validation']['status'] = 'MISSING'

    # ———————————————————————————————
    # PHASE 3: SECURITY HEADERS
    # ———————————————————————————————
    def test_security_headers(self):
        self.safe_log('info', "Phase 3: Security Headers")
        try:
            res = self.session.get(self.target_url, timeout=5)
            headers = res.headers
            missing = []
            if 'Content-Security-Policy' not in headers:
                missing.append('CSP')
            if 'X-Frame-Options' not in headers:
                missing.append('X-Frame-Options')
            if 'X-Content-Type-Options' not in headers:
                missing.append('X-Content-Type-Options')
            if 'Strict-Transport-Security' not in headers:
                missing.append('HSTS')

            if not missing:
                self.safe_log('info', "✅ All critical security headers present")
                self.score['security_headers'] = 25
                self.results['security_headers']['status'] = 'COMPLETE'
            else:
                self.safe_log('warning', f"❌ Missing security headers: {', '.join(missing)}")
                self.score['security_headers'] = max(0, 25 - len(missing) * 5)
                self.results['security_headers']['missing'] = missing
                self.results['security_headers']['status'] = 'INCOMPLETE'
        except Exception as e:
            self.safe_log('error', f"Header test error: {e}")
            self.results['security_headers']['status'] = 'ERROR'

    # ———————————————————————————————
    # REPORTING
    # ———————————————————————————————
    def generate_report(self):
        self.safe_log('info', "📊 Generating Security Assessment Report...")

        total_score = self.score['authentication'] + self.score['input_validation'] + self.score['security_headers']
        max_score = 100
        rating = "POOR"
        if total_score >= 80:
            rating = "EXCELLENT"
        elif total_score >= 60:
            rating = "GOOD"
        elif total_score >= 40:
            rating = "FAIR"
        else:
            rating = "POOR"

        report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.target_url,
            'score': {
                'authentication': self.score['authentication'],
                'input_validation': self.score['input_validation'],
                'security_headers': self.score['security_headers'],
                'total': total_score,
                'max_possible': max_score,
                'rating': rating
            },
            'detailed_results': self.results,
            'recommendations': [
                "Enforce strong password policies (min length, complexity)",
                "Implement account lockout after 3-5 failed attempts",
                "Add rate limiting on authentication endpoints",
                "Sanitize and validate all user inputs",
                "Deploy Content Security Policy (CSP)",
                "Set security headers: X-Frame-Options, X-Content-Type-Options, HSTS"
            ]
        }

        report_path = '../reports/security_controls_report.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        # Print summary
        print(f"\n🛡️ SECURITY ASSESSMENT SUMMARY")
        print(f"   Overall Security Score: {total_score}.0/100")
        print(f"   Security Rating: {rating}")
        print(f"   Authentication: {self.score['authentication']}.0/50")
        print(f"   Input Validation: {self.score['input_validation']}.0/25")
        print(f"   Security Headers: {self.score['security_headers']}.0/25")

        return report

    def run_complete_test(self):
        self.safe_log('info', "🛡️ Starting Comprehensive Security Controls Testing")
        self.test_auth_controls()
        self.test_input_validation()
        self.test_security_headers()
        return self.generate_report()


if __name__ == "__main__":
    tester = SecurityControlsTester()
    tester.run_complete_test()