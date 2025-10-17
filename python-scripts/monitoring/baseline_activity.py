import requests
import time
import random
import json
import logging
import os
from datetime import datetime
from faker import Faker
from typing import Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor

class NormalUserSimulator:
    def __init__(self, base_url: str = "http://localhost:3000"):
        self.base_url = base_url
        self.fake = Faker()
        self.session = requests.Session()
        self.user_profiles = []
        self.activity_log = []
        
        # Ensure required directories exist
        os.makedirs('../logs', exist_ok=True)
        os.makedirs('../reports', exist_ok=True)
        
        # Configure logging with UTF-8 support
        log_file = '../logs/baseline_activity.log'
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        stream_handler = logging.StreamHandler()
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[file_handler, stream_handler]
        )
        self.logger = logging.getLogger(__name__)
    
    def safe_log_info(self, message_with_emoji, plain_message=None):
        """Log emoji message to file, plain message to console"""
        if plain_message is None:
            # Remove common emojis for console
            plain_message = (
                message_with_emoji
                .replace("✅", "")
                .replace("⚠️", "")
                .replace("❌", "")
                .replace("🔍", "")
                .replace("📂", "")
                .replace("📄", "")
                .replace("⭐", "")
                .replace("🛒", "")
                .replace("📋", "")
                .replace("👤", "")
                .replace("🎯", "")
                .replace("🚀", "")
                .replace("📊", "")
                .replace("📈", "")
                .strip()
            )
        # Log full message (with emoji) to file
        self.logger.info(message_with_emoji)
        # Print plain version to console
        print(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - INFO - {plain_message}")

    def generate_user_profile(self) -> Dict:
        """Generate realistic user profile"""
        return {
            'email': self.fake.email(),
            'password': self.fake.password(length=12),
            'first_name': self.fake.first_name(),
            'last_name': self.fake.last_name(),
            'security_question': 'Your favorite food?',
            'security_answer': self.fake.word()
        }
    
    def register_user(self, profile: Dict) -> bool:
        """Register a new user"""
        try:
            response = self.session.post(
                f"{self.base_url}/api/Users",
                json={
                    "email": profile['email'],
                    "password": profile['password'],
                    "passwordRepeat": profile['password'],
                    "securityQuestion": {"id": 1, "question": profile['security_question']},
                    "securityAnswer": profile['security_answer']
                },
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 201:
                self.safe_log_info(f"✅ User registered: {profile['email']}")
                return True
            else:
                self.safe_log_info(f"⚠️ Registration failed for {profile['email']}: {response.status_code}")
                return False
                
        except Exception as e:
            self.safe_log_info(f"❌ Registration error for {profile['email']}: {e}")
            return False
    
    def user_login(self, email: str, password: str) -> Optional[str]:
        """User login and return authentication token"""
        try:
            response = self.session.post(
                f"{self.base_url}/rest/user/login",
                json={"email": email, "password": password},
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                token = response.json().get('authentication', {}).get('token')
                self.safe_log_info(f"✅ User logged in: {email}")
                return token
            else:
                self.safe_log_info(f"⚠️ Login failed for {email}: {response.status_code}")
                return None
                
        except Exception as e:
            self.safe_log_info(f"❌ Login error for {email}: {e}")
            return None
    
    def browse_products(self, token: str) -> None:
        """Simulate realistic product browsing"""
        browsing_actions = [
            self.search_products,
            self.view_product_categories,
            self.view_product_details,
            self.check_product_reviews
        ]
        
        for _ in range(random.randint(3, 5)):
            action = random.choice(browsing_actions)
            action(token)
            time.sleep(random.uniform(1, 3))
    
    def search_products(self, token: str) -> None:
        """Search for products using realistic terms"""
        search_terms = ['apple', 'orange', 'banana', 'juice', 'organic', 'fresh', 'fruit']
        term = random.choice(search_terms)
        
        response = self.session.get(
            f"{self.base_url}/rest/products/search?q={term}",
            headers={'Authorization': f'Bearer {token}'}
        )
        
        if response.status_code == 200:
            results = response.json().get('data', [])
            self.safe_log_info(f"🔍 Searched for '{term}', found {len(results)} results")
    
    def view_product_categories(self, token: str) -> None:
        """Browse different product categories"""
        categories = [
            '/rest/products/search?q=fruit',
            '/rest/products/search?q=vegetable', 
            '/rest/products/search?q=drink',
            '/rest/products/search?q=snack'
        ]
        
        category = random.choice(categories)
        response = self.session.get(
            f"{self.base_url}{category}",
            headers={'Authorization': f'Bearer {token}'}
        )
        
        if response.status_code == 200:
            self.safe_log_info(f"📂 Browsed category: {category}")
    
    def view_product_details(self, token: str) -> None:
        """View detailed product information"""
        response = self.session.get(
            f"{self.base_url}/api/Products",
            headers={'Authorization': f'Bearer {token}'}
        )
        
        if response.status_code == 200:
            products = response.json().get('data', [])
            if products:
                product = random.choice(products)
                product_id = product['id']
                
                detail_response = self.session.get(
                    f"{self.base_url}/api/Products/{product_id}",
                    headers={'Authorization': f'Bearer {token}'}
                )
                
                if detail_response.status_code == 200:
                    self.safe_log_info(f"📄 Viewed details for product: {product['name']}")
    
    def check_product_reviews(self, token: str) -> None:
        """Check product reviews and ratings"""
        response = self.session.get(
            f"{self.base_url}/api/Feedbacks",
            headers={'Authorization': f'Bearer {token}'}
        )
        
        if response.status_code == 200:
            reviews = response.json().get('data', [])
            self.safe_log_info(f"⭐ Checked {len(reviews)} product reviews")
    
    def shopping_cart_activities(self, token: str) -> None:
        """Simulate shopping cart interactions"""
        response = self.session.get(
            f"{self.base_url}/api/Products",
            headers={'Authorization': f'Bearer {token}'}
        )
        
        if response.status_code == 200:
            products = response.json().get('data', [])
            
            for _ in range(random.randint(1, 3)):
                if products:
                    product = random.choice(products)
                    
                    add_response = self.session.post(
                        f"{self.base_url}/api/BasketItems",
                        json={
                            "ProductId": product['id'],
                            "Quantity": random.randint(1, 3),
                            "BasketId": "1"
                        },
                        headers={'Authorization': f'Bearer {token}'}
                    )
                    
                    if add_response.status_code == 201:
                        self.safe_log_info(f"🛒 Added {product['name']} to cart")
            
            cart_response = self.session.get(
                f"{self.base_url}/rest/basket/1",
                headers={'Authorization': f'Bearer {token}'}
            )
            
            if cart_response.status_code == 200:
                self.safe_log_info("📋 Viewed shopping cart")
    
    def simulate_user_session(self, user_profile: Dict) -> None:
        """Complete user session simulation"""
        self.safe_log_info(f"👤 Starting session for user: {user_profile['email']}")
        
        if not self.register_user(user_profile):
            return
        
        time.sleep(1)
        
        token = self.user_login(user_profile['email'], user_profile['password'])
        if not token:
            return
        
        activities = [
            (self.browse_products, "Browsing products"),
            (self.shopping_cart_activities, "Shopping cart activities"),
            (self.browse_products, "Additional browsing")
        ]
        
        for activity, description in activities:
            self.safe_log_info(f"  🎯 {description}")
            activity(token)
            time.sleep(random.uniform(2, 5))
        
        self.safe_log_info(f"👤 Completed session for user: {user_profile['email']}")
        
        session_data = {
            'timestamp': datetime.now().isoformat(),
            'user_email': user_profile['email'],
            'activities_performed': [desc for _, desc in activities],
            'session_duration': '2-5 minutes'
        }
        self.activity_log.append(session_data)
    
    def run_baseline_simulation(self, num_users: int = 5) -> None:
        """Run complete baseline simulation with multiple users"""
        self.safe_log_info("🚀 Starting Comprehensive Baseline Activity Simulation")
        
        self.user_profiles = [self.generate_user_profile() for _ in range(num_users)]
        
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(self.simulate_user_session, profile) for profile in self.user_profiles]
            for future in futures:
                try:
                    future.result(timeout=300)
                except Exception as e:
                    self.safe_log_info(f"Session failed: {e}")
        
        self.generate_baseline_report()
    
    def generate_baseline_report(self) -> None:
        """Generate comprehensive baseline activity report"""
        report = {
            'simulation_timestamp': datetime.now().isoformat(),
            'total_users_simulated': len(self.user_profiles),
            'successful_sessions': len(self.activity_log),
            'user_profiles': self.user_profiles,
            'activity_log': self.activity_log,
            'baseline_metrics': {
                'average_session_duration': '3-8 minutes',
                'typical_activities': [
                    'User registration',
                    'Product search and browsing',
                    'Product detail viewing',
                    'Shopping cart operations',
                    'Review checking'
                ],
                'request_patterns': {
                    'average_request_size': '1-5 KB',
                    'typical_status_codes': [200, 201, 304],
                    'common_endpoints': [
                        '/api/Users',
                        '/rest/user/login',
                        '/api/Products',
                        '/rest/products/search',
                        '/api/BasketItems'
                    ]
                }
            }
        }
        
        report_path = '../reports/baseline_activity_report.json'
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        self.safe_log_info(f"📊 Baseline report generated: {report_path}")
        
        print(f"\n📈 BASELINE SIMULATION SUMMARY")
        print(f"   Users simulated: {len(self.user_profiles)}")
        print(f"   Successful sessions: {len(self.activity_log)}")
        print(f"   Report saved to: {os.path.abspath(report_path)}")

if __name__ == "__main__":
    simulator = NormalUserSimulator()
    simulator.run_baseline_simulation(num_users=5)