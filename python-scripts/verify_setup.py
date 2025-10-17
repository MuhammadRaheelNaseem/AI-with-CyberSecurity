import sys
import subprocess
import requests

def check_python():
    try:
        result = subprocess.run([sys.executable, '--version'], capture_output=True, text=True)
        print(f"✅ Python: {result.stdout.strip()}")
        return True
    except:
        print("❌ Python not found")
        return False

def check_nodejs():
    try:
        result = subprocess.run(['node', '--version'], capture_output=True, text=True)
        print(f"✅ Node.js: {result.stdout.strip()}")
        return True
    except:
        print("❌ Node.js not found")
        return False

def check_juice_shop():
    try:
        response = requests.get('http://localhost:3000', timeout=5)
        if response.status_code == 200:
            print("✅ Juice Shop: Running")
            return True
        else:
            print("❌ Juice Shop: Not accessible")
            return False
    except:
        print("❌ Juice Shop: Not running")
        return False

def check_dashboard():
    try:
        response = requests.get('http://localhost:5000', timeout=5)
        if response.status_code == 200:
            print("✅ Dashboard: Running")
            return True
        else:
            print("❌ Dashboard: Not accessible")
            return False
    except:
        print("❌ Dashboard: Not running")
        return False

def main():
    print("🔍 Verifying Security Training Lab Setup...")
    print("-" * 40)
    
    checks = [
        check_python(),
        check_nodejs(), 
        check_juice_shop(),
        check_dashboard()
    ]
    
    print("-" * 40)
    if all(checks):
        print("🎉 All checks passed! Training lab is ready.")
    else:
        print("❌ Some checks failed. Please review the setup.")

if __name__ == "__main__":
    main()
