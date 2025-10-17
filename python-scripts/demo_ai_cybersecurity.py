"""
LIVE DEMO SCRIPT FOR AI CYBERSECURITY SESSION
Covers: Threat Detection, Penetration Testing, Threat Hunting, AI Defense
"""

from ai_models.real_time_detector import get_detector
import time

def live_demo():
    print("🎯 LIVE AI CYBERSECURITY DEMONSTRATION")
    print("=" * 60)
    
    # Load AI model
    detector = get_detector()
    print("✅ AI Threat Detection Model Loaded")
    
    # Demo 1: Traditional Cyber Threats
    print("\n🔓 PHASE 1: TRADITIONAL CYBER THREATS")
    print("-" * 40)
    
    cyber_threats = [
        ("SQL Injection", "' OR 1=1--", "Bypasses authentication"),
        ("XSS Attack", "<script>alert('XSS')</script>", "Executes malicious scripts"),
        ("Path Traversal", "../../../etc/passwd", "Accesses sensitive files"),
        ("Command Injection", "; ls -la", "Executes system commands"),
        ("Brute Force", "admin:password123", "Credential guessing")
    ]
    
    for threat_name, payload, description in cyber_threats:
        print(f"🔍 {threat_name}: {payload}")
        print(f"   Impact: {description}")
    
    # Demo 2: AI-Powered Detection
    print("\n🤖 PHASE 2: AI-POWERED THREAT DETECTION")
    print("-" * 40)
    
    test_cases = [
        "normal user login",
        "SELECT * FROM users WHERE 1=1",
        "<img src=x onerror=stealCookies()>",
        "cat /etc/passwd",
        "legitimate API call"
    ]
    
    for i, test_input in enumerate(test_cases, 1):
        print(f"\nTest {i}: {test_input}")
        result = detector.analyze_text(test_input)
        
        if result['is_malicious']:
            print(f"   🚨 AI DETECTION: {result['prediction'].upper()}")
            print(f"   Confidence: {result['confidence']:.1%}")
            print(f"   Threat Level: {result['threat_level']}")
            print(f"   ✅ AI Recommendation: BLOCK & ALERT")
        else:
            print(f"   ✅ AI ASSESSMENT: NORMAL TRAFFIC")
            print(f"   Confidence: {result['confidence']:.1%}")
            print(f"   ✅ AI Recommendation: ALLOW")
        
        time.sleep(1)  # Dramatic effect
    
    # Demo 3: Threat Hunting with Anomaly Detection
    print("\n🔍 PHASE 3: AI THREAT HUNTING - ANOMALY DETECTION")
    print("-" * 40)
    
    traffic_patterns = [
        {"type": "Normal Traffic", "features": {
            'request_size': 1500, 'response_time': 0.3, 
            'requests_per_minute': 15, 'error_rate': 0.02
        }},
        {"type": "DDoS Attack", "features": {
            'request_size': 200, 'response_time': 0.1,
            'requests_per_minute': 1000, 'error_rate': 0.01
        }},
        {"type": "Data Exfiltration", "features": {
            'request_size': 50000, 'response_time': 2.5,
            'requests_per_minute': 2, 'error_rate': 0.8
        }}
    ]
    
    for pattern in traffic_patterns:
        print(f"\n📊 Analyzing: {pattern['type']}")
        result = detector.analyze_traffic(pattern['features'])
        
        if result['is_anomaly']:
            print(f"   🚨 ANOMALY DETECTED!")
            print(f"   Anomaly Score: {result['anomaly_score']:.3f}")
            print(f"   Confidence: {result['confidence']:.1%}")
            print(f"   ✅ AI Recommendation: INVESTIGATE IMMEDIATELY")
        else:
            print(f"   ✅ NORMAL BEHAVIOR")
            print(f"   Anomaly Score: {result['anomaly_score']:.3f}")
            print(f"   ✅ AI Recommendation: CONTINUE MONITORING")
        
        time.sleep(1)
    
    # Demo 4: Building AI Defense
    print("\n🛡️ PHASE 4: BUILDING AI-POWERED CYBER DEFENSE")
    print("-" * 40)
    
    defense_strategies = [
        "1. PATTERN RECOGNITION: ML models learn attack signatures",
        "2. BEHAVIORAL ANALYSIS: Detect deviations from normal patterns", 
        "3. REAL-TIME SCORING: Instant threat confidence scoring",
        "4. AUTOMATED RESPONSE: AI recommends block/allow decisions",
        "5. CONTINUOUS LEARNING: Models improve with new attack data"
    ]
    
    for strategy in defense_strategies:
        print(strategy)
        time.sleep(0.5)
    
    print("\n" + "=" * 60)
    print("🎯 DEMONSTRATION COMPLETE!")
    print("💡 Key Takeaway: AI transforms cybersecurity from:")
    print("   Reactive (after breach) → Proactive (prevent breach)")
    print("   Signature-based → Behavior-based")
    print("   Manual analysis → Automated intelligence")

if __name__ == "__main__":
    live_demo()