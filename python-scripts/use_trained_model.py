"""
INSTANT MODEL USAGE SCRIPT
Use this after training to instantly use the model
"""

import sys
import os
import json
from datetime import datetime

def main():
    print("⚡ INSTANT THREAT DETECTION MODEL")
    print("=" * 50)
    
    # Add current directory to path
    sys.path.append(os.path.dirname(__file__))
    
    try:
        from ai_models.real_time_detector import quick_analyze, get_detector
        
        # Load detector
        detector = get_detector()
        
        print("✅ Model loaded successfully!")
        print("🤖 Ready for instant threat detection")
        print("\nEnter text to analyze (or 'quit' to exit):")
        print("-" * 50)
        
        while True:
            user_input = input("\n🔍 Enter text to analyze: ").strip()
            
            if user_input.lower() in ['quit', 'exit', 'q']:
                break
            
            if not user_input:
                continue
            
            # Analyze the input
            result = quick_analyze(user_input)
            
            if result:
                if result['is_malicious']:
                    print(f"🚨 THREAT DETECTED: {result['prediction']}")
                    print(f"   Threat Level: {result['threat_level']}")
                    print(f"   Confidence: {result['confidence']:.3f}")
                    print(f"   Recommendation: BLOCK THIS REQUEST")
                else:
                    print(f"✅ NORMAL: {result['prediction']}")
                    print(f"   Confidence: {result['confidence']:.3f}")
                    print(f"   Recommendation: ALLOW THIS REQUEST")
                
                # Show probabilities
                print(f"   Details: Malicious confidence: {result['confidence']:.1%}")
            else:
                print("❌ Error analyzing input")
    
    except Exception as e:
        print(f"❌ Error: {e}")
        print("💡 Make sure you've trained the model first by running:")
        print("   python train_model_once.py")

def demo_mode():
    """Run a quick demo with sample inputs"""
    from ai_models.real_time_detector import quick_analyze, get_detector
    
    detector = get_detector()
    
    test_inputs = [
        "normal user login",
        "' OR 1=1--",
        "<script>alert('xss')</script>", 
        "../../../etc/passwd",
        "legitimate search query",
        "'; DROP TABLE users--",
        "<img src=x onerror=alert(1)>"
    ]
    
    print("🎯 DEMO MODE: Instant Threat Detection")
    print("=" * 50)
    
    for input_text in test_inputs:
        result = quick_analyze(input_text)
        
        if result and result['is_malicious']:
            print(f"🚨 BLOCK: {input_text[:40]}... -> {result['prediction']} (conf: {result['confidence']:.3f})")
        elif result:
            print(f"✅ ALLOW: {input_text[:40]}... -> {result['prediction']} (conf: {result['confidence']:.3f})")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == 'demo':
        demo_mode()
    else:
        main()