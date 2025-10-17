"""
ONE-TIME MODEL TRAINING SCRIPT
Run this once to train and save the AI model
"""

import sys
import os
import time
from datetime import datetime

def main():
    print("🔧 ONE-TIME MODEL TRAINING SCRIPT")
    print("=" * 50)
    
    # Add current directory to path
    sys.path.append(os.path.dirname(__file__))
    
    try:
        from ai_models.master_threat_model import train_and_save_model
        # from ai_models.MasterThreatModelV2 import train_and_save_enhanced_model
        
        print("🚀 Starting model training...")
        print("This will train both:")
        print("  🤖 Text-based threat classifier")
        print("  🔍 Anomaly detection model")
        print("  💾 Save all models as pickle files")
        print("\nEstimated time: 1-2 minutes")
        print("-" * 50)
        
        start_time = time.time()
        
        # Train and save model
        # model = train_and_save_enhanced_model()
        model = train_and_save_model()
        
        end_time = time.time()
        training_time = end_time - start_time
        
        print(f"\n✅ MODEL TRAINING COMPLETED!")
        print(f"⏱️  Training time: {training_time:.2f} seconds")
        print(f"📁 Models saved in: ../models/")
        print(f"📊 Reports saved in: ../reports/")
        
        print("\n🎯 NOW YOU CAN USE THE MODEL INSTANTLY!")
        print("Run: python use_trained_model.py")
        
    except Exception as e:
        print(f"❌ Error during training: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()