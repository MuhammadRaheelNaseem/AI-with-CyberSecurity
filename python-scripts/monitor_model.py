"""
MODEL MONITORING SCRIPT
Monitor model performance and health
"""

import pickle
import json
import logging
from datetime import datetime, timedelta
import pandas as pd

class ModelMonitor:
    def __init__(self, model_path='../models/master_threat_model.pkl'):
        self.model_path = model_path
        self.setup_logging()
    
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - MODEL_MONITOR - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def check_model_health(self):
        """Check if model is healthy and loaded properly"""
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            health_report = {
                'timestamp': datetime.now().isoformat(),
                'model_loaded': True,
                'model_trained': model_data.get('is_trained', False),
                'save_date': model_data.get('save_date', 'Unknown'),
                'performance_metrics': model_data.get('performance_metrics', {}),
                'components_loaded': {
                    'text_model': model_data.get('text_model') is not None,
                    'vectorizer': model_data.get('vectorizer') is not None,
                    'anomaly_model': model_data.get('anomaly_model') is not None,
                    'scaler': model_data.get('scaler') is not None
                }
            }
            
            # Check if all components are loaded
            health_report['all_components_healthy'] = all(health_report['components_loaded'].values())
            
            self.logger.info("✅ Model health check passed")
            return health_report
            
        except Exception as e:
            self.logger.error(f"❌ Model health check failed: {e}")
            return {
                'timestamp': datetime.now().isoformat(),
                'model_loaded': False,
                'error': str(e)
            }
    
    def monitor_performance(self):
        """Monitor model performance over time"""
        try:
            # Load recent attack reports to test model
            from ai_models.real_time_detector import RealTimeThreatDetector
            
            detector = RealTimeThreatDetector()
            report = detector.generate_realtime_report()
            
            performance_data = {
                'timestamp': datetime.now().isoformat(),
                'attack_detection_rate': report['attack_analysis_summary']['correctly_identified'] / max(report['attack_analysis_summary']['total_attacks_processed'], 1),
                'false_negative_rate': report['attack_analysis_summary']['false_negatives'] / max(report['attack_analysis_summary']['total_attacks_processed'], 1),
                'total_tests_conducted': len(report['real_time_test_results']),
                'model_accuracy_estimate': None  # Would need ground truth for actual accuracy
            }
            
            # Save performance data
            try:
                with open('../reports/model_performance_history.json', 'r') as f:
                    history = json.load(f)
            except FileNotFoundError:
                history = {'performance_records': []}
            
            history['performance_records'].append(performance_data)
            
            # Keep only last 100 records
            if len(history['performance_records']) > 100:
                history['performance_records'] = history['performance_records'][-100:]
            
            with open('../reports/model_performance_history.json', 'w') as f:
                json.dump(history, f, indent=2)
            
            self.logger.info("✅ Performance monitoring completed")
            return performance_data
            
        except Exception as e:
            self.logger.error(f"❌ Performance monitoring failed: {e}")
            return {'error': str(e)}
    
    def generate_monitoring_report(self):
        """Generate comprehensive monitoring report"""
        self.logger.info("📊 Generating Model Monitoring Report")
        
        health_report = self.check_model_health()
        performance_report = self.monitor_performance()
        
        monitoring_report = {
            'report_time': datetime.now().isoformat(),
            'model_health': health_report,
            'performance_metrics': performance_report,
            'recommendations': []
        }
        
        # Generate recommendations
        if not health_report.get('all_components_healthy', False):
            monitoring_report['recommendations'].append("Retrain and save model - some components are missing")
        
        if performance_report.get('false_negative_rate', 0) > 0.1:
            monitoring_report['recommendations'].append("Consider retraining model - high false negative rate detected")
        
        if health_report.get('performance_metrics', {}).get('text_classifier', {}).get('test_accuracy', 0) < 0.9:
            monitoring_report['recommendations'].append("Model accuracy below 90% - consider retraining with more data")
        
        # Save report
        with open('../reports/model_monitoring_report.json', 'w') as f:
            json.dump(monitoring_report, f, indent=2)
        
        self.logger.info("✅ Monitoring report generated")
        
        # Print summary
        print(f"\n🔍 MODEL MONITORING REPORT")
        print("=" * 50)
        print(f"Model Health: {'✅ HEALTHY' if health_report.get('all_components_healthy') else '❌ UNHEALTHY'}")
        print(f"Detection Rate: {performance_report.get('attack_detection_rate', 0):.1%}")
        print(f"False Negative Rate: {performance_report.get('false_negative_rate', 0):.1%}")
        
        if monitoring_report['recommendations']:
            print(f"\n💡 Recommendations:")
            for rec in monitoring_report['recommendations']:
                print(f"  • {rec}")
        
        return monitoring_report

if __name__ == "__main__":
    monitor = ModelMonitor()
    monitor.generate_monitoring_report()