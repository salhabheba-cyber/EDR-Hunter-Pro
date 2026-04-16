"""
EDR-Hunter Pro - AI Anomaly Detector
يستخدم Isolation Forest لكشف السلوكيات غير الطبيعية
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
from datetime import datetime

class AnomalyDetector:
    def __init__(self, model_path='models/anomaly_model.pkl'):
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.load_model()
    
    def load_model(self):
        """تحميل النموذج المدرب مسبقاً"""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                scaler_path = self.model_path.replace('.pkl', '_scaler.pkl')
                if os.path.exists(scaler_path):
                    self.scaler = joblib.load(scaler_path)
                    self.is_fitted = True
                print("✅ Model loaded successfully")
            except Exception as e:
                print(f"⚠️ Error loading model: {e}")
                self.model = None
        else:
            print("⚠️ No existing model found. Train a new model first.")
    
    def train_model(self, data_path):
        """تدريب نموذج كشف الشذوذ"""
        print(f"[+] Training anomaly detection model on {data_path}...")
        
        # قراءة البيانات
        df = pd.read_csv(data_path)
        
        # الميزات المستخدمة للكشف
        features = ['process_count', 'network_connections', 'file_changes', 
                   'registry_changes', 'cpu_usage', 'memory_usage']
        
        X = df[features]
        
        # تطبيع البيانات
        X_scaled = self.scaler.fit_transform(X)
        self.is_fitted = True
        
        # تدريب نموذج Isolation Forest
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.model.fit(X_scaled)
        
        # حفظ النموذج
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.model_path.replace('.pkl', '_scaler.pkl'))
        
        print("✅ Model trained and saved successfully")
        return True
    
    def extract_features(self, event):
        """استخراج الميزات من حدث أمني"""
        return [
            event.get('process_count', 1),
            event.get('network_connections', 0),
            event.get('file_changes', 0),
            event.get('registry_changes', 0),
            event.get('cpu_usage', 10),
            event.get('memory_usage', 100)
        ]
    
    def detect(self, event):
        """كشف الشذوذ في الوقت الفعلي"""
        # إذا لم يكن النموذج مدرباً، استخدم قواعد بسيطة
        if self.model is None or not self.is_fitted:
            # قواعد بسيطة كبديل مؤقت
            is_anomaly = (
                event.get('process_count', 0) > 30 or 
                event.get('network_connections', 0) > 50 or
                event.get('cpu_usage', 0) > 80
            )
            return {
                'is_anomaly': is_anomaly,
                'anomaly_score': -0.5 if is_anomaly else 0.5,
                'severity': 'HIGH' if is_anomaly else 'LOW',
                'timestamp': datetime.now().isoformat(),
                'mode': 'rule_based'
            }
        
        # استخدام النموذج المدرب
        features = self.extract_features(event)
        features_scaled = self.scaler.transform([features])
        
        prediction = self.model.predict(features_scaled)
        score = self.model.score_samples(features_scaled)[0]
        
        return {
            'is_anomaly': prediction[0] == -1,
            'anomaly_score': float(score),
            'severity': 'HIGH' if prediction[0] == -1 else 'LOW',
            'timestamp': datetime.now().isoformat(),
            'mode': 'ai_model'
        }
    
    def generate_report(self, events):
        """توليد تقرير أمني"""
        anomalies = []
        for event in events:
            result = self.detect(event)
            if result['is_anomaly']:
                anomalies.append({**event, **result})
        
        report = {
            'total_events': len(events),
            'anomalies_found': len(anomalies),
            'anomaly_rate': len(anomalies) / len(events) if events else 0,
            'anomalies': anomalies,
            'generated_at': datetime.now().isoformat()
        }
        
        return report

# اختبار سريع
if __name__ == "__main__":
    detector = AnomalyDetector()
    
    # بيانات تجريبية للاختبار
    sample_events = [
        {'process_count': 5, 'network_connections': 2, 'file_changes': 1, 
         'registry_changes': 0, 'cpu_usage': 15, 'memory_usage': 200},
        {'process_count': 50, 'network_connections': 100, 'file_changes': 20, 
         'registry_changes': 15, 'cpu_usage': 90, 'memory_usage': 2000},
    ]
    
    for event in sample_events:
        result = detector.detect(event)
        print(f"Event: {result}")
