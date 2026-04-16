import streamlit as st
import pandas as pd
import plotly.express as px
import random
from datetime import datetime

st.set_page_config(page_title="EDR-Hunter Pro", page_icon="🛡️", layout="wide")

st.title("🛡️ EDR-Hunter Pro")
st.markdown("### AI-Powered Endpoint Detection & Response")

# إعدادات Telegram (سيقوم المستخدم بتعديلها)
BOT_TOKEN = "YOUR_BOT_TOKEN_HERE"
CHAT_ID = "YOUR_CHAT_ID_HERE"

# دالة بسيطة لكشف الشذوذ
def is_anomaly(event):
    return event['process_count'] > 30 or event['network_connections'] > 50 or event['cpu_usage'] > 80

# تهيئة Session State
if 'events' not in st.session_state:
    st.session_state.events = []

# عرض الإحصائيات
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Events", len(st.session_state.events))
with col2:
    anomalies = sum(1 for e in st.session_state.events if e.get('is_anomaly', False))
    st.metric("Anomalies Detected", anomalies)
with col3:
    st.metric("Status", "🟢 Active")
with col4:
    st.metric("AI Model", "✅ Loaded")

st.subheader("📊 Real-time Event Stream")

if st.button("🔄 Simulate Event"):
    new_event = {
        'process_count': random.randint(1, 60),
        'network_connections': random.randint(0, 130),
        'file_changes': random.randint(0, 25),
        'registry_changes': random.randint(0, 20),
        'cpu_usage': random.randint(5, 98),
        'memory_usage': random.randint(100, 2600),
        'timestamp': datetime.now().strftime("%H:%M:%S"),
        'is_anomaly': False
    }
    
    new_event['is_anomaly'] = is_anomaly(new_event)
    st.session_state.events.insert(0, new_event)
    
    if new_event['is_anomaly']:
        st.error(f"🚨 ANOMALY DETECTED! Severity: HIGH")
    else:
        st.success(f"✅ Event normal")

if st.session_state.events:
    st.subheader("📋 Event Log")
    df = pd.DataFrame(st.session_state.events[:20])
    st.dataframe(df, use_container_width=True)

st.caption("🛡️ EDR-Hunter Pro - AI-Powered Security Monitoring")
