import streamlit as st
import os
from app_pages import dashboard, alerts, settings

# Configure Streamlit page
st.set_page_config(
    page_title="AI Security Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Environment configuration
SENSOR_URL = os.getenv("SENSOR_URL", "http://localhost:8001")
ENFORCER_URL = os.getenv("ENFORCER_URL", "http://localhost:8002")
ML_URL = os.getenv("ML_URL", "http://localhost:8003")
ORCH_API_URL = os.getenv("ORCH_API_URL", "http://localhost:8000")
WS_URL = os.getenv("WS_URL", "ws://localhost:8000/ws/realtime")

# Store config in session state
if "sensor_url" not in st.session_state:
    st.session_state.sensor_url = SENSOR_URL
if "enforcer_url" not in st.session_state:
    st.session_state.enforcer_url = ENFORCER_URL
if "ml_url" not in st.session_state:
    st.session_state.ml_url = ML_URL
if "orch_api_url" not in st.session_state:
    st.session_state.orch_api_url = ORCH_API_URL
if "ws_url" not in st.session_state:
    st.session_state.ws_url = WS_URL

# Sidebar navigation
st.sidebar.title("🛡️ AI Security Monitor")
st.sidebar.markdown("---")

page = st.sidebar.selectbox(
    "Navigate to:",
    ["Dashboard", "Alerts", "Settings"],
    index=0
)

# Display connection info
st.sidebar.markdown("### Connection Info")
st.sidebar.text(f"Sensor: {st.session_state.sensor_url}")
st.sidebar.text(f"Enforcer: {st.session_state.enforcer_url}")
st.sidebar.text(f"ML: {st.session_state.ml_url}")
st.sidebar.text(f"WebSocket: {st.session_state.ws_url}")

# Route to selected page
if page == "Dashboard":
    dashboard.show()
elif page == "Alerts":
    alerts.show()
elif page == "Settings":
    settings.show()