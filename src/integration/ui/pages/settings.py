import streamlit as st
import os
from utils import APIClient, format_timestamp, init_session_state, get_cached_or_fetch

def show():
    st.title("⚙️ System Settings")
    
    # Initialize session state
    init_session_state()
    
    # Initialize API client
    api = APIClient(
        sensor_url=st.session_state.sensor_url,
        enforcer_url=st.session_state.enforcer_url,
        ml_url=st.session_state.ml_url,
        orch_api_url=st.session_state.orch_api_url
    )
    
    # Connection settings
    st.header("🔗 Connection Settings")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Service URLs")
        new_sensor_url = st.text_input("Sensor URL", value=st.session_state.sensor_url)
        new_enforcer_url = st.text_input("Enforcer URL", value=st.session_state.enforcer_url)
        new_ml_url = st.text_input("ML URL", value=st.session_state.ml_url)
        
        if st.button("Update Service URLs"):
            st.session_state.sensor_url = new_sensor_url
            st.session_state.enforcer_url = new_enforcer_url
            st.session_state.ml_url = new_ml_url
            st.success("Service URLs updated")
            st.rerun()
    
    with col2:
        st.subheader("Other Settings")
        new_orch_url = st.text_input("Orchestrator API URL", value=st.session_state.orch_api_url)
        new_ws_url = st.text_input("WebSocket URL", value=st.session_state.ws_url)
        
        if st.button("Update Other URLs"):
            st.session_state.orch_api_url = new_orch_url
            st.session_state.ws_url = new_ws_url
            st.success("URLs updated")
            st.rerun()
    
    # Service status and controls
    st.header("🛠️ Service Management")
    
    # Create placeholders for service status
    service_status_placeholder = st.empty()
    
    # Get current status with caching
    with st.spinner("🔄 Checking service status...") if st.session_state.last_sensor_status is None else st.empty():
        sensor_status, sensor_fresh = get_cached_or_fetch(api, "sensor_status", api.get_sensor_status_cached)
        enforcer_status, enforcer_fresh = get_cached_or_fetch(api, "enforcer_status", api.get_enforcer_status_cached)
    
    # Render service status in placeholder
    with service_status_placeholder.container():
        if not (sensor_fresh and enforcer_fresh) and (st.session_state.last_sensor_status or st.session_state.last_enforcer_status):
            st.info("📡 Showing cached service status")
        
        # Sensor service controls
        st.subheader("📡 Sensor Service")
        
        col1, col2 = st.columns([2, 1])
    
    with col1:
        if sensor_status:
            st.success("✅ Sensor service is reachable")
            
            status_info = {
                "Running": "🟢 Yes" if sensor_status.get('running') else "🔴 No",
                "Mode": sensor_status.get('mode', 'N/A'),
                "Output File": sensor_status.get('output_file', 'N/A'),
                "Last Event": format_timestamp(sensor_status.get('last_event_ts')) if sensor_status.get('last_event_ts') else 'N/A'
            }
            
            for key, value in status_info.items():
                st.write(f"**{key}:** {value}")
        else:
            st.error("❌ Cannot connect to sensor service")
            st.write("Make sure the sensor service is running on port 8001")
    
    with col2:
        st.write("**Controls:**")
        
        if sensor_status and sensor_status.get('running'):
            if st.button("🛑 Stop Sensor", type="primary"):
                result = api.stop_sensor()
                if result:
                    st.success("Sensor stopped")
                    st.rerun()
                else:
                    st.error("Failed to stop sensor")
        else:
            # Sensor configuration
            mode = st.selectbox("Mode", ["proc", "ebpf"], index=0)
            sample_interval = st.number_input("Sample Interval (s)", min_value=0.1, max_value=60.0, value=1.0, step=0.1)
            
            if st.button("▶️ Start Sensor", type="primary"):
                result = api.start_sensor(mode, sample_interval)
                if result:
                    st.success(f"Sensor started in {mode} mode")
                    st.rerun()
                else:
                    st.error("Failed to start sensor")
    
    # Enforcer service status
    st.subheader("🛡️ Enforcer Service")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        if enforcer_status:
            st.success("✅ Enforcer service is reachable")
            
            enforcer_info = {
                "Status": "🟢 Available" if enforcer_status.get('ok') else "🔴 Error",
                "Engine": enforcer_status.get('engine', 'N/A'),
                "cgroup v2 Mount": enforcer_status.get('v2', {}).get('mount', 'N/A'),
                "cgroup v2 Controllers": enforcer_status.get('v2', {}).get('controllers', 'N/A'),
                "cgroup v1 CPU": "Available" if enforcer_status.get('v1', {}).get('cpu_mount') else "Not available",
                "cgroup v1 Memory": "Available" if enforcer_status.get('v1', {}).get('mem_mount') else "Not available"
            }
            
            for key, value in enforcer_info.items():
                st.write(f"**{key}:** {value}")
        else:
            st.error("❌ Cannot connect to enforcer service")
            st.write("Make sure the enforcer service is running on port 8002 with sudo privileges")
    
    with col2:
        st.write("**Info:**")
        st.info("Enforcer service requires sudo privileges to manage cgroups")
        
        if enforcer_status:
            engine = enforcer_status.get('engine', 'unknown')
            if engine == 'cgroupv1':
                st.warning("Using cgroup v1 (fallback mode)")
            elif engine == 'cgroupv2':
                st.success("Using cgroup v2 (preferred)")
    
    # System configuration
    st.header("🔧 System Configuration")
    
    # Data retention settings
    st.subheader("💾 Data Management")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Event Buffer Settings**")
        buffer_size = st.number_input("Max events in memory", min_value=100, max_value=5000, value=500, step=100)
        st.info(f"Current buffer holds up to {buffer_size} events")
    
    with col2:
        st.write("**CSV Export Settings**")
        export_dir = st.text_input("Export Directory", value="data/raw")
        
        if st.button("📁 Open Export Directory"):
            if os.path.exists(export_dir):
                # List CSV files
                csv_files = [f for f in os.listdir(export_dir) if f.endswith('.csv')]
                if csv_files:
                    st.write("**Available CSV files:**")
                    for file in sorted(csv_files, reverse=True)[:10]:  # Show last 10 files
                        file_path = os.path.join(export_dir, file)
                        file_size = os.path.getsize(file_path) / 1024  # KB
                        st.write(f"- {file} ({file_size:.1f} KB)")
                else:
                    st.info("No CSV files found")
            else:
                st.error(f"Directory {export_dir} does not exist")
    
    # Alert thresholds
    st.subheader("🚨 Alert Thresholds")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        cpu_alert_threshold = st.slider("CPU Alert Threshold (%)", 0, 100, 80)
        st.session_state['cpu_alert_threshold'] = cpu_alert_threshold
    
    with col2:
        memory_alert_threshold = st.slider("Memory Alert Threshold (GB)", 0.1, 8.0, 1.0, 0.1)
        st.session_state['memory_alert_threshold'] = memory_alert_threshold
    
    with col3:
        alert_cooldown = st.number_input("Alert Cooldown (seconds)", min_value=1, max_value=3600, value=60)
        st.session_state['alert_cooldown'] = alert_cooldown
    
    # Enforcement presets
    st.subheader("⚡ Enforcement Presets")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**CPU Throttling Presets**")
        cpu_presets = {
            "Light (50%)": "50000 100000",
            "Medium (20%)": "20000 100000", 
            "Heavy (10%)": "10000 100000",
            "Minimal (5%)": "5000 100000"
        }
        
        for name, value in cpu_presets.items():
            st.code(f"{name}: {value}")
    
    with col2:
        st.write("**Memory Limit Presets**")
        memory_presets = {
            "128 MB": 128 * 1024 * 1024,
            "256 MB": 256 * 1024 * 1024,
            "512 MB": 512 * 1024 * 1024,
            "1 GB": 1024 * 1024 * 1024
        }
        
        for name, value in memory_presets.items():
            st.code(f"{name}: {value:,} bytes")
    
    # System information
    st.header("ℹ️ System Information")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("**Environment Variables**")
        env_vars = {
            "SENSOR_URL": os.getenv("SENSOR_URL", "Not set"),
            "ENFORCER_URL": os.getenv("ENFORCER_URL", "Not set"),
            "ML_URL": os.getenv("ML_URL", "Not set"),
            "WS_URL": os.getenv("WS_URL", "Not set")
        }
        
        for key, value in env_vars.items():
            st.write(f"**{key}:** `{value}`")
    
    with col2:
        st.write("**Current Service URLs**")
        st.write(f"**Sensor API:** `{api.sensor_url}`")
        st.write(f"**Enforcer API:** `{api.enforcer_url}`")
        st.write(f"**ML API:** `{api.ml_url}`")
        st.write(f"**WebSocket:** `{st.session_state.ws_url}`")
    
    # Test connections
    st.header("🔍 Connection Test")
    
    if st.button("🧪 Test All Connections"):
        with st.spinner("Testing connections..."):
            # Test sensor
            sensor_ok = api.get_sensor_status() is not None
            
            # Test enforcer  
            enforcer_ok = api.get_enforcer_status() is not None
            
            # Results
            col1, col2 = st.columns(2)
            
            with col1:
                if sensor_ok:
                    st.success("✅ Sensor service: Connected")
                else:
                    st.error("❌ Sensor service: Failed")
            
            with col2:
                if enforcer_ok:
                    st.success("✅ Enforcer service: Connected")
                else:
                    st.error("❌ Enforcer service: Failed")
            
            if sensor_ok and enforcer_ok:
                st.success("🎉 All services are operational!")
            else:
                st.warning("⚠️ Some services are not available. Check the service status above.")