import streamlit as st
import time
from typing import List, Dict, Any
from components.tables import render_alerts_table, render_events_table
from utils import APIClient, detect_suspicious_events, format_timestamp, format_memory_size, init_session_state, get_cached_or_fetch

def show():
    st.title("🚨 Security Alerts")
    
    # Initialize session state
    init_session_state()
    
    # Initialize API client
    api = APIClient(
        sensor_url=st.session_state.sensor_url,
        enforcer_url=st.session_state.enforcer_url,
        ml_url=st.session_state.ml_url,
        orch_api_url=st.session_state.orch_api_url
    )
    
    # Alert configuration
    st.header("⚙️ Alert Configuration")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        cpu_threshold = st.slider("CPU Alert Threshold (%)", 0, 100, 80)
    
    with col2:
        memory_threshold = st.slider("Memory Alert Threshold (GB)", 0.1, 8.0, 1.0, 0.1)
    
    with col3:
        auto_action = st.selectbox("Auto Action", ["None", "Throttle", "Kill"], index=0)
    
    # Create placeholders for dynamic content
    alerts_placeholder = st.empty()
    
    # Get recent events for analysis with caching
    with st.spinner("🔍 Analyzing events for alerts...") if not st.session_state.last_events else st.empty():
        events, events_fresh = get_cached_or_fetch(api, "events", api.get_latest_events_cached, 200)
    
    # Render alerts section in placeholder
    with alerts_placeholder.container():
        if not events_fresh and events:
            st.info("⚠️ Analyzing cached events data")
        
        if not events:
            st.warning("No events available for alert analysis. Make sure the sensor service is running.")
            return
    
        # Detect suspicious events
        suspicious_events = detect_suspicious_events(events)
    
    # Apply user-defined thresholds
    threshold_alerts = []
    for event in events:
        reasons = []
        
        # CPU threshold check
        try:
            cpu = float(event.get('cpu_percent', 0) or 0)
            if cpu > cpu_threshold:
                reasons.append(f"CPU usage {cpu}% exceeds threshold {cpu_threshold}%")
        except (ValueError, TypeError):
            pass
        
        # Memory threshold check
        try:
            memory_gb = int(event.get('memory_bytes', 0) or 0) / (1024**3)
            if memory_gb > memory_threshold:
                reasons.append(f"Memory usage {memory_gb:.1f}GB exceeds threshold {memory_threshold}GB")
        except (ValueError, TypeError):
            pass
        
        if reasons:
            alert = event.copy()
            alert['alert_reasons'] = reasons
            alert['severity'] = 'HIGH' if len(reasons) > 1 else 'MEDIUM'
            alert['alert_type'] = 'THRESHOLD'
            threshold_alerts.append(alert)
    
    # Combine all alerts
    all_alerts = suspicious_events + threshold_alerts
    
    # Remove duplicates based on event_id
    seen_ids = set()
    unique_alerts = []
    for alert in all_alerts:
        event_id = alert.get('event_id')
        if event_id not in seen_ids:
            seen_ids.add(event_id)
            unique_alerts.append(alert)
    
    # Sort by timestamp (most recent first)
    unique_alerts.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
    
    # Alert summary
    st.header("📊 Alert Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        high_alerts = [a for a in unique_alerts if a.get('severity') == 'HIGH']
        st.metric("🔴 High Severity", len(high_alerts))
    
    with col2:
        medium_alerts = [a for a in unique_alerts if a.get('severity') == 'MEDIUM']
        st.metric("🟡 Medium Severity", len(medium_alerts))
    
    with col3:
        recent_alerts = [a for a in unique_alerts if time.time() - a.get('timestamp', 0) < 300]  # Last 5 minutes
        st.metric("⏰ Recent (5min)", len(recent_alerts))
    
    with col4:
        unique_pids = set(a.get('pid') for a in unique_alerts if a.get('pid'))
        st.metric("🎯 Affected Processes", len(unique_pids))
    
    # Active alerts table
    st.header("🚨 Active Alerts")
    
    if unique_alerts:
        # Convert alerts to display format
        alert_display = []
        for alert in unique_alerts:
            alert_display.append({
                'timestamp': alert.get('timestamp'),
                'time': format_timestamp(alert.get('timestamp')),
                'severity': alert.get('severity', 'UNKNOWN'),
                'message': '; '.join(alert.get('alert_reasons', ['Unknown alert'])),
                'pid': alert.get('pid', 'N/A'),
                'comm': alert.get('comm', 'N/A'),
                'action_taken': 'None',
                'event_id': alert.get('event_id')
            })
        
        selected_alert = render_alerts_table(alert_display)
        
        if selected_alert:
            st.header("🔍 Alert Details & Actions")
            
            # Find the original event
            original_event = None
            for alert in unique_alerts:
                if alert.get('event_id') == selected_alert.get('event_id'):
                    original_event = alert
                    break
            
            if original_event:
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.subheader("Event Information")
                    st.json({
                        "Event ID": original_event.get('event_id', 'N/A'),
                        "Timestamp": format_timestamp(original_event.get('timestamp')),
                        "Process": f"{original_event.get('comm', 'N/A')} (PID: {original_event.get('pid', 'N/A')})",
                        "Executable": original_event.get('exe_path', 'N/A'),
                        "Syscall": original_event.get('syscall_name', 'N/A'),
                        "CPU Usage": f"{original_event.get('cpu_percent', 'N/A')}%",
                        "Memory Usage": format_memory_size(original_event.get('memory_bytes')),
                        "Alert Reasons": original_event.get('alert_reasons', [])
                    })
                
                with col2:
                    st.subheader("Enforcement Actions")
                    
                    pid = original_event.get('pid')
                    if pid and str(pid).isdigit():
                        pid = int(pid)
                        
                        # Throttle controls
                        st.write("**Throttle Process**")
                        cpu_limit = st.selectbox("CPU Limit", ["10000 100000", "20000 100000", "50000 100000"], 
                                                key=f"cpu_{pid}")
                        memory_limit = st.selectbox("Memory Limit", [128*1024*1024, 256*1024*1024, 512*1024*1024], 
                                                   format_func=format_memory_size, key=f"mem_{pid}")
                        
                        col_throttle, col_kill, col_release = st.columns(3)
                        
                        with col_throttle:
                            if st.button("🐌 Throttle", key=f"throttle_{pid}"):
                                result = api.enforce_action(pid, "throttle", cpu_limit, memory_limit)
                                if result:
                                    st.success(f"✅ Process {pid} throttled")
                                else:
                                    st.error("❌ Throttle failed")
                        
                        with col_kill:
                            if st.button("💀 Kill", key=f"kill_{pid}", type="primary"):
                                if st.session_state.get(f"confirm_kill_{pid}", False):
                                    result = api.enforce_action(pid, "kill")
                                    if result:
                                        st.success(f"✅ Process {pid} killed")
                                    else:
                                        st.error("❌ Kill failed")
                                    st.session_state[f"confirm_kill_{pid}"] = False
                                else:
                                    st.session_state[f"confirm_kill_{pid}"] = True
                                    st.warning("⚠️ Click again to confirm kill")
                        
                        with col_release:
                            if st.button("🔓 Release", key=f"release_{pid}"):
                                result = api.release_process(pid)
                                if result:
                                    st.success(f"✅ Process {pid} released")
                                else:
                                    st.error("❌ Release failed")
                    else:
                        st.warning("Invalid PID - cannot perform actions")
    
    else:
        st.info("🎉 No alerts detected! Your system appears to be running normally.")
    
    # Alert history (simulated)
    st.header("📜 Alert History")
    
    # For now, show recent alerts as history
    if unique_alerts:
        st.write(f"Showing {len(unique_alerts)} recent alerts")
        
        # Group alerts by severity
        high_count = len([a for a in unique_alerts if a.get('severity') == 'HIGH'])
        medium_count = len([a for a in unique_alerts if a.get('severity') == 'MEDIUM'])
        
        st.write(f"- 🔴 High severity: {high_count}")
        st.write(f"- 🟡 Medium severity: {medium_count}")
        
        # Show timeline of alerts
        if len(unique_alerts) > 1:
            oldest = min(a.get('timestamp', 0) for a in unique_alerts)
            newest = max(a.get('timestamp', 0) for a in unique_alerts)
            duration = newest - oldest
            
            st.write(f"Alert timespan: {duration/60:.1f} minutes")
    
    # Auto-refresh with rate limiting
    auto_refresh_alerts = st.checkbox("Auto-refresh alerts", value=True)
    if auto_refresh_alerts:
        time_since_update = time.time() - st.session_state.last_update_time
        if time_since_update >= 10:  # Refresh every 10 seconds for alerts
            # Clear cache to force fresh data
            api.get_latest_events_cached.clear()
            st.rerun()
        else:
            remaining = 10 - time_since_update
            st.sidebar.text(f"Next alert refresh: {remaining:.1f}s")