import streamlit as st
import time
from typing import List, Dict, Any
from streamlit_autorefresh import st_autorefresh
from components.charts import (
    plot_resource_usage_timeline, 
    plot_event_types_distribution, 
    plot_process_activity,
    plot_system_metrics_gauge
)
from components.tables import render_events_table, render_process_table, render_service_status_table
from utils import APIClient, format_memory_size, format_timestamp, init_session_state, get_cached_or_fetch


def show():
    st.title("🛡️ Security Dashboard")
    
    # Initialize session state
    init_session_state()
    
    # Sidebar: Refresh rate control
    st.sidebar.header("⚙️ Dashboard Settings")
    refresh_interval = st.sidebar.selectbox(
        "Refresh interval (seconds)",
        [5, 10, 15],
        index=0,  # Default 5 seconds
        key="refresh_interval_select"
    )
    
    # Auto refresh with user-selected interval
    count = st_autorefresh(interval=refresh_interval * 1000, limit=None, key="dashboard_refresh")
    
    # Initialize API client
    api = APIClient(
        sensor_url=st.session_state.sensor_url,
        enforcer_url=st.session_state.enforcer_url,
        ml_url=st.session_state.ml_url,
        orch_api_url=st.session_state.orch_api_url
    )
    
    # Manual refresh button
    col1, col2 = st.columns([4, 1])
    with col2:
        if st.button("🔄 Refresh Now"):
            # Clear all caches to force fresh data
            api.get_sensor_status_cached.clear()
            api.get_latest_events_cached.clear()
            api.get_enforcer_status_cached.clear()
            st.rerun()
    
    # Get service statuses
    sensor_status, sensor_fresh = get_cached_or_fetch(api, "sensor_status", api.get_sensor_status_cached)
    enforcer_status, enforcer_fresh = get_cached_or_fetch(api, "enforcer_status", api.get_enforcer_status_cached)
    
    # ========== DETECTION METRICS ==========
    st.header("🔍 Detection Metrics")
    
    # Get detection stats from sensor status
    events_scanned = sensor_status.get("events_scanned", 0) if sensor_status else 0
    threats_detected = sensor_status.get("threats_detected", 0) if sensor_status else 0
    processes_blocked = sensor_status.get("processes_blocked", 0) if sensor_status else 0
    auto_detect_enabled = sensor_status.get("auto_detect", False) if sensor_status else False
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            "📊 Events Scanned", 
            events_scanned,
            help="Total events analyzed by ML model"
        )
    
    with col2:
        delta_color = "inverse" if threats_detected > 0 else "off"
        st.metric(
            "🚨 Threats Detected", 
            threats_detected,
            delta=f"+{threats_detected}" if threats_detected > 0 else None,
            delta_color=delta_color,
            help="Malicious processes detected"
        )
    
    with col3:
        st.metric(
            "🛡️ Processes Blocked", 
            processes_blocked,
            help="Processes killed or throttled"
        )
    
    with col4:
        if auto_detect_enabled:
            st.success("✅ Auto-Detect ON")
        else:
            st.warning("⚠️ Auto-Detect OFF")
    
    # Show freshness indicator
    if not (sensor_fresh and enforcer_fresh) and (st.session_state.last_sensor_status or st.session_state.last_enforcer_status):
        st.info("📡 Showing cached data (services may be temporarily unavailable)")
    
    # ========== SERVICE STATUS ==========
    st.header("📊 Service Status")
    render_service_status_table(sensor_status, enforcer_status)
    
    # ========== SYSTEM METRICS ==========
    if sensor_status and sensor_status.get('running'):
        st.header("⚡ System Metrics")
        # Calculate system metrics from recent events
        events = api.get_latest_events(50)
        
        if events:
            # Calculate average CPU and memory usage
            cpu_values = []
            memory_values = []
            
            for event in events:
                try:
                    cpu_val = event.get('cpu_percent')
                    if cpu_val is not None and cpu_val != "":
                        cpu_values.append(float(cpu_val))
                except (ValueError, TypeError):
                    pass
                
                try:
                    mem_val = event.get('memory_bytes')
                    if mem_val is not None and mem_val != "":
                        # Convert to percentage of 8GB system
                        memory_pct = (int(mem_val) / (8 * 1024**3)) * 100
                        memory_values.append(min(memory_pct, 100))
                except (ValueError, TypeError):
                    pass
            
            avg_cpu = sum(cpu_values) / len(cpu_values) if cpu_values else 0
            avg_memory = sum(memory_values) / len(memory_values) if memory_values else 0
            
            plot_system_metrics_gauge(avg_cpu, avg_memory)
    
    # ========== REAL-TIME EVENTS ==========
    st.header("📡 Real-time Events")
    
    # Event limit control
    event_limit = st.slider("Number of events to display", 10, 500, 100, key="event_limit_slider")
    
    # Get latest events with caching
    events, events_fresh = get_cached_or_fetch(api, "events", api.get_latest_events_cached, event_limit)
    
    if not events_fresh and events:
        st.info("📊 Showing cached events data")
    
    if events:
        # Event statistics
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Total Events", len(events))
        
        with col2:
            event_types = set(event.get('event_type', 'unknown') for event in events)
            st.metric("Event Types", len(event_types))
        
        with col3:
            processes = set(event.get('pid', 0) for event in events if event.get('pid'))
            st.metric("Active Processes", len(processes))
        
        with col4:
            if events:
                latest_time = max(event.get('timestamp', 0) for event in events)
                st.metric("Last Event", format_timestamp(latest_time))
    
        # Events table
        st.subheader("📋 Event Stream")
        render_events_table(events, highlight_suspicious=True)
        
        # ========== ANALYTICS ==========
        st.header("📈 Analytics")
        
        # Event type distribution
        col1, col2 = st.columns(2)
        
        with col1:
            plot_event_types_distribution(events)
        
        with col2:
            # Process activity chart
            plot_process_activity(events)
        
        # Resource usage timeline
        st.subheader("💻 Resource Usage Timeline")
        plot_resource_usage_timeline(events)
        
        # Active processes table
        st.subheader("🔄 Active Processes")
        render_process_table(events)
    
    else:
        st.warning("No events available. Make sure the sensor service is running and collecting data.")
        
        if sensor_status and not sensor_status.get('running'):
            st.info("💡 Go to Settings to start the sensor service.")
    
    # Show refresh count in sidebar
    st.sidebar.text(f"Refresh count: {count}")
    st.sidebar.text(f"Interval: {refresh_interval}s")
