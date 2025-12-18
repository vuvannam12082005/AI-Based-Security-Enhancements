import streamlit as st
import time
from typing import List, Dict, Any
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
    
    # Initialize API client
    api = APIClient(
        sensor_url=st.session_state.sensor_url,
        enforcer_url=st.session_state.enforcer_url,
        ml_url=st.session_state.ml_url,
        orch_api_url=st.session_state.orch_api_url
    )
    
    # Auto-refresh controls
    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        auto_refresh = st.checkbox("Auto-refresh", value=True)
    with col2:
        refresh_interval = st.selectbox("Refresh interval", [5, 10, 30, 60], index=1)
    with col3:
        if st.button("🔄 Refresh Now"):
            # Clear all caches to force fresh data
            api.get_sensor_status_cached.clear()
            api.get_latest_events_cached.clear()
            api.get_enforcer_status_cached.clear()
            st.rerun()
    
    # Service status section
    st.header("📊 Service Status")
    
    # Create placeholders for dynamic content
    status_placeholder = st.empty()
    
    # Get service statuses with caching and fallback
    with st.spinner("🔄 Updating service status...") if st.session_state.last_sensor_status is None else st.empty():
        sensor_status, sensor_fresh = get_cached_or_fetch(api, "sensor_status", api.get_sensor_status_cached)
        enforcer_status, enforcer_fresh = get_cached_or_fetch(api, "enforcer_status", api.get_enforcer_status_cached)
    
    # Show freshness indicator
    if not (sensor_fresh and enforcer_fresh) and (st.session_state.last_sensor_status or st.session_state.last_enforcer_status):
        st.info("📡 Showing cached data (services may be temporarily unavailable)")
    
    # Render status table in placeholder
    with status_placeholder.container():
        render_service_status_table(sensor_status, enforcer_status)
    
    # System metrics (mock data for now)
    if sensor_status and sensor_status.get('running'):
        st.header("⚡ System Metrics")
        # Calculate mock system metrics from recent events
        events = api.get_latest_events(50)
        
        if events:
            # Calculate average CPU and memory usage
            cpu_values = []
            memory_values = []
            
            for event in events:
                try:
                    if event.get('cpu_percent'):
                        cpu_values.append(float(event['cpu_percent']))
                except (ValueError, TypeError):
                    pass
                
                try:
                    if event.get('memory_bytes'):
                        # Convert to percentage of 8GB system
                        memory_pct = (int(event['memory_bytes']) / (8 * 1024**3)) * 100
                        memory_values.append(min(memory_pct, 100))
                except (ValueError, TypeError):
                    pass
            
            avg_cpu = sum(cpu_values) / len(cpu_values) if cpu_values else 0
            avg_memory = sum(memory_values) / len(memory_values) if memory_values else 0
            
            plot_system_metrics_gauge(avg_cpu, avg_memory)
    
    # Real-time events section
    st.header("📡 Real-time Events")
    
    # Event limit control
    event_limit = st.slider("Number of events to display", 10, 500, 100)
    
    # Create placeholders for events section
    events_placeholder = st.empty()
    
    # Get latest events with caching
    with st.spinner("📡 Fetching events...") if not st.session_state.last_events else st.empty():
        events, events_fresh = get_cached_or_fetch(api, "events", api.get_latest_events_cached, event_limit)
    
    # Render events section in placeholder
    with events_placeholder.container():
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
            selected_event = render_events_table(events, highlight_suspicious=True)
            
            # Show event details if selected
            if selected_event:
                st.subheader("🔍 Event Details")
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.json({
                        "Event ID": selected_event.get('event_id', 'N/A'),
                        "Type": selected_event.get('event_type', 'N/A'),
                        "Timestamp": format_timestamp(selected_event.get('timestamp')),
                        "PID": selected_event.get('pid', 'N/A'),
                        "Process": selected_event.get('comm', 'N/A'),
                        "Executable": selected_event.get('exe_path', 'N/A')
                    })
                
                with col2:
                    st.json({
                        "Syscall": selected_event.get('syscall_name', 'N/A'),
                        "CPU %": selected_event.get('cpu_percent', 'N/A'),
                        "Memory": format_memory_size(selected_event.get('memory_bytes')),
                        "UID": selected_event.get('uid', 'N/A'),
                        "GID": selected_event.get('gid', 'N/A'),
                        "File Path": selected_event.get('file_path', 'N/A')
                    })
            
            # Charts section
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
            selected_process = render_process_table(events)
            
            if selected_process:
                st.info(f"Selected process: {selected_process.get('comm', 'Unknown')} (PID: {selected_process.get('pid', 'N/A')})")
        
        else:
            st.warning("No events available. Make sure the sensor service is running and collecting data.")
            
            if sensor_status and not sensor_status.get('running'):
                st.info("💡 Go to Settings to start the sensor service.")
    
    # Auto-refresh logic with rate limiting
    if auto_refresh:
        # Only refresh if enough time has passed since last update
        time_since_update = time.time() - st.session_state.last_update_time
        if time_since_update >= refresh_interval:
            # Clear cache to force fresh data
            api.get_sensor_status_cached.clear()
            api.get_latest_events_cached.clear()
            api.get_enforcer_status_cached.clear()
            st.rerun()
        else:
            # Show countdown until next refresh
            remaining = refresh_interval - time_since_update
            st.sidebar.text(f"Next refresh in: {remaining:.1f}s")