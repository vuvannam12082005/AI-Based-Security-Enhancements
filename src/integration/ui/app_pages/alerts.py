"""
Alerts Page - Security Alerts and Enforcement Actions
======================================================
"""

import streamlit as st
import time
import pandas as pd
from typing import List, Dict, Any
from streamlit_autorefresh import st_autorefresh
from utils import (
    APIClient, format_timestamp, format_memory_size, 
    init_session_state, get_cached_or_fetch
)


def show():
    st.title("🚨 Security Alerts")
    
    # Auto refresh every 5 seconds
    st_autorefresh(interval=5000, limit=None, key="alerts_refresh")
    
    # Initialize
    init_session_state()
    
    api = APIClient(
        sensor_url=st.session_state.sensor_url,
        enforcer_url=st.session_state.enforcer_url,
        ml_url=st.session_state.ml_url,
        orch_api_url=st.session_state.orch_api_url
    )
    
    # Get sensor status
    sensor_status, _ = get_cached_or_fetch(api, "sensor_status", api.get_sensor_status_cached)
    
    # ==========================================================================
    # DETECTION SUMMARY
    # ==========================================================================
    st.header("📊 Detection Summary")
    
    col1, col2, col3, col4 = st.columns(4)
    
    events_scanned = sensor_status.get("events_scanned", 0) if sensor_status else 0
    threats_detected = sensor_status.get("threats_detected", 0) if sensor_status else 0
    processes_blocked = sensor_status.get("processes_blocked", 0) if sensor_status else 0
    auto_detect_on = sensor_status.get("auto_detect", False) if sensor_status else False
    
    with col1:
        st.metric("📊 Events Scanned", events_scanned)
    
    with col2:
        st.metric("🚨 Threats Detected", threats_detected, 
                  delta=f"+{threats_detected}" if threats_detected > 0 else None,
                  delta_color="inverse")
    
    with col3:
        st.metric("🛡️ Blocked", processes_blocked)
    
    with col4:
        if auto_detect_on:
            st.success("✅ Auto-Detect ON")
        else:
            st.warning("⚠️ Auto-Detect OFF")
    
    # ==========================================================================
    # ENFORCEMENT HISTORY
    # ==========================================================================
    st.header("📜 Enforcement History")
    
    history_result = api.get_enforcement_history(limit=100)
    
    if history_result and history_result.get("history"):
        history = history_result["history"]
        
        # Create DataFrame
        df_data = []
        for entry in history:
            status_icon = {
                "success": "✅",
                "failed": "❌", 
                "timeout": "⏱️",
                "error": "⚠️",
                "pending": "⏳"
            }.get(entry.get("status", ""), "❓")
            
            action_icon = "💀" if entry.get("enforcer_action") == "kill" else "🐌"
            
            threat_type = entry.get("threat_type", "unknown")
            threat_badges = {
                "sensitive_file_access": "🔐 Sensitive File",
                "privilege_escalation": "⬆️ Priv Escalation",
                "suspicious_exec": "🏃 Suspicious Exec",
                "crypto_miner": "⛏️ Crypto Miner",
                "reverse_shell": "🐚 Reverse Shell",
                "data_exfiltration": "📤 Exfiltration",
                "high_cpu_usage": "🔥 High CPU",
                "high_memory_usage": "💾 High Memory",
            }
            
            df_data.append({
                "Time": format_timestamp(entry.get("timestamp")),
                "PID": entry.get("pid"),
                "Process": entry.get("comm", "unknown"),
                "Threat Type": threat_badges.get(threat_type, f"❓ {threat_type}"),
                "Detection": entry.get("detection_method", "unknown"),
                "ML Score": f"{entry.get('ml_score', 0):.2f}" if entry.get('ml_score') else "-",
                "Action": f"{action_icon} {entry.get('enforcer_action', 'unknown')}",
                "Status": f"{status_icon} {entry.get('status', 'unknown')}",
                "CPU%": f"{entry.get('cpu_percent', 0):.1f}%",
            })
        
        df = pd.DataFrame(df_data)
        
        # Filters
        col1, col2, col3 = st.columns(3)
        with col1:
            threat_filter = st.multiselect(
                "Filter by Threat Type",
                options=df["Threat Type"].unique(),
                default=[]
            )
        with col2:
            status_filter = st.multiselect(
                "Filter by Status",
                options=df["Status"].unique(),
                default=[]
            )
        with col3:
            detection_filter = st.multiselect(
                "Filter by Detection Method",
                options=df["Detection"].unique(),
                default=[]
            )
        
        # Apply filters
        filtered_df = df.copy()
        if threat_filter:
            filtered_df = filtered_df[filtered_df["Threat Type"].isin(threat_filter)]
        if status_filter:
            filtered_df = filtered_df[filtered_df["Status"].isin(status_filter)]
        if detection_filter:
            filtered_df = filtered_df[filtered_df["Detection"].isin(detection_filter)]
        
        # Display
        st.dataframe(filtered_df, use_container_width=True, hide_index=True)
        
        st.caption(f"Showing {len(filtered_df)} of {history_result.get('total', 0)} entries")
        
        # Threat type breakdown
        st.subheader("📈 Threat Type Breakdown")
        threat_counts = df["Threat Type"].value_counts()
        
        col1, col2 = st.columns(2)
        with col1:
            st.bar_chart(threat_counts)
        with col2:
            for threat, count in threat_counts.items():
                st.write(f"**{threat}**: {count}")
        
    else:
        st.info("No enforcement history yet. Enable Auto-Detect to start monitoring.")
    
    # ==========================================================================
    # MANUAL ACTIONS
    # ==========================================================================
    st.header("🔧 Manual Actions")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Kill Process")
        kill_pid = st.number_input("PID to kill", min_value=1, step=1, key="kill_pid")
        if st.button("💀 Kill Process", type="primary"):
            result = api.enforce_action(int(kill_pid), "kill")
            if result and result.get("ok"):
                st.success(f"Process {kill_pid} killed")
            else:
                st.error(f"Failed: {result}")
    
    with col2:
        st.subheader("Throttle Process")
        throttle_pid = st.number_input("PID to throttle", min_value=1, step=1, key="throttle_pid")
        cpu_limit = st.selectbox(
            "CPU Limit",
            ["5000 100000 (5%)", "10000 100000 (10%)", "20000 100000 (20%)"],
            key="cpu_limit"
        )
        if st.button("🐌 Throttle Process"):
            cpu_max = cpu_limit.split()[0] + " " + cpu_limit.split()[1]
            result = api.enforce_action(int(throttle_pid), "throttle", cpu_max=cpu_max)
            if result and result.get("ok"):
                st.success(f"Process {throttle_pid} throttled to {cpu_limit}")
            else:
                st.error(f"Failed: {result}")
