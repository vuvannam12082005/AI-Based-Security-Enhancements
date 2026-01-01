import streamlit as st
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any, Optional


def render_events_table(events: List[Dict[str, Any]], highlight_suspicious: bool = True) -> Optional[Dict[str, Any]]:
    """Render events table with optional highlighting"""
    if not events:
        st.info("No events to display")
        return None

    df = pd.DataFrame(events)

    if 'timestamp' in df.columns:
        df['time'] = pd.to_datetime(df['timestamp'], unit='s', errors='coerce').dt.strftime('%H:%M:%S')

    display_cols = ['time', 'event_type', 'pid', 'comm', 'syscall_name', 'cpu_percent', 'memory_bytes']
    available_cols = [col for col in display_cols if col in df.columns]

    if not available_cols:
        st.warning("No displayable columns found")
        return None

    display_df = df[available_cols].copy()

    if 'memory_bytes' in display_df.columns:
        display_df['memory_mb'] = pd.to_numeric(display_df['memory_bytes'], errors='coerce') / (1024 * 1024)
        display_df['memory_mb'] = display_df['memory_mb'].round(2)
        display_df = display_df.drop('memory_bytes', axis=1)

    st.dataframe(display_df, use_container_width=True, hide_index=True)
    return None


def render_process_table(processes: List[Dict[str, Any]]) -> None:
    """Render process table"""
    if not processes:
        st.info("No processes to display")
        return

    df = pd.DataFrame(processes)

    # Group by PID to get latest info per process
    if 'pid' in df.columns and 'timestamp' in df.columns:
        df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
        df = df.dropna(subset=['timestamp'])
        if not df.empty:
            df = df.loc[df.groupby('pid')['timestamp'].idxmax()]

    # Select process info columns
    process_cols = ['pid', 'comm', 'cpu_percent', 'memory_bytes']
    available_cols = [col for col in process_cols if col in df.columns]

    if not available_cols:
        st.warning("No process columns available")
        return

    display_df = df[available_cols].copy()

    # Format memory
    if 'memory_bytes' in display_df.columns:
        display_df['memory_mb'] = pd.to_numeric(display_df['memory_bytes'], errors='coerce') / (1024 * 1024)
        display_df['memory_mb'] = display_df['memory_mb'].round(2)
        display_df = display_df.drop('memory_bytes', axis=1)

    # Format CPU
    if 'cpu_percent' in display_df.columns:
        display_df['cpu_percent'] = pd.to_numeric(display_df['cpu_percent'], errors='coerce').round(2)

    # Sort by CPU usage
    if 'cpu_percent' in display_df.columns:
        display_df = display_df.sort_values('cpu_percent', ascending=False, na_position='last')

    st.dataframe(display_df, use_container_width=True, hide_index=True)


def render_service_status_table(sensor_status: Dict, enforcer_status: Dict) -> None:
    """Render service status table"""
    data = []

    sensor_running = sensor_status.get('running', False) if sensor_status else False
    data.append({
        'Service': 'Sensor',
        'Status': '🟢 Running' if sensor_running else '🔴 Stopped',
        'Port': '8001'
    })

    enforcer_ok = enforcer_status.get('ok', False) if enforcer_status else False
    data.append({
        'Service': 'Enforcer',
        'Status': '🟢 Ready' if enforcer_ok else '🔴 Error',
        'Port': '8002'
    })

    df = pd.DataFrame(data)
    st.dataframe(df, use_container_width=True, hide_index=True)


def render_alerts_table(alerts: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Render alerts table"""
    if not alerts:
        st.info("No alerts to display")
        return None

    df = pd.DataFrame(alerts)

    # Select alert columns
    alert_cols = ['time', 'severity', 'message', 'pid', 'comm']
    available_cols = [col for col in alert_cols if col in df.columns]

    if not available_cols:
        st.warning("No alert columns available")
        return None

    display_df = df[available_cols].copy()

    st.dataframe(display_df, use_container_width=True, hide_index=True)
    return None
