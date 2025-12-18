import streamlit as st
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any, Optional

def render_events_table(events: List[Dict[str, Any]], highlight_suspicious: bool = True) -> Optional[Dict[str, Any]]:
    """Render events table with optional highlighting and return selected row"""
    if not events:
        st.info("No events to display")
        return None
    
    df = pd.DataFrame(events)
    
    # Convert timestamp to readable format
    if 'timestamp' in df.columns:
        df['time'] = pd.to_datetime(df['timestamp'], unit='s').dt.strftime('%H:%M:%S')
    
    # Select key columns for display
    display_cols = ['time', 'event_type', 'pid', 'comm', 'syscall_name', 'cpu_percent', 'memory_bytes']
    available_cols = [col for col in display_cols if col in df.columns]
    
    if not available_cols:
        st.warning("No displayable columns found")
        return None
    
    display_df = df[available_cols].copy()
    
    # Add row highlighting for suspicious activity
    if highlight_suspicious and 'syscall_name' in display_df.columns:
        suspicious_syscalls = ['execve', 'clone', 'fork', 'setuid', 'setgid']
        display_df['suspicious'] = display_df['syscall_name'].isin(suspicious_syscalls)
    
    # Format memory bytes
    if 'memory_bytes' in display_df.columns:
        display_df['memory_mb'] = pd.to_numeric(display_df['memory_bytes'], errors='coerce') / (1024 * 1024)
        display_df['memory_mb'] = display_df['memory_mb'].round(2)
        display_df = display_df.drop('memory_bytes', axis=1)
    
    # Display table with selection
    selected_indices = st.dataframe(
        display_df,
        width='stretch',
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row"
    )
    
    # Return selected row data
    if selected_indices and len(selected_indices['selection']['rows']) > 0:
        selected_idx = selected_indices['selection']['rows'][0]
        return events[selected_idx]
    
    return None

def render_process_table(events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Render active processes table with resource usage"""
    if not events:
        st.info("No process data available")
        return None
    
    df = pd.DataFrame(events)
    
    # Group by PID to get latest info per process
    if 'pid' not in df.columns:
        st.warning("No PID data available")
        return None
    
    # Get latest event per PID
    df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
    latest_per_pid = df.loc[df.groupby('pid')['timestamp'].idxmax()]
    
    # Select process info columns
    process_cols = ['pid', 'comm', 'exe_path', 'cpu_percent', 'memory_bytes', 'uid', 'gid']
    available_cols = [col for col in process_cols if col in latest_per_pid.columns]
    
    if not available_cols:
        st.warning("No process columns available")
        return None
    
    process_df = latest_per_pid[available_cols].copy()
    
    # Format memory
    if 'memory_bytes' in process_df.columns:
        process_df['memory_mb'] = pd.to_numeric(process_df['memory_bytes'], errors='coerce') / (1024 * 1024)
        process_df['memory_mb'] = process_df['memory_mb'].round(2)
        process_df = process_df.drop('memory_bytes', axis=1)
    
    # Format CPU
    if 'cpu_percent' in process_df.columns:
        process_df['cpu_percent'] = pd.to_numeric(process_df['cpu_percent'], errors='coerce')
    
    # Sort by CPU usage
    if 'cpu_percent' in process_df.columns:
        process_df = process_df.sort_values('cpu_percent', ascending=False, na_position='last')
    
    # Display with selection
    selected_indices = st.dataframe(
        process_df,
        width='stretch',
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row"
    )
    
    # Return selected process
    if selected_indices and len(selected_indices['selection']['rows']) > 0:
        selected_idx = selected_indices['selection']['rows'][0]
        selected_pid = process_df.iloc[selected_idx]['pid']
        # Return the full event data for the selected PID
        return latest_per_pid[latest_per_pid['pid'] == selected_pid].iloc[0].to_dict()
    
    return None

def render_alerts_table(alerts: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Render alerts table with severity highlighting"""
    if not alerts:
        st.info("No alerts to display")
        return None
    
    df = pd.DataFrame(alerts)
    
    # Add timestamp formatting if available
    if 'timestamp' in df.columns:
        df['time'] = pd.to_datetime(df['timestamp'], unit='s').dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Select alert columns
    alert_cols = ['time', 'severity', 'message', 'pid', 'comm', 'action_taken']
    available_cols = [col for col in alert_cols if col in df.columns]
    
    if not available_cols:
        st.warning("No alert columns available")
        return None
    
    display_df = df[available_cols].copy()
    
    # Sort by timestamp (most recent first)
    if 'timestamp' in df.columns:
        display_df = display_df.sort_values('timestamp', ascending=False)
    
    # Display with selection
    selected_indices = st.dataframe(
        display_df,
        width='stretch',
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row"
    )
    
    # Return selected alert
    if selected_indices and len(selected_indices['selection']['rows']) > 0:
        selected_idx = selected_indices['selection']['rows'][0]
        return alerts[selected_idx]
    
    return None

def render_service_status_table(sensor_status: Dict, enforcer_status: Dict, loading: bool = False) -> None:
    """Render service status as a table"""
    if loading:
        st.info("🔄 Loading service status...")
        return
        
    status_data = []
    
    # Sensor status
    if sensor_status:
        status_data.append({
            'Service': 'Sensor',
            'Status': '🟢 Running' if sensor_status.get('running', False) else '🔴 Stopped',
            'Mode': sensor_status.get('mode', 'N/A'),
            'Port': '8001',
            'Last Event': datetime.fromtimestamp(sensor_status['last_event_ts']).strftime('%H:%M:%S') 
                         if sensor_status.get('last_event_ts') else 'N/A'
        })
    else:
        status_data.append({
            'Service': 'Sensor',
            'Status': '🔴 Unavailable',
            'Mode': 'N/A',
            'Port': '8001',
            'Last Event': 'N/A'
        })
    
    # Enforcer status
    if enforcer_status:
        status_data.append({
            'Service': 'Enforcer',
            'Status': '🟢 Available' if enforcer_status.get('ok', False) else '🔴 Error',
            'Mode': enforcer_status.get('engine', 'N/A'),
            'Port': '8002',
            'Last Event': 'N/A'
        })
    else:
        status_data.append({
            'Service': 'Enforcer',
            'Status': '🔴 Unavailable',
            'Mode': 'N/A',
            'Port': '8002',
            'Last Event': 'N/A'
        })
    
    df = pd.DataFrame(status_data)
    st.dataframe(df, width='stretch', hide_index=True)