import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any

def plot_resource_usage_timeline(events: List[Dict[str, Any]]) -> None:
    """Plot CPU and memory usage over time"""
    if not events:
        st.info("No events available for charting")
        return
    
    df = pd.DataFrame(events)
    
    # Convert timestamp to datetime
    if 'timestamp' in df.columns:
        df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
    else:
        st.warning("No timestamp data available")
        return
    
    # Filter for events with resource data
    resource_events = df[
        (df['cpu_percent'].notna() & (df['cpu_percent'] != '')) |
        (df['memory_bytes'].notna() & (df['memory_bytes'] != ''))
    ].copy()
    
    if resource_events.empty:
        st.info("No resource usage data available")
        return
    
    # Convert resource columns to numeric
    resource_events['cpu_percent'] = pd.to_numeric(resource_events['cpu_percent'], errors='coerce')
    resource_events['memory_mb'] = pd.to_numeric(resource_events['memory_bytes'], errors='coerce') / (1024 * 1024)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("CPU Usage Over Time")
        if resource_events['cpu_percent'].notna().any():
            fig_cpu = px.line(
                resource_events, 
                x='datetime', 
                y='cpu_percent',
                color='comm',
                title="CPU Usage by Process"
            )
            fig_cpu.update_layout(yaxis_title="CPU %", xaxis_title="Time")
            st.plotly_chart(fig_cpu, width='stretch')
        else:
            st.info("No CPU usage data")
    
    with col2:
        st.subheader("Memory Usage Over Time")
        if resource_events['memory_mb'].notna().any():
            fig_mem = px.line(
                resource_events, 
                x='datetime', 
                y='memory_mb',
                color='comm',
                title="Memory Usage by Process"
            )
            fig_mem.update_layout(yaxis_title="Memory (MB)", xaxis_title="Time")
            st.plotly_chart(fig_mem, width='stretch')
        else:
            st.info("No memory usage data")

def plot_event_types_distribution(events: List[Dict[str, Any]]) -> None:
    """Plot distribution of event types"""
    if not events:
        st.info("No events available")
        return
    
    df = pd.DataFrame(events)
    
    if 'event_type' not in df.columns:
        st.warning("No event type data available")
        return
    
    event_counts = df['event_type'].value_counts()
    
    fig = px.pie(
        values=event_counts.values,
        names=event_counts.index,
        title="Event Types Distribution"
    )
    st.plotly_chart(fig, width='stretch')

def plot_process_activity(events: List[Dict[str, Any]]) -> None:
    """Plot process activity heatmap"""
    if not events:
        st.info("No events available")
        return
    
    df = pd.DataFrame(events)
    
    if 'comm' not in df.columns or 'timestamp' not in df.columns:
        st.warning("Insufficient data for process activity chart")
        return
    
    df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
    df['hour'] = df['datetime'].dt.hour
    
    # Count events per process per hour
    activity = df.groupby(['comm', 'hour']).size().reset_index(name='count')
    
    if activity.empty:
        st.info("No process activity data")
        return
    
    # Create pivot table for heatmap
    pivot = activity.pivot(index='comm', columns='hour', values='count').fillna(0)
    
    fig = go.Figure(data=go.Heatmap(
        z=pivot.values,
        x=pivot.columns,
        y=pivot.index,
        colorscale='Viridis'
    ))
    
    fig.update_layout(
        title="Process Activity Heatmap (Events per Hour)",
        xaxis_title="Hour of Day",
        yaxis_title="Process Name"
    )
    
    st.plotly_chart(fig, width='stretch')

def plot_system_metrics_gauge(cpu_usage: float, memory_usage: float) -> None:
    """Plot system metrics as gauges"""
    col1, col2 = st.columns(2)
    
    with col1:
        fig_cpu = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = cpu_usage,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "CPU Usage %"},
            delta = {'reference': 50},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        st.plotly_chart(fig_cpu, width='stretch')
    
    with col2:
        fig_mem = go.Figure(go.Indicator(
            mode = "gauge+number+delta",
            value = memory_usage,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Memory Usage %"},
            delta = {'reference': 50},
            gauge = {
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkgreen"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "red"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        st.plotly_chart(fig_mem, width='stretch')