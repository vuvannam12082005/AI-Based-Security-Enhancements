import requests
import streamlit as st
from typing import Dict, List, Any, Optional
import time
import hashlib

class APIClient:
    def __init__(self, sensor_url: str, enforcer_url: str, ml_url: str = None, orch_api_url: str = None):
        self.sensor_url = sensor_url.rstrip('/')
        self.enforcer_url = enforcer_url.rstrip('/')
        self.ml_url = ml_url.rstrip('/') if ml_url else None
        self.orch_api_url = orch_api_url.rstrip('/') if orch_api_url else None
        
    def _get_cache_key(self, method: str, url: str) -> str:
        """Generate cache key for API requests"""
        return hashlib.md5(f"{method}:{url}".encode()).hexdigest()
    
    def _make_request(self, method: str, url: str, **kwargs) -> Optional[Dict]:
        """Make HTTP request with error handling"""
        try:
            response = requests.request(method, url, timeout=5, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.ConnectionError:
            st.error(f"❌ Cannot connect to {url}")
            return None
        except requests.exceptions.Timeout:
            st.error(f"⏱️ Request timeout to {url}")
            return None
        except requests.exceptions.HTTPError as e:
            st.error(f"❌ HTTP error {e.response.status_code}: {e.response.text}")
            return None
        except Exception as e:
            st.error(f"❌ Unexpected error: {str(e)}")
            return None
    
    # Cached API methods
    @st.cache_data(ttl=3, show_spinner=False)
    def get_sensor_status_cached(_self) -> Optional[Dict]:
        """Get sensor service status (cached)"""
        return _self._make_request("GET", f"{_self.sensor_url}/sensor/status")
    
    @st.cache_data(ttl=2, show_spinner=False)
    def get_latest_events_cached(_self, limit: int = 100) -> Optional[List[Dict]]:
        """Get latest events from sensor (cached)"""
        result = _self._make_request("GET", f"{_self.sensor_url}/sensor/events/latest?limit={limit}")
        return result.get('events', []) if result else []
    
    @st.cache_data(ttl=5, show_spinner=False)
    def get_enforcer_status_cached(_self) -> Optional[Dict]:
        """Get enforcer service status (cached)"""
        return _self._make_request("GET", f"{_self.enforcer_url}/enforcer/status")
    
    # Non-cached API methods (for actions)
    def get_sensor_status(self) -> Optional[Dict]:
        """Get sensor service status"""
        return self._make_request("GET", f"{self.sensor_url}/sensor/status")
    
    def start_sensor(
        self, 
        mode: str = "proc", 
        sample_interval: float = 1.0,
        auto_detect: bool = False,
        auto_action: str = "throttle"
    ) -> Optional[Dict]:
        """Start sensor data collection with optional auto-detect"""
        data = {
            "mode": mode, 
            "sample_interval": sample_interval,
            "auto_detect": auto_detect,
            "auto_action": auto_action
        }
        # Clear cache after action
        self.get_sensor_status_cached.clear()
        return self._make_request("POST", f"{self.sensor_url}/sensor/start", json=data)
    
    def stop_sensor(self) -> Optional[Dict]:
        """Stop sensor data collection"""
        # Clear cache after action
        self.get_sensor_status_cached.clear()
        return self._make_request("POST", f"{self.sensor_url}/sensor/stop")
    
    def get_latest_events(self, limit: int = 100) -> Optional[List[Dict]]:
        """Get latest events from sensor"""
        result = self._make_request("GET", f"{self.sensor_url}/sensor/events/latest?limit={limit}")
        return result.get('events', []) if result else []
    
    # Enforcer API methods
    def get_enforcer_status(self) -> Optional[Dict]:
        """Get enforcer service status"""
        return self._make_request("GET", f"{self.enforcer_url}/enforcer/status")
    
    def enforce_action(self, pid: int, action: str, cpu_max: str = None, memory_max: int = None) -> Optional[Dict]:
        """Execute enforcement action (throttle/kill)"""
        data = {"pid": pid, "action": action}
        if cpu_max:
            data["cpu_max"] = cpu_max
        if memory_max:
            data["memory_max"] = memory_max
        # Clear cache after action
        self.get_enforcer_status_cached.clear()
        return self._make_request("POST", f"{self.enforcer_url}/enforcer/action", json=data)
    
    def release_process(self, pid: int) -> Optional[Dict]:
        """Release process from enforcement"""
        data = {"pid": pid}
        # Clear cache after action
        self.get_enforcer_status_cached.clear()
        return self._make_request("POST", f"{self.enforcer_url}/enforcer/release", json=data)
    
    def set_auto_detect(self, enabled: bool, action: str = "throttle") -> Optional[Dict]:
        """Toggle auto-detect at runtime"""
        data = {"enabled": enabled, "action": action}
        # Clear cache after action
        self.get_sensor_status_cached.clear()
        return self._make_request("POST", f"{self.sensor_url}/sensor/auto_detect", json=data)
    
    def get_enforcement_history(self, limit: int = 50) -> Optional[Dict]:
        """Get history of detected threats and enforcement actions"""
        return self._make_request("GET", f"{self.sensor_url}/sensor/enforcement_history?limit={limit}")

def detect_suspicious_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect suspicious events based on patterns"""
    suspicious = []
    
    for event in events:
        reasons = []
        
        # Check for privilege escalation syscalls
        if event.get('syscall_name') in ['setuid', 'setgid', 'setresuid', 'setresgid']:
            reasons.append("Privilege escalation syscall")
        
        # Check for process creation
        if event.get('syscall_name') in ['execve', 'clone', 'fork']:
            reasons.append("Process creation")
        
        # Check for high resource usage
        try:
            cpu = float(event.get('cpu_percent', 0) or 0)
            if cpu > 80:
                reasons.append(f"High CPU usage: {cpu}%")
        except (ValueError, TypeError):
            pass
        
        try:
            memory = int(event.get('memory_bytes', 0) or 0)
            if memory > 1024 * 1024 * 1024:  # > 1GB
                reasons.append(f"High memory usage: {memory / (1024**3):.1f}GB")
        except (ValueError, TypeError):
            pass
        
        # Check for suspicious file operations
        if event.get('file_path') and any(path in event['file_path'] for path in ['/etc/passwd', '/etc/shadow', '/root']):
            reasons.append("Sensitive file access")
        
        if reasons:
            alert = event.copy()
            alert['alert_reasons'] = reasons
            alert['severity'] = 'HIGH' if len(reasons) > 1 else 'MEDIUM'
            suspicious.append(alert)
    
    return suspicious

def format_memory_size(bytes_value: Any) -> str:
    """Format memory size in human readable format"""
    try:
        bytes_val = int(bytes_value or 0)
        if bytes_val == 0:
            return "0 B"
        
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024
        return f"{bytes_val:.1f} TB"
    except (ValueError, TypeError):
        return "N/A"

def format_timestamp(timestamp: Any) -> str:
    """Format timestamp to readable string"""
    try:
        ts = float(timestamp)
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))
    except (ValueError, TypeError):
        return "N/A"

def init_session_state():
    """Initialize session state with default values"""
    if "last_sensor_status" not in st.session_state:
        st.session_state.last_sensor_status = None
    if "last_enforcer_status" not in st.session_state:
        st.session_state.last_enforcer_status = None
    if "last_events" not in st.session_state:
        st.session_state.last_events = []
    if "last_update_time" not in st.session_state:
        st.session_state.last_update_time = 0

def get_cached_or_fetch(api_client: APIClient, data_type: str, fetch_func, *args, **kwargs):
    """Get cached data or fetch new data, maintaining previous state"""
    try:
        new_data = fetch_func(*args, **kwargs)
        if new_data is not None:
            # Update session state with new data
            st.session_state[f"last_{data_type}"] = new_data
            st.session_state.last_update_time = time.time()
            return new_data, True  # (data, is_fresh)
        else:
            # Return cached data if fetch failed
            return st.session_state.get(f"last_{data_type}"), False
    except Exception:
        # Return cached data on any error
        return st.session_state.get(f"last_{data_type}"), False