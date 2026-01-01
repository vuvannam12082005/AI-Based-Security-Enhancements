"""
Process Collector for Sensor Service
=====================================
Collects process information from /proc filesystem.
Enriches events with security-relevant information.
"""

import os
import time
from typing import Dict, Iterator, Optional, Tuple, List, Any
from shared.schemas.event_schema import new_event_base

# System constants
PAGE_SIZE = int(os.sysconf("SC_PAGE_SIZE")) if hasattr(os, "sysconf") else 4096
CLK_TCK = int(os.sysconf("SC_CLK_TCK")) if hasattr(os, "sysconf") else 100

# Sensitive files for detection
SENSITIVE_FILES = {
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys", "/root/.ssh/id_rsa", "/root/.bash_history",
    "/etc/gshadow", "/etc/security/opasswd"
}

# Suspicious ports (reverse shell, C2)
SUSPICIOUS_PORTS = {4444, 5555, 6666, 1234, 1337, 9001, 9999, 31337, 12345}

# Shell commands (for reverse shell detection)
SHELL_COMMANDS = {"bash", "sh", "zsh", "dash", "fish", "tcsh", "csh"}

# Data exfiltration threshold
IO_EXFIL_THRESHOLD = 10 * 1024 * 1024  # 10MB io_write with network = suspicious


def _read_first_line(path: str) -> str:
    """Read first line of a file."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.readline().strip()
    except Exception:
        return ""


def _readlink(path: str) -> str:
    """Read symlink target."""
    try:
        return os.readlink(path)
    except Exception:
        return ""


def _read_cmdline(pid: int) -> str:
    """Read process command line."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            data = f.read()
            return data.replace(b"\x00", b" ").decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _get_open_files(pid: int) -> list:
    """Get list of open files for a process."""
    files = []
    fd_dir = f"/proc/{pid}/fd"
    try:
        for fd in os.listdir(fd_dir):
            try:
                link = os.readlink(os.path.join(fd_dir, fd))
                if link.startswith("/") and not link.startswith("/dev/"):
                    files.append(link)
            except Exception:
                continue
    except Exception:
        pass
    return files[:10]


def _check_sensitive_file_access(pid: int) -> Tuple[bool, str]:
    """Check if process has any sensitive files open."""
    try:
        fd_dir = f"/proc/{pid}/fd"
        for fd in os.listdir(fd_dir):
            try:
                link = os.readlink(os.path.join(fd_dir, fd))
                for sensitive in SENSITIVE_FILES:
                    if sensitive in link:
                        return True, link
            except Exception:
                continue
    except Exception:
        pass
    return False, ""


def _parse_hex_ip_port(hex_str: str) -> Tuple[str, int]:
    """Parse hex IP:PORT from /proc/net/tcp format."""
    try:
        ip_hex, port_hex = hex_str.split(":")
        port = int(port_hex, 16)
        # Convert hex IP (little-endian) to dotted decimal
        ip_int = int(ip_hex, 16)
        ip = f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
        return ip, port
    except Exception:
        return "", 0


def _get_network_connections(pid: int) -> List[Dict]:
    """Get network connections for a process."""
    connections = []
    
    # Get socket inodes for this process
    try:
        fd_dir = f"/proc/{pid}/fd"
        socket_inodes = set()
        for fd in os.listdir(fd_dir):
            try:
                link = os.readlink(os.path.join(fd_dir, fd))
                if link.startswith("socket:["):
                    inode = link[8:-1]
                    socket_inodes.add(inode)
            except Exception:
                continue
        
        if not socket_inodes:
            return []
        
        # Check TCP connections
        try:
            with open("/proc/net/tcp", "r") as f:
                for line in f.readlines()[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 10:
                        inode = parts[9]
                        if inode in socket_inodes:
                            local_ip, local_port = _parse_hex_ip_port(parts[1])
                            remote_ip, remote_port = _parse_hex_ip_port(parts[2])
                            connections.append({
                                "local_ip": local_ip,
                                "local_port": local_port,
                                "remote_ip": remote_ip,
                                "remote_port": remote_port,
                                "protocol": "TCP"
                            })
        except Exception:
            pass
        
        # Check TCP6 connections
        try:
            with open("/proc/net/tcp6", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 10:
                        inode = parts[9]
                        if inode in socket_inodes:
                            try:
                                local_port = int(parts[1].split(":")[1], 16)
                                remote_port = int(parts[2].split(":")[1], 16)
                                connections.append({
                                    "local_ip": "::1",
                                    "local_port": local_port,
                                    "remote_ip": "::1",
                                    "remote_port": remote_port,
                                    "protocol": "TCP6"
                                })
                            except:
                                pass
        except Exception:
            pass
            
    except Exception:
        pass
    
    return connections[:10]


def _get_process_cpu_and_mem(pid: int) -> Tuple[int, int]:
    """Get CPU ticks and memory bytes for a process."""
    try:
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8", errors="ignore") as f:
            stat = f.read().split()
            utime = int(stat[13])
            stime = int(stat[14])
            cpu_ticks = utime + stime
        
        with open(f"/proc/{pid}/statm", "r", encoding="utf-8", errors="ignore") as f:
            statm = f.read().split()
            rss_pages = int(statm[1])
            memory_bytes = rss_pages * PAGE_SIZE
        
        return cpu_ticks, memory_bytes
    except Exception:
        return 0, 0


def _calc_cpu_percent(
    pid: int,
    prev_cpu_ticks: Optional[int],
    prev_time: Optional[float],
    now: float,
) -> Tuple[float, int, int]:
    """Calculate CPU percentage for a process."""
    current_ticks, memory_bytes = _get_process_cpu_and_mem(pid)
    
    if prev_cpu_ticks is None or prev_time is None:
        return 0.0, memory_bytes, current_ticks
    
    delta_ticks = current_ticks - prev_cpu_ticks
    delta_time = now - prev_time
    
    if delta_ticks < 0 or delta_time <= 0:
        return 0.0, memory_bytes, current_ticks
    
    cpu_seconds = delta_ticks / float(CLK_TCK)
    cpu_percent = (cpu_seconds / delta_time) * 100.0 if delta_time > 0 else 0.0
    cpu_percent = max(0.0, min(100.0, cpu_percent))
    
    return cpu_percent, memory_bytes, current_ticks


def _get_io_stats(pid: int) -> Tuple[int, int]:
    """Get I/O statistics for a process."""
    try:
        with open(f"/proc/{pid}/io", "r") as f:
            read_bytes = 0
            write_bytes = 0
            for line in f:
                if line.startswith("read_bytes:"):
                    read_bytes = int(line.split()[1])
                elif line.startswith("write_bytes:"):
                    write_bytes = int(line.split()[1])
            return read_bytes, write_bytes
    except Exception:
        return 0, 0


class ProcCollector:
    """
    Collects process information from /proc filesystem.
    Yields events with security-relevant enrichment.
    """
    
    def __init__(self, sample_interval: float = 1.0):
        self.sample_interval = sample_interval
        self._prev: Dict[int, Tuple[int, float]] = {}
        self._prev_io_write: Dict[int, int] = {}
    
    def stream(self) -> Iterator[Dict]:
        """Stream events continuously."""
        while True:
            now = time.time()
            
            for pid_str in os.listdir("/proc"):
                if not pid_str.isdigit():
                    continue
                
                pid = int(pid_str)
                
                try:
                    event = self._collect_process(pid, now)
                    if event:
                        yield event
                except Exception:
                    continue
            
            self._cleanup_dead_processes()
            time.sleep(self.sample_interval)
    
    def _collect_process(self, pid: int, now: float) -> Optional[Dict]:
        """Collect information for a single process."""
        proc_dir = f"/proc/{pid}"
        
        if not os.path.exists(proc_dir):
            return None
        
        # Basic info
        comm = _read_first_line(f"{proc_dir}/comm")
        exe_path = _readlink(f"{proc_dir}/exe")
        cmdline = _read_cmdline(pid)
        
        # UID/GID/PPID from status
        uid = gid = ppid = 0
        try:
            with open(f"{proc_dir}/status", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        uid = int(line.split()[1])
                    elif line.startswith("Gid:"):
                        gid = int(line.split()[1])
                    elif line.startswith("PPid:"):
                        ppid = int(line.split()[1])
        except Exception:
            return None
        
        # CPU and memory
        prev_ticks, prev_time = self._prev.get(pid, (None, None))
        cpu_percent, memory_bytes, current_ticks = _calc_cpu_percent(
            pid, prev_ticks, prev_time, now
        )
        self._prev[pid] = (current_ticks, now)
        
        # I/O stats
        io_read, io_write = _get_io_stats(pid)
        
        # Calculate io_write delta for exfiltration detection
        prev_io = self._prev_io_write.get(pid, 0)
        io_write_delta = io_write - prev_io if io_write > prev_io else 0
        self._prev_io_write[pid] = io_write
        
        # Check sensitive file access
        has_sensitive, sensitive_file = _check_sensitive_file_access(pid)
        
        # Check network connections
        connections = _get_network_connections(pid)
        has_suspicious_port = False
        suspicious_conn = None
        first_conn = None
        
        for conn in connections:
            if first_conn is None:
                first_conn = conn
            remote_port = conn.get("remote_port", 0)
            local_port = conn.get("local_port", 0)
            if remote_port in SUSPICIOUS_PORTS or local_port in SUSPICIOUS_PORTS:
                has_suspicious_port = True
                suspicious_conn = conn
                break
        
        # Check if shell with network (reverse shell indicator)
        is_shell_with_network = comm in SHELL_COMMANDS and len(connections) > 0
        
        # Check for data exfiltration
        has_network = len(connections) > 0
        is_exfiltration = has_network and io_write_delta > IO_EXFIL_THRESHOLD
        
        # Determine event type
        if has_sensitive:
            event_type = "file"
        elif has_suspicious_port or is_shell_with_network or is_exfiltration:
            event_type = "network"
        elif connections:
            event_type = "network"
        else:
            event_type = "syscall"
        
        # Build event
        event = new_event_base()
        event.update({
            "timestamp": now,
            "event_type": event_type,
            "pid": pid,
            "ppid": ppid,
            "uid": uid,
            "gid": gid,
            "comm": comm,
            "exe_path": exe_path,
            "cmdline": cmdline,
            "cpu_percent": round(cpu_percent, 2),
            "memory_bytes": memory_bytes,
            "io_read_bytes": io_read,
            "io_write_bytes": io_write,
            "io_write_delta": io_write_delta,
            "syscall_name": "open" if has_sensitive else "",
            "file_op": "read" if has_sensitive else "",
        })
        
        # Add sensitive file info
        if has_sensitive:
            event["file_path"] = sensitive_file
        
        # Add network info
        active_conn = suspicious_conn or first_conn
        if active_conn:
            event["src_ip"] = active_conn.get("local_ip", "")
            event["src_port"] = active_conn.get("local_port", 0)
            event["dst_ip"] = active_conn.get("remote_ip", "")
            event["dst_port"] = active_conn.get("remote_port", 0)
            event["protocol"] = active_conn.get("protocol", "TCP")
        
        # Add detection flags
        event["has_suspicious_port"] = has_suspicious_port
        event["is_shell_with_network"] = is_shell_with_network
        event["is_exfiltration"] = is_exfiltration
        event["has_network"] = has_network
        
        return event
    
    def _cleanup_dead_processes(self):
        """Remove dead processes from tracking."""
        try:
            alive = {int(x) for x in os.listdir("/proc") if x.isdigit()}
            dead = [pid for pid in self._prev if pid not in alive]
            for pid in dead:
                self._prev.pop(pid, None)
                self._prev_io_write.pop(pid, None)
        except Exception:
            pass
