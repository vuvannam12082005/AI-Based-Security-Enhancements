"""
Synthetic Data Generator for Intrusion Detection System
========================================================
Generates realistic labeled data for training ML model to detect:
1. Sensitive file access
2. Privilege escalation attempts
3. Suspicious process execution
4. Resource abuse (crypto mining)
5. Reverse shell patterns
6. Data exfiltration
"""

from __future__ import annotations

import random
import uuid
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
import pandas as pd


# =============================================================================
# CONFIGURATION - Attack patterns and normal behavior profiles
# =============================================================================

SENSITIVE_FILES = [
    "/etc/shadow", "/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config",
    "/root/.ssh/authorized_keys", "/root/.ssh/id_rsa", "/root/.bash_history",
    "/etc/gshadow", "/etc/security/opasswd", "/var/log/auth.log"
]

NORMAL_FILES = [
    "/usr/bin/python3", "/usr/lib/libc.so", "/home/user/document.txt",
    "/tmp/cache.tmp", "/var/log/syslog", "/etc/hosts", "/etc/resolv.conf"
]

PRIV_ESCALATION_SYSCALLS = ["setuid", "setgid", "setresuid", "setresgid", "setreuid", "setregid"]
NORMAL_SYSCALLS = ["read", "write", "open", "close", "stat", "fstat", "mmap", "brk", "access"]
EXEC_SYSCALLS = ["execve", "execveat"]

SUSPICIOUS_EXEC_PATHS = [
    "/tmp/", "/dev/shm/", "/var/tmp/", "/run/user/", "/.hidden",
    "/tmp/shell", "/tmp/backdoor", "/dev/shm/exploit"
]

NORMAL_EXEC_PATHS = [
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/local/bin/",
    "/opt/", "/usr/lib/"
]

SHELL_COMMANDS = ["bash", "sh", "zsh", "dash", "fish", "tcsh", "csh"]
NORMAL_COMMANDS = ["python3", "node", "java", "nginx", "apache2", "sshd", "systemd", "cron"]

REVERSE_SHELL_PORTS = [4444, 5555, 6666, 1234, 1337, 9001, 9999, 31337]
NORMAL_PORTS = [80, 443, 22, 53, 8080, 3306, 5432, 6379, 27017]

MINER_COMMANDS = ["xmrig", "minerd", "cpuminer", "ethminer", "cgminer", "bfgminer"]


def _rand_timestamp(start: datetime, end: datetime) -> float:
    """Generate random Unix timestamp between start and end."""
    delta = (end - start).total_seconds()
    return (start + timedelta(seconds=random.uniform(0, delta))).timestamp()


def _generate_base_event(ts: float, label: int, label_reason: str) -> Dict[str, Any]:
    """Generate base event with common fields."""
    return {
        "timestamp": ts,
        "event_id": str(uuid.uuid4()),
        "event_type": "syscall",
        "pid": random.randint(1000, 65535),
        "ppid": random.randint(1, 1000),
        "uid": random.randint(0, 1000),
        "gid": random.randint(0, 1000),
        "comm": "",
        "exe_path": "",
        "syscall_nr": random.randint(0, 400),
        "syscall_name": "",
        "syscall_ret": 0,
        "src_ip": "",
        "dst_ip": "",
        "src_port": 0,
        "dst_port": 0,
        "protocol": "",
        "bytes_sent": 0,
        "bytes_recv": 0,
        "file_path": "",
        "file_op": "",
        "file_flags": 0,
        "cpu_percent": 0.0,
        "memory_bytes": 0,
        "io_read_bytes": 0,
        "io_write_bytes": 0,
        "label": label,
        "label_reason": label_reason,
    }


# =============================================================================
# NORMAL EVENT GENERATORS
# =============================================================================

def generate_normal_syscall(ts: float) -> Dict[str, Any]:
    """Normal syscall event - regular process activity."""
    event = _generate_base_event(ts, label=0, label_reason="normal_syscall")
    event["event_type"] = "syscall"
    event["comm"] = random.choice(NORMAL_COMMANDS)
    event["exe_path"] = random.choice(NORMAL_EXEC_PATHS) + event["comm"]
    event["syscall_name"] = random.choice(NORMAL_SYSCALLS)
    event["uid"] = random.randint(1000, 65000)  # Non-root
    event["cpu_percent"] = max(0, random.gauss(5, 3))
    event["memory_bytes"] = int(max(0, random.gauss(50_000_000, 30_000_000)))
    return event


def generate_normal_file_access(ts: float) -> Dict[str, Any]:
    """Normal file access - reading regular files."""
    event = _generate_base_event(ts, label=0, label_reason="normal_file_access")
    event["event_type"] = "file"
    event["comm"] = random.choice(NORMAL_COMMANDS)
    event["exe_path"] = random.choice(NORMAL_EXEC_PATHS) + event["comm"]
    event["file_path"] = random.choice(NORMAL_FILES)
    event["file_op"] = random.choice(["read", "write", "open"])
    event["syscall_name"] = "open"
    event["uid"] = random.randint(1000, 65000)
    event["cpu_percent"] = max(0, random.gauss(2, 1))
    event["memory_bytes"] = int(max(0, random.gauss(30_000_000, 15_000_000)))
    event["io_read_bytes"] = random.randint(0, 100000)
    return event


def generate_normal_network(ts: float) -> Dict[str, Any]:
    """Normal network activity - web requests, DB connections."""
    event = _generate_base_event(ts, label=0, label_reason="normal_network")
    event["event_type"] = "network"
    event["comm"] = random.choice(["curl", "wget", "python3", "node", "nginx"])
    event["exe_path"] = "/usr/bin/" + event["comm"]
    event["src_ip"] = f"192.168.1.{random.randint(2, 254)}"
    event["dst_ip"] = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    event["src_port"] = random.randint(32768, 65535)
    event["dst_port"] = random.choice(NORMAL_PORTS)
    event["protocol"] = "TCP"
    event["bytes_sent"] = random.randint(100, 10000)
    event["bytes_recv"] = random.randint(1000, 100000)
    event["uid"] = random.randint(1000, 65000)
    event["cpu_percent"] = max(0, random.gauss(3, 2))
    event["memory_bytes"] = int(max(0, random.gauss(40_000_000, 20_000_000)))
    return event


def generate_normal_process_exec(ts: float) -> Dict[str, Any]:
    """Normal process execution - legitimate programs."""
    event = _generate_base_event(ts, label=0, label_reason="normal_exec")
    event["event_type"] = "syscall"
    event["syscall_name"] = "execve"
    event["comm"] = random.choice(NORMAL_COMMANDS)
    event["exe_path"] = random.choice(NORMAL_EXEC_PATHS) + event["comm"]
    event["uid"] = random.randint(1000, 65000)
    event["cpu_percent"] = max(0, random.gauss(10, 5))
    event["memory_bytes"] = int(max(0, random.gauss(80_000_000, 40_000_000)))
    return event


# =============================================================================
# ATTACK EVENT GENERATORS
# =============================================================================

def generate_sensitive_file_access(ts: float) -> Dict[str, Any]:
    """ATTACK: Accessing sensitive system files (password files, SSH keys)."""
    event = _generate_base_event(ts, label=1, label_reason="sensitive_file_access")
    event["event_type"] = "file"
    event["comm"] = random.choice(["cat", "vim", "nano", "less", "head", "tail", "python3"])
    event["exe_path"] = "/usr/bin/" + event["comm"]
    event["file_path"] = random.choice(SENSITIVE_FILES)
    event["file_op"] = random.choice(["read", "open"])
    event["syscall_name"] = "open"
    event["uid"] = random.randint(1000, 65000)  # Non-root trying to access sensitive files
    event["cpu_percent"] = max(0, random.gauss(2, 1))
    event["memory_bytes"] = int(max(0, random.gauss(20_000_000, 10_000_000)))
    event["io_read_bytes"] = random.randint(100, 5000)
    return event


def generate_privilege_escalation(ts: float) -> Dict[str, Any]:
    """ATTACK: Attempting privilege escalation via setuid/setgid syscalls."""
    event = _generate_base_event(ts, label=1, label_reason="privilege_escalation")
    event["event_type"] = "syscall"
    event["comm"] = random.choice(["exploit", "sudo", "su", "pkexec", "python3", "perl"])
    event["exe_path"] = random.choice(["/tmp/exploit", "/dev/shm/pwn", "/usr/bin/" + event["comm"]])
    event["syscall_name"] = random.choice(PRIV_ESCALATION_SYSCALLS)
    event["uid"] = random.randint(1000, 65000)  # Non-root attempting privilege escalation
    event["syscall_ret"] = random.choice([0, -1])  # May succeed or fail
    event["cpu_percent"] = max(0, random.gauss(5, 3))
    event["memory_bytes"] = int(max(0, random.gauss(30_000_000, 15_000_000)))
    return event


def generate_suspicious_exec(ts: float) -> Dict[str, Any]:
    """ATTACK: Executing programs from suspicious locations (/tmp, /dev/shm)."""
    event = _generate_base_event(ts, label=1, label_reason="suspicious_exec")
    event["event_type"] = "syscall"
    event["syscall_name"] = "execve"
    suspicious_path = random.choice(SUSPICIOUS_EXEC_PATHS)
    event["comm"] = random.choice(["shell", "backdoor", "exploit", "payload", "rev", "bind"])
    event["exe_path"] = suspicious_path + event["comm"]
    event["uid"] = random.randint(1000, 65000)
    event["cpu_percent"] = max(0, random.gauss(15, 8))
    event["memory_bytes"] = int(max(0, random.gauss(50_000_000, 25_000_000)))
    return event


def generate_crypto_miner(ts: float) -> Dict[str, Any]:
    """ATTACK: Crypto mining behavior - sustained high CPU usage."""
    event = _generate_base_event(ts, label=1, label_reason="crypto_miner")
    event["event_type"] = "syscall"
    event["comm"] = random.choice(MINER_COMMANDS + ["python3", "java", "node"])
    event["exe_path"] = random.choice(["/tmp/", "/dev/shm/", "/opt/", "/usr/bin/"]) + event["comm"]
    event["syscall_name"] = random.choice(["read", "write", "futex", "nanosleep"])
    event["uid"] = random.randint(1000, 65000)
    event["cpu_percent"] = random.uniform(80, 100)  # Very high CPU
    event["memory_bytes"] = int(random.uniform(200_000_000, 500_000_000))  # High memory
    return event


def generate_reverse_shell(ts: float) -> Dict[str, Any]:
    """ATTACK: Reverse shell - shell process with outbound connection to unusual port."""
    event = _generate_base_event(ts, label=1, label_reason="reverse_shell")
    event["event_type"] = "network"
    event["comm"] = random.choice(SHELL_COMMANDS)
    event["exe_path"] = "/bin/" + event["comm"]
    event["src_ip"] = f"192.168.1.{random.randint(2, 254)}"
    event["dst_ip"] = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    event["src_port"] = random.randint(32768, 65535)
    event["dst_port"] = random.choice(REVERSE_SHELL_PORTS)
    event["protocol"] = "TCP"
    event["bytes_sent"] = random.randint(50, 500)  # Shell commands are small
    event["bytes_recv"] = random.randint(100, 2000)  # Responses
    event["uid"] = random.randint(1000, 65000)
    event["cpu_percent"] = max(0, random.gauss(5, 3))
    event["memory_bytes"] = int(max(0, random.gauss(10_000_000, 5_000_000)))
    return event


def generate_data_exfiltration(ts: float) -> Dict[str, Any]:
    """ATTACK: Data exfiltration - large outbound data transfer."""
    event = _generate_base_event(ts, label=1, label_reason="data_exfiltration")
    event["event_type"] = "network"
    event["comm"] = random.choice(["curl", "wget", "nc", "python3", "scp", "rsync"])
    event["exe_path"] = "/usr/bin/" + event["comm"]
    event["src_ip"] = f"192.168.1.{random.randint(2, 254)}"
    event["dst_ip"] = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    event["src_port"] = random.randint(32768, 65535)
    event["dst_port"] = random.choice([443, 8443, 8080, 9000] + REVERSE_SHELL_PORTS)
    event["protocol"] = "TCP"
    event["bytes_sent"] = random.randint(1_000_000, 50_000_000)  # Large outbound
    event["bytes_recv"] = random.randint(100, 1000)  # Small response
    event["uid"] = random.randint(1000, 65000)
    event["cpu_percent"] = max(0, random.gauss(10, 5))
    event["memory_bytes"] = int(max(0, random.gauss(100_000_000, 50_000_000)))
    event["io_read_bytes"] = random.randint(1_000_000, 50_000_000)  # Reading files to send
    return event


# =============================================================================
# MAIN GENERATOR
# =============================================================================

def generate_synthetic_events(
    n_normal: int = 3000,
    n_attack: int = 1000,
    attack_distribution: Dict[str, float] = None
) -> pd.DataFrame:
    """
    Generate synthetic events for training intrusion detection model.
    
    Args:
        n_normal: Number of normal events
        n_attack: Number of attack events
        attack_distribution: Dict mapping attack type to proportion (must sum to 1.0)
    
    Returns:
        DataFrame with labeled events
    """
    if attack_distribution is None:
        attack_distribution = {
            "sensitive_file_access": 0.20,
            "privilege_escalation": 0.20,
            "suspicious_exec": 0.15,
            "crypto_miner": 0.15,
            "reverse_shell": 0.15,
            "data_exfiltration": 0.15,
        }
    
    start = datetime.now() - timedelta(days=1)
    end = datetime.now()
    
    events: List[Dict[str, Any]] = []
    
    # Generate normal events
    normal_generators = [
        generate_normal_syscall,
        generate_normal_file_access,
        generate_normal_network,
        generate_normal_process_exec,
    ]
    
    for _ in range(n_normal):
        ts = _rand_timestamp(start, end)
        generator = random.choice(normal_generators)
        events.append(generator(ts))
    
    # Generate attack events
    attack_generators = {
        "sensitive_file_access": generate_sensitive_file_access,
        "privilege_escalation": generate_privilege_escalation,
        "suspicious_exec": generate_suspicious_exec,
        "crypto_miner": generate_crypto_miner,
        "reverse_shell": generate_reverse_shell,
        "data_exfiltration": generate_data_exfiltration,
    }
    
    for attack_type, proportion in attack_distribution.items():
        n_this_attack = int(n_attack * proportion)
        generator = attack_generators[attack_type]
        for _ in range(n_this_attack):
            ts = _rand_timestamp(start, end)
            events.append(generator(ts))
    
    # Shuffle events
    random.shuffle(events)
    
    return pd.DataFrame(events)


def save_synthetic_csv(
    path: str = "data/synthetic/synthetic_events.csv",
    n_normal: int = 3000,
    n_attack: int = 1000
) -> str:
    """Generate and save synthetic events to CSV."""
    import os
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    df = generate_synthetic_events(n_normal=n_normal, n_attack=n_attack)
    df.to_csv(path, index=False)
    
    # Print statistics
    print(f"Generated {len(df)} events:")
    print(f"  - Normal: {len(df[df['label'] == 0])}")
    print(f"  - Attack: {len(df[df['label'] == 1])}")
    print(f"\nAttack breakdown:")
    for reason in df[df['label'] == 1]['label_reason'].value_counts().items():
        print(f"  - {reason[0]}: {reason[1]}")
    print(f"\nSaved to: {path}")
    
    return path


if __name__ == "__main__":
    save_synthetic_csv()
