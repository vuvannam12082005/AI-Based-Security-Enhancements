#!/usr/bin/env python3
"""
Attack Simulation Tests for AI-Based Security Enhancements
Các test này dùng để demo detection với proc mode

Usage:
    python3 tests/test_scripts/test_attacks.py all
    python3 tests/test_scripts/test_attacks.py cpu_abuse 30
    python3 tests/test_scripts/test_attacks.py sensitive_file
    python3 tests/test_scripts/test_attacks.py suspicious_exec
    python3 tests/test_scripts/test_attacks.py reverse_shell 30
"""

import os
import sys
import time
import socket
import signal
import subprocess
from datetime import datetime

DEFAULT_DURATION = 30

def print_header(test_name, expected_detection):
    print("=" * 60)
    print(f"TEST: {test_name}")
    print(f"PID: {os.getpid()}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print(f"Expected detection: {expected_detection}")
    print("-" * 60)

def test_cpu_abuse(duration=DEFAULT_DURATION):
    """CPU Abuse / Crypto Miner Simulation"""
    print_header("CPU Abuse (Crypto Miner)", "high_cpu_usage")
    print(f"Running CPU stress for {duration} seconds...")
    
    start = time.time()
    iterations = 0
    try:
        while time.time() - start < duration:
            _ = sum(i * i for i in range(10000))
            iterations += 1
            if iterations % 5000 == 0:
                print(f"  {int(time.time() - start)}s - {iterations} iterations")
    except KeyboardInterrupt:
        pass
    
    print(f"\n[DONE] CPU stress completed")
    print("[CHECK] curl -s 'http://localhost:8001/sensor/enforcement_history?limit=5' | python3 -m json.tool")

def test_sensitive_file(duration=DEFAULT_DURATION):
    """Sensitive File Access"""
    print_header("Sensitive File Access", "sensitive_file_access")
    
    files = ["/etc/shadow", "/etc/passwd", "/etc/sudoers"]
    opened = None
    
    for f in files:
        try:
            opened = open(f, "r")
            print(f"SUCCESS: Opened {f}")
            break
        except:
            print(f"DENIED: {f}")
    
    if opened:
        print(f"Holding file open for {duration}s...")
        try:
            for i in range(duration):
                time.sleep(1)
                if i % 10 == 0:
                    print(f"  {i}s...")
        except KeyboardInterrupt:
            pass
        opened.close()
    
    print("\n[DONE] File access test completed")
    print("[CHECK] curl -s 'http://localhost:8001/sensor/enforcement_history?limit=5' | python3 -m json.tool")

def test_suspicious_exec(duration=DEFAULT_DURATION):
    """Suspicious Execution from /tmp"""
    print_header("Suspicious Exec (/tmp)", "suspicious_exec")
    
    script = "/tmp/evil_test.sh"
    with open(script, "w") as f:
        f.write(f"#!/bin/bash\necho 'Evil from /tmp'\nsleep {duration}\n")
    os.chmod(script, 0o755)
    
    print(f"Running {script}...")
    try:
        subprocess.run([script], timeout=duration+5)
    except:
        pass
    
    try:
        os.remove(script)
    except:
        pass
    
    print("\n[DONE] Suspicious exec test completed")
    print("[CHECK] curl -s 'http://localhost:8001/sensor/enforcement_history?limit=5' | python3 -m json.tool")

def test_reverse_shell(duration=DEFAULT_DURATION):
    """Reverse Shell - Connect to suspicious ports"""
    print_header("Reverse Shell (Port 4444)", "reverse_shell")
    
    # Start listener bằng nc
    print("Starting listener on port 4444...")
    listener = subprocess.Popen(
        ["nc", "-l", "4444"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    time.sleep(1)
    
    print(f"PID của test process: {os.getpid()}")
    print("Connecting to suspicious port 4444...")
    
    client = socket.socket()
    try:
        client.connect(("127.0.0.1", 4444))
        print("Connected to suspicious port 4444!")
        
        print(f"Holding connection for {duration}s...")
        for i in range(duration):
            time.sleep(1)
            if i % 10 == 0:
                print(f"  {i}s...")
    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        client.close()
        listener.terminate()
        listener.wait()
    
    print("\n[DONE] Reverse shell test completed")
    print("[CHECK] curl -s 'http://localhost:8001/sensor/enforcement_history?limit=5' | python3 -m json.tool")

def test_all():
    """Run all tests - chỉ 4 loại detect được với proc mode"""
    print("RUNNING ALL ATTACK TESTS (PROC MODE)")
    print("=" * 60)
    
    # Chỉ chạy 4 test detect được với proc mode
    tests = [
        ("CPU Abuse", test_cpu_abuse),
        ("Sensitive File", test_sensitive_file),
        ("Suspicious Exec", test_suspicious_exec),
        ("Reverse Shell", test_reverse_shell),
    ]
    
    for name, func in tests:
        print(f"\n>>> Starting: {name}")
        func(20)
        print("Waiting 5s before next test...")
        time.sleep(5)
    
    print("\n" + "=" * 60)
    print("ALL TESTS DONE!")
    print("=" * 60)
    print("\nCheck results:")
    print("  curl -s 'http://localhost:8001/sensor/enforcement_history?limit=20' | python3 -m json.tool")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    
    if len(sys.argv) < 2:
        print("Usage: python3 test_attacks.py <test_name> [duration]")
        print("")
        print("Available tests:")
        print("  all            - Run all 4 tests")
        print("  cpu_abuse      - CPU stress (crypto miner)")
        print("  sensitive_file - Read /etc/shadow, /etc/passwd")
        print("  suspicious_exec- Execute from /tmp/")
        print("  reverse_shell  - Connect to port 4444")
        print("")
        print("Example:")
        print("  python3 test_attacks.py cpu_abuse 30")
        sys.exit(1)
    
    test = sys.argv[1].lower()
    dur = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_DURATION
    
    tests = {
        "all": test_all,
        "cpu_abuse": test_cpu_abuse,
        "cpu": test_cpu_abuse,
        "sensitive_file": test_sensitive_file,
        "file": test_sensitive_file,
        "suspicious_exec": test_suspicious_exec,
        "exec": test_suspicious_exec,
        "reverse_shell": test_reverse_shell,
        "shell": test_reverse_shell,
    }
    
    if test in tests:
        if test == "all":
            tests[test]()
        else:
            tests[test](dur)
    else:
        print(f"Unknown test: {test}")
        print("Available: all, cpu_abuse, sensitive_file, suspicious_exec, reverse_shell")
