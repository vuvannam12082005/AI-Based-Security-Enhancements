#!/usr/bin/env python3
"""CPU Stress Test - Crypto Miner Simulation"""
import os, sys, time, signal

def main():
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    print(f"CPU STRESS TEST - PID: {os.getpid()}, Duration: {dur}s")
    
    signal.signal(signal.SIGINT, lambda s,f: sys.exit(0))
    start = time.time()
    i = 0
    
    while time.time() - start < dur:
        _ = sum(x*x for x in range(10000))
        i += 1
        if i % 5000 == 0:
            print(f"  {int(time.time()-start)}s")
    
    print("Done! Check: curl -s 'http://localhost:8001/sensor/enforcement_history?limit=5' | python3 -m json.tool")

if __name__ == "__main__":
    main()