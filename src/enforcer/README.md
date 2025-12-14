# Enforcer (Person A)

Enforcer service exposes actions to throttle or kill a process.

## Important (WSL2)
WSL2 here has cgroup v2 mounted but with empty controllers, so throttling uses cgroups v1:
- /sys/fs/cgroup/cpu
- /sys/fs/cgroup/memory

## Run (requires sudo)
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

sudo -E uvicorn src.enforcer.enforcer_service:app --host 0.0.0.0 --port 8002 --reload

## API
- GET  /enforcer/status
- POST /enforcer/action
  - throttle: {"pid":1234,"action":"throttle","cpu_max":"20000 100000","memory_max":268435456}
  - kill:     {"pid":1234,"action":"kill"}
- POST /enforcer/release: {"pid":1234}
