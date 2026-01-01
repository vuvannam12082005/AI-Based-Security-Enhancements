# Enforcer Service

Thực thi các hành động ngăn chặn tiến trình nguy hiểm:
- kill: Gửi SIGKILL để dừng ngay tiến trình
- throttle: Giới hạn CPU/memory bằng cgroup v2

## Chạy service (cần sudo)

    cd ~/AI-Based-Security-Enhancements
    ./scripts/run_enforcer.sh

Hoặc:
    sudo -E bash -c 'source .venv/bin/activate && uvicorn src.enforcer.enforcer_service:app --host 0.0.0.0 --port 8002 --reload'

## Các endpoint

GET /enforcer/status
    Trả về engine (cgroupv2/cgroupv1), controllers available

POST /enforcer/action
    Kill: {"pid":1234,"action":"kill"}
    Throttle: {"pid":1234,"action":"throttle","cpu_max":"20000 100000","memory_max":268435456}

POST /enforcer/release
    {"pid":1234}
    Giải phóng process khỏi cgroup throttle

## Cgroup v2 implementation

File: src/enforcer/cgroups/cgroup_manager.py

1. Tạo cgroup tại /sys/fs/cgroup/ai-sec/[pid]/
2. Enable controllers: cpu, memory
3. Move process: echo [pid] > cgroup.procs
4. Set limits:
   - cpu.max: "quota period" (e.g., "5000 100000" = 5% CPU)
   - memory.max: bytes (e.g., 134217728 = 128MB)

## Throttle presets

CPU:
- 5% CPU: "5000 100000"
- 10% CPU: "10000 100000"
- 20% CPU: "20000 100000"

Memory:
- 128 MB: 134217728
- 256 MB: 268435456
- 512 MB: 536870912

## Liên quan OS

- Cgroup v2: Control Groups là cơ chế kernel Linux để quản lý và giới hạn tài nguyên
- Ghi trực tiếp vào /sys/fs/cgroup/ - sysfs interface của kernel
- Kill signal: Sử dụng os.kill(pid, signal.SIGKILL) - system call tới kernel
- Cần quyền root để modify cgroup hierarchy

## Fallback cgroup v1

Nếu cgroup v2 không có controllers, fallback sang v1:
- /sys/fs/cgroup/cpu/ai-sec/[pid]/cpu.cfs_quota_us
- /sys/fs/cgroup/memory/ai-sec/[pid]/memory.limit_in_bytes

## Người phụ trách

Nguyễn Công Sơn