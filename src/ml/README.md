# ML Service

Cung cấp API cho model inference và retraining. Sử dụng RandomForest classifier để phát hiện 6 loại tấn công.

## Chạy service

    cd ~/AI-Based-Security-Enhancements
    source .venv/bin/activate
    uvicorn src.ml.ml_service:app --host 0.0.0.0 --port 8003 --reload

## Các endpoint

GET /ml/status
    Kiểm tra model đã load chưa, feature count, supported threats

POST /ml/predict
    Body: {"event": {...}}
    Trả về: label (0/1), score (0-1), action (allow/monitor/block), threat_type

POST /ml/predict/batch
    Body: {"events": [{...}, {...}]}

POST /ml/retrain
    Body: {"csv_path":"...", "regenerate":true, "n_normal":3000, "n_attack":1000}

POST /ml/generate
    Tạo synthetic data mới

GET /ml/report
    Xem training report (accuracy, f1, confusion matrix)

## Features được sử dụng

Numeric features từ /proc:
- pid, ppid, uid, gid
- cpu_percent, memory_bytes
- io_read_bytes, io_write_bytes
- src_port, dst_port, bytes_sent, bytes_recv

Derived features (feature engineering):
- is_sensitive_file: file_path chứa /etc/shadow, /etc/passwd, ...
- is_suspicious_path: exe_path từ /tmp/, /dev/shm/
- is_priv_escalation: syscall setuid/setgid
- is_shell: comm là bash/sh/zsh
- is_miner_name: comm là xmrig/minerd/...
- is_high_cpu: cpu_percent > 70
- is_suspicious_port: dst_port trong [4444, 5555, 6666, ...]
- is_large_outbound: bytes_sent > 500KB
- is_shell_network: shell + network event
- is_nonroot_sensitive: uid >= 1000 và truy cập sensitive file

## Các loại tấn công phát hiện được

1. sensitive_file_access
2. privilege_escalation
3. suspicious_exec
4. crypto_miner
5. reverse_shell
6. data_exfiltration

## Liên quan OS

- Feature engineering xử lý dữ liệu từ /proc (cpu_percent, memory_bytes, ...)
- Các features phản ánh trạng thái process trong kernel
- Hiểu được ý nghĩa của từng field trong /proc/[pid]/stat

## Người phụ trách

Trần Bình Minh
