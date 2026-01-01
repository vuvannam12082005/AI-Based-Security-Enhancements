# AI-Based Security Enhancements (OS Project)

Hệ thống phát hiện và ngăn chặn xâm nhập theo thời gian thực trên Linux.

## Tổng quan

Hệ thống giám sát các tiến trình đang chạy, sử dụng model ML để phát hiện hành vi đáng ngờ, và thực thi phản hồi theo thời gian thực.

Gồm 5 thành phần chính:

- Sensor: Thu thập sự kiện từ tiến trình qua /proc filesystem
- ML Service: Dự đoán hành vi bình thường hay tấn công (RandomForest)
- Enforcer: Giới hạn/dừng tiến trình nguy hiểm bằng cgroup v2
- Orchestrator: API tích hợp pipeline detect-and-respond
- Streamlit UI: Dashboard và cảnh báo thời gian thực

Môi trường: Ubuntu VM (VirtualBox), Python 3.10+

## Yêu cầu hệ thống

- Ubuntu 22.04+ (VM hoặc native)
- Python 3.10+
- Quyền sudo (cho Enforcer)

## Cài đặt và huấn luyện (chạy 1 lần)

cd ~/AI-Based-Security-Enhancements
chmod +x scripts/*.sh
./scripts/setup_and_train.sh

Lệnh này sẽ tạo ra:

- data/synthetic/synthetic_events.csv - dữ liệu huấn luyện
- data/models/classifier_pipeline.joblib - model đã train

## Chạy hệ thống

cd ~/AI-Based-Security-Enhancements
./scripts/run_all.sh

Truy cập:

- UI Dashboard: http://localhost:8501
- Sensor API: http://localhost:8001/sensor/status
- Enforcer API: http://localhost:8002/enforcer/status
- ML API: http://localhost:8003/ml/status
- Orchestrator: http://localhost:8000/status

## Demo (giả lập tấn công)

1. Mở UI tại http://localhost:8501
2. Vào Settings, đảm bảo:
   - Sensor đang chạy (mode: proc)
   - Auto-Detect: ON
   - Action: throttle hoặc kill

3. Chạy test trong terminal khác:

Test CPU abuse (crypto miner simulation):
python3 tests/test_scripts/test_attacks.py cpu_abuse 30

Test sensitive file access:
python3 tests/test_scripts/test_attacks.py sensitive_file

Test suspicious execution:
python3 tests/test_scripts/test_attacks.py suspicious_exec

Test reverse shell:
python3 tests/test_scripts/test_attacks.py reverse_shell 30

Chạy tất cả tests:
python3 tests/test_scripts/test_attacks.py all

4. Quan sát kết quả trên UI Dashboard hoặc:

curl -s "http://localhost:8001/sensor/enforcement_history?limit=10" | python3 -m json.tool

## Các loại tấn công phát hiện được

| Loại tấn công | Mô tả | Detection |
|---------------|-------|-----------|
| CPU Abuse (Crypto Miner) | CPU > 80% kéo dài | Rule + ML |
| Sensitive File Access | Đọc /etc/shadow, /etc/passwd... | Rule + ML |
| Suspicious Exec | Thực thi từ /tmp/, /dev/shm/ | Rule |
| Reverse Shell | Kết nối đến port nghi ngờ (4444, 5555...) | Rule |
| Data Exfiltration | Gửi lượng lớn dữ liệu ra ngoài | Future (eBPF) |

## Cấu trúc thư mục

AI-Based-Security-Enhancements/
├── src/
│   ├── sensor/           # Thu thập events từ /proc
│   ├── ml/               # ML service: train, predict
│   ├── enforcer/         # Cgroup v2 throttle/kill
│   └── integration/      # Orchestrator + UI
├── shared/               # Schema dùng chung
├── scripts/              # run_all.sh, setup_and_train.sh
├── tests/                # Test scripts
└── data/                 # Data và models

## Kiến trúc hệ thống

Sensor (8001) --> ML Service (8003) --> Enforcer (8002)
      |                |                    |
      +----------------+--------------------+
                       |
               Orchestrator (8000)
                       |
               Streamlit UI (8501)

## Lưu ý kỹ thuật

- Enforcer cần sudo vì ghi vào /sys/fs/cgroup/
- Hệ thống tự động whitelist các service để tránh tự block
- Mode proc polling mỗi 0.5s, detect trong khoảng 10s
- Mode eBPF (future): real-time, hỗ trợ data exfiltration detection

## Phân công công việc

| Thành viên | Công việc |
|------------|-----------|
| Vũ Văn Nam | Sensor collector (/proc), Schema, CSV exporter |
| Trần Bình Minh | ML service (train, predict), Feature engineering |
| Nguyễn Công Sơn | Enforcer (cgroup v2), Scripts, UI, Demo |

## References

- Linux /proc filesystem: https://man7.org/linux/man-pages/man5/proc.5.html
- Cgroup v2: https://docs.kernel.org/admin-guide/cgroup-v2.html
- scikit-learn RandomForest: https://scikit-learn.org/stable/modules/ensemble.html
- FastAPI: https://fastapi.tiangolo.com/
- Streamlit: https://streamlit.io/
