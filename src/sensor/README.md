# Sensor Service

Thu thập sự kiện từ tiến trình, lưu trong memory, xuất CSV, và chạy phát hiện theo thời gian thực với ML + rule-based.

## Phương thức thu thập

/proc polling: Đọc trực tiếp từ /proc filesystem
- File: src/sensor/loader/collector.py
- Đọc: /proc/[pid]/stat, /proc/[pid]/status, /proc/[pid]/statm, /proc/[pid]/io, /proc/[pid]/fd

## Chạy service

    cd ~/AI-Based-Security-Enhancements
    ./scripts/run_all.sh

## Các endpoint chính

- GET /sensor/status - Trạng thái sensor
- POST /sensor/start - Bắt đầu thu thập
- POST /sensor/stop - Dừng thu thập
- GET /sensor/events/latest?limit=100 - Lấy events mới nhất
- POST /sensor/auto_detect - Bật/tắt auto-detect
- GET /sensor/enforcement_history?limit=50 - Lịch sử threats

## Liên quan OS

- Đọc /proc filesystem: tương tác trực tiếp với kernel qua procfs
- CPU time từ /proc/[pid]/stat
- Memory từ /proc/[pid]/statm
- Network từ /proc/net/tcp và /proc/[pid]/fd

## Người phụ trách

Vũ Văn Nam
