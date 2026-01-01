# Streamlit UI

Dashboard và Alerts cho hệ thống AI Security Monitor.

## Chạy

    cd ~/AI-Based-Security-Enhancements
    source .venv/bin/activate
    ./scripts/run_ui.sh

Hoặc:
    streamlit run src/integration/ui/app.py --server.address 0.0.0.0 --server.port 8501

Mở trình duyệt: http://localhost:8501

## Cấu trúc

    src/integration/ui/
    ├── app.py              # Main Streamlit app
    ├── utils.py            # APIClient class
    ├── app_pages/
    │   ├── dashboard.py    # Real-time monitoring
    │   ├── alerts.py       # Enforcement history
    │   └── settings.py     # Start/stop sensor, config
    └── components/
        ├── charts.py       # Plotly charts
        └── tables.py       # Data tables

## Pages

1. Dashboard:
   - Service status (Sensor, Enforcer)
   - Detection metrics (events scanned, threats, blocked)
   - System metrics gauges (CPU, Memory)
   - Event stream table
   - Analytics charts

2. Alerts:
   - Enforcement history table
   - Filter by threat type, status, detection method
   - Manual actions (kill/throttle PID)

3. Settings:
   - Start/stop Sensor
   - Toggle Auto-Detect on/off
   - Configure action (throttle/kill)
   - Test connections

## Environment variables

    SENSOR_URL=http://localhost:8001
    ENFORCER_URL=http://localhost:8002
    ML_URL=http://localhost:8003
    ORCH_API_URL=http://localhost:8000

## Yêu cầu

Backend services phải chạy trước:
- Sensor (port 8001)
- Enforcer (port 8002)
- ML (port 8003)

## Người phụ trách

Nguyễn Công Sơn