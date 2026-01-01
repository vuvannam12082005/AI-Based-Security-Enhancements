#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "🚀 Starting AI Security Monitor - All Services"
echo "=============================================="

# Check virtual environment
if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment not found. Run first:"
    echo "   ./scripts/setup_and_train.sh"
    exit 1
fi

source .venv/bin/activate

# Function to kill process on port (dùng sudo để kill cả root processes)
kill_port() {
    local port=$1
    local pid=$(sudo lsof -ti:$port 2>/dev/null || true)
    if [ -n "$pid" ]; then
        echo "   Killing process on port $port (PID: $pid)"
        sudo kill -9 $pid 2>/dev/null || true
        sleep 1
    fi
}

echo ""
echo "🔪 Cleaning up old processes..."
kill_port 8000
kill_port 8001
kill_port 8002
kill_port 8003
kill_port 8501
sleep 2

echo ""
echo "📡 Starting Sensor on port 8001..."
.venv/bin/uvicorn src.sensor.sensor_service:app --host 0.0.0.0 --port 8001 &
sleep 2

echo "🛡️  Starting Enforcer on port 8002 (requires sudo)..."
sudo -E .venv/bin/uvicorn src.enforcer.enforcer_service:app --host 0.0.0.0 --port 8002 &
sleep 2

echo "🧠 Starting ML on port 8003..."
.venv/bin/uvicorn src.ml.ml_service:app --host 0.0.0.0 --port 8003 &
sleep 2

echo "🎯 Starting Orchestrator on port 8000..."
.venv/bin/uvicorn src.integration.api.main:app --host 0.0.0.0 --port 8000 &
sleep 3

echo ""
echo "🔍 Checking services..."

check_service() {
    local name=$1
    local url=$2
    if curl -s "$url" >/dev/null 2>&1; then
        echo "   ✅ $name: Ready"
        return 0
    else
        echo "   ❌ $name: Not responding"
        return 1
    fi
}

check_service "Sensor" "http://localhost:8001/sensor/status"
check_service "Enforcer" "http://localhost:8002/enforcer/status"
check_service "ML" "http://localhost:8003/ml/status"
check_service "Orchestrator" "http://localhost:8000/status"

echo ""
echo "=============================================="
echo "🎉 All services started!"
echo ""
echo "📊 UI Dashboard:    http://localhost:8501"
echo "📡 Sensor API:      http://localhost:8001"
echo "🛡️  Enforcer API:    http://localhost:8002"
echo "🧠 ML API:          http://localhost:8003"
echo "🎯 Orchestrator:    http://localhost:8000"
echo ""
echo "Press Ctrl+C to stop all services"
echo "=============================================="
echo ""

echo "🖥️  Starting UI on port 8501..."
.venv/bin/streamlit run src/integration/ui/app.py \
    --server.address 0.0.0.0 \
    --server.port 8501 \
    --server.headless true
