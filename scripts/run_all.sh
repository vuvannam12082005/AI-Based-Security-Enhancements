#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

echo "🚀 Starting AI Security Monitor - All Services"
echo "=============================================="

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    echo "❌ Virtual environment not found. Please run:"
    echo "   python3 -m venv .venv"
    echo "   source .venv/bin/activate"
    echo "   pip install -r requirements.txt"
    exit 1
fi

# Function to start service in background
start_service() {
    local name=$1
    local script=$2
    local port=$3
    
    echo "📡 Starting $name service on port $port..."
    
    # Kill existing process on port if any
    if lsof -ti:$port >/dev/null 2>&1; then
        echo "   Killing existing process on port $port"
        kill $(lsof -ti:$port) 2>/dev/null || true
        sleep 2
    fi
    
    # Start service
    bash "$script" &
    local pid=$!
    echo "   Started $name (PID: $pid)"
    
    # Wait a moment and check if still running
    sleep 3
    if kill -0 $pid 2>/dev/null; then
        echo "   ✅ $name is running"
    else
        echo "   ❌ $name failed to start"
        return 1
    fi
}

# Start sensor service
start_service "Sensor" "./scripts/run_sensor.sh" "8001"

# Start enforcer service (requires sudo)
echo "🛡️  Starting Enforcer service on port 8002..."
echo "   Note: This requires sudo privileges for cgroup management"
if command -v sudo >/dev/null 2>&1; then
    start_service "Enforcer" "./scripts/run_enforcer.sh" "8002"
else
    echo "   ⚠️  sudo not available - enforcer may not work properly"
    start_service "Enforcer" "./scripts/run_enforcer.sh" "8002"
fi

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 5

# Test service connectivity
echo "🔍 Testing service connectivity..."

# Test sensor
if curl -s http://localhost:8001/sensor/status >/dev/null 2>&1; then
    echo "   ✅ Sensor service: Ready"
else
    echo "   ❌ Sensor service: Not responding"
fi

# Test enforcer
if curl -s http://localhost:8002/enforcer/status >/dev/null 2>&1; then
    echo "   ✅ Enforcer service: Ready"
else
    echo "   ❌ Enforcer service: Not responding"
fi

# Start UI
echo "🖥️  Starting Streamlit UI on port 8501..."
export SENSOR_URL="http://localhost:8001"
export ENFORCER_URL="http://localhost:8002"
export ML_URL="http://localhost:8003"
export ORCH_API_URL="http://localhost:8000"
export WS_URL="ws://localhost:8000/ws/realtime"

# Start UI in foreground (so we can see logs and stop with Ctrl+C)
echo "=============================================="
echo "🎉 All services started!"
echo ""
echo "📊 Access the dashboard at: http://localhost:8501"
echo "📡 Sensor API: http://localhost:8001"
echo "🛡️  Enforcer API: http://localhost:8002"
echo ""
echo "Press Ctrl+C to stop all services"
echo "=============================================="

# Activate venv and start UI
source .venv/bin/activate
streamlit run src/integration/ui/app.py --server.address 0.0.0.0 --server.port 8501