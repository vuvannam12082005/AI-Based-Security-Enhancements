#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Activate virtual environment
source .venv/bin/activate

# Set default environment variables
export SENSOR_URL="${SENSOR_URL:-http://localhost:8001}"
export ENFORCER_URL="${ENFORCER_URL:-http://localhost:8002}"
export ML_URL="${ML_URL:-http://localhost:8003}"
export ORCH_API_URL="${ORCH_API_URL:-http://localhost:8000}"
export WS_URL="${WS_URL:-ws://localhost:8000/ws/realtime}"

# Run Streamlit UI
streamlit run src/integration/ui/app.py --server.address 0.0.0.0 --server.port 8501