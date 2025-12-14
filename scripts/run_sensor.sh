#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .venv/bin/activate
uvicorn src.sensor.sensor_service:app --host 0.0.0.0 --port 8001 --reload
