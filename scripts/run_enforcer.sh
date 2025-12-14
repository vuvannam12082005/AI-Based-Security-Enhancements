#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
sudo -E bash -lc 'source .venv/bin/activate && uvicorn src.enforcer.enforcer_service:app --host 0.0.0.0 --port 8002 --reload'
