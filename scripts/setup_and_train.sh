#!/usr/bin/env bash
set -euo pipefail

echo "=============================================="
echo "AI-Based Intrusion Detection System - Setup"
echo "=============================================="

cd "$(dirname "$0")/.."
ROOT_DIR=$(pwd)

# Create virtual environment if not exists
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate venv
source .venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -q -r requirements.txt

# Create data directories
echo "Creating data directories..."
mkdir -p data/raw data/synthetic data/models

# Generate synthetic data
echo ""
echo "=============================================="
echo "Generating synthetic training data..."
echo "=============================================="
python3 -c "
from src.ml.data_generator.synthetic_generator import save_synthetic_csv
save_synthetic_csv(n_normal=3000, n_attack=1000)
"

# Train model
echo ""
echo "=============================================="
echo "Training ML model..."
echo "=============================================="
python3 -c "
from src.ml.training.train_pipeline import train_from_csv
artifacts, report = train_from_csv()
print()
print('Training complete!')
print(f'Model saved to: {artifacts.model_path}')
print(f'F1 Score: {report[\"classification_report\"][\"macro avg\"][\"f1-score\"]:.4f}')
"

echo ""
echo "=============================================="
echo "Setup complete!"
echo "=============================================="
echo ""
echo "To start the system, run:"
echo "  ./scripts/run_all.sh"
echo ""
