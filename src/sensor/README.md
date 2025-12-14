# Sensor (Person A)

MVP sensor for WSL2: collects process snapshots from /proc, exports events to CSV
(schema in shared/schemas/event_schema.py), and exposes REST API.

## Run
1) Create venv and install deps:
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt

2) Start service:
   uvicorn src.sensor.sensor_service:app --host 0.0.0.0 --port 8001 --reload

## API
- GET  /sensor/status
- POST /sensor/start    body: {"mode":"proc","sample_interval":1.0}
- POST /sensor/stop
- GET  /sensor/events/latest?limit=100

## CSV output
On start, writes to data/raw/events_YYYYMMDD_HHMMSS.csv with header EVENT_COLUMNS.
