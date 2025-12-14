import csv, os
from datetime import datetime
from typing import Dict, List, Any
from shared.schemas.event_schema import EVENT_COLUMNS

class CsvExporter:
    def __init__(self, out_dir: str = "data/raw"):
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        self.file_path = os.path.join(out_dir, f"events_{ts}.csv")
        self._init_file()

    def _init_file(self):
        with open(self.file_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=EVENT_COLUMNS)
            w.writeheader()

    def append(self, event: Dict[str, Any]):
        row = {k: event.get(k, "") for k in EVENT_COLUMNS}
        with open(self.file_path, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=EVENT_COLUMNS)
            w.writerow(row)
