from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Dict, List

import pandas as pd


def _rand_ts(start: datetime, end: datetime) -> str:
    delta = end - start
    sec = random.randint(0, max(1, int(delta.total_seconds())))
    return (start + timedelta(seconds=sec)).isoformat()


def generate_synthetic_events(n_normal: int = 2000, n_attack: int = 500) -> pd.DataFrame:
    """
    Sinh events tổng quát (độc lập).
    Bạn có thể mở rộng thêm các field sau khi nhìn thấy event_schema.py.
    """
    start = datetime.now() - timedelta(days=1)
    end = datetime.now()

    rows: List[Dict] = []

    # Normal
    for _ in range(n_normal):
        rows.append(
            {
                "timestamp": _rand_ts(start, end),
                "event_type": random.choice(["syscall", "network", "file"]),
                "cpu": max(0.0, random.gauss(15, 7)),
                "mem": max(0.0, random.gauss(30, 12)),
                "bytes_out": max(0.0, random.gauss(2_000, 1_500)),
                "file_ops": max(0, int(random.gauss(3, 2))),
                "label": 0,
                "label_reason": "synthetic_normal",
            }
        )

    # Attack-ish
    for _ in range(n_attack):
        et = random.choice(["syscall", "network", "file"])
        rows.append(
            {
                "timestamp": _rand_ts(start, end),
                "event_type": et,
                "cpu": max(0.0, random.gauss(75, 15)),
                "mem": max(0.0, random.gauss(80, 10)),
                "bytes_out": max(0.0, random.gauss(150_000, 50_000)) if et == "network" else max(0.0, random.gauss(20_000, 10_000)),
                "file_ops": max(0, int(random.gauss(80, 20))) if et == "file" else max(0, int(random.gauss(20, 10))),
                "label": 1,
                "label_reason": "synthetic_attack",
            }
        )

    df = pd.DataFrame(rows)
    return df


def save_synthetic_csv(path: str = "data/synthetic/synthetic_events.csv", n_normal: int = 2000, n_attack: int = 500) -> str:
    df = generate_synthetic_events(n_normal=n_normal, n_attack=n_attack)
    df.to_csv(path, index=False)
    return path


if __name__ == "__main__":
    out = save_synthetic_csv()
    print(f"Saved: {out}")
