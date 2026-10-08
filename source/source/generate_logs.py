"""Create a fully synthetic log file (no real IPs, accounts or secrets)."""
import csv, random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)  # same data every time you run it (reproducible)
OUT = Path(__file__).resolve().parent.parent / "data" / "activity_logs.csv"

# module -> probability of an error. payments is deliberately high so it gets flagged
MODULES = {"auth": 0.04, "search": 0.05, "reports": 0.04, "uploads": 0.07, "payments": 0.22}
EVENTS = ["LOGIN", "QUERY", "UPLOAD", "EXPORT", "API_CALL"]
start = datetime(2026, 9, 1)

rows = []
for _ in range(2000):
    m = random.choice(list(MODULES))
    err = random.random() < MODULES[m]
    dur = random.lognormvariate(5.0, 0.6) * (3 if err else 1)   # errors take ~3x longer
    ts = start + timedelta(seconds=random.randint(0, 7 * 86400))  # random time within 7 days
    rows.append([ts.isoformat(), m, random.choice(EVENTS), "ERROR" if err else "SUCCESS", round(dur, 1)])
rows.sort()

# 6 deliberately BAD rows to demonstrate safe handling of invalid input
rows += [["not-a-date", "auth", "LOGIN", "SUCCESS", 120],             # invalid timestamp
         ["2026-09-03T10:00:00", "auth", "LOGIN", "", 120],           # missing status
         ["2026-09-03T10:05:00", "search", "QUERY", "SUCCESS", -5],   # negative duration
         ["2026-09-03T10:06:00", "search", "QUERY", "SUCCESS", 99999999],  # extreme duration
         ["2026-09-03T10:07:00", "bad module!", "QUERY", "SUCCESS", 80],   # illegal characters
         ["2026-09-03T10:08:00", "auth", "LOGIN", "MAYBE", 80]]       # invalid status

OUT.parent.mkdir(exist_ok=True)
with open(OUT, "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["timestamp", "module", "event_type", "status", "duration_ms"])
    w.writerows(rows)
print(f"Wrote {len(rows)} rows to {OUT}")