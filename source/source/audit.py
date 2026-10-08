"""Audit trail of report-filter use. Stores only filter choices, never log contents or identities."""
import sqlite3
from datetime import datetime


def _conn(db_path):
    """Open the database and create the table if it does not exist yet."""
    c = sqlite3.connect(db_path)
    c.execute("""CREATE TABLE IF NOT EXISTS filter_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        modules TEXT, status TEXT,
        start_date TEXT, end_date TEXT,
        threshold REAL, rows_returned INTEGER)""")
    return c


def record_filter(db_path, modules, status, start, end, threshold, rows_returned):
    """Save one audit row. The ? placeholders make this a PARAMETERIZED query (stops SQL injection)."""
    c = _conn(db_path)
    with c:
        c.execute("INSERT INTO filter_audit (ts, modules, status, start_date, end_date, threshold, rows_returned) "
                  "VALUES (?,?,?,?,?,?,?)",
                  (datetime.now().isoformat(timespec="seconds"), ",".join(modules)[:200], str(status),
                   str(start), str(end), float(threshold), int(rows_returned)))
    c.close()


def recent(db_path, limit=20):
    """Read the latest audit rows (also parameterized)."""
    c = _conn(db_path)
    rows = c.execute("SELECT ts, modules, status, start_date, end_date, threshold, rows_returned "
                     "FROM filter_audit ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
    c.close()
    return rows