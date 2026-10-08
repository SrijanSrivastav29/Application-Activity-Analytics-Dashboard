"""Parsing, validation, summary metrics and threshold flags for synthetic activity logs."""
import csv, io, re
from datetime import datetime, timezone
import pandas as pd

# ---- Settings (kept as named constants so they are easy to document) ----
REQUIRED = ["timestamp", "module", "event_type", "status", "duration_ms"]  # mandatory CSV columns
VALID_STATUS = {"SUCCESS", "ERROR"}                 # allow-list: only these statuses are accepted
NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,32}$")       # module/event names: letters, digits, underscore only
MAX_DURATION_MS = 600_000                           # durations above 10 minutes are rejected as implausible
MAX_FILE_BYTES = 2 * 1024 * 1024                    # 2 MB size limit (security control)
DEFAULT_THRESHOLD = 0.15                            # 15% = about 3x the ~5% baseline error rate


def _empty_df():
    """Return an empty table with correct columns, so later code never crashes on empty input."""
    return pd.DataFrame({"timestamp": pd.Series(dtype="datetime64[ns]"),
                         "module": pd.Series(dtype="object"),
                         "event_type": pd.Series(dtype="object"),
                         "status": pd.Series(dtype="object"),
                         "duration_ms": pd.Series(dtype="float64")})


def _validate_row(row):
    """Check one CSV row. Returns (clean_row, None) if valid, or (None, reason) if invalid."""
    # 1. Every required field must be present and non-blank
    for col in REQUIRED:
        if row.get(col) is None or str(row[col]).strip() == "":
            return None, f"missing field: {col}"
    # 2. Timestamp must be a valid ISO date-time
    try:
        ts = datetime.fromisoformat(row["timestamp"].strip())
        if ts.tzinfo:  # convert timezone-aware times to plain UTC
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
    except ValueError:
        return None, "invalid timestamp"
    # 3. Module and event names must match the safe pattern
    module, event = row["module"].strip(), row["event_type"].strip()
    if not NAME_RE.match(module):
        return None, "invalid module name"
    if not NAME_RE.match(event):
        return None, "invalid event type"
    # 4. Status must be on the allow-list
    status = row["status"].strip().upper()
    if status not in VALID_STATUS:
        return None, "invalid status"
    # 5. Duration must be a number in a sensible range
    try:
        dur = float(row["duration_ms"])
    except ValueError:
        return None, "non-numeric duration"
    if dur != dur or dur < 0 or dur > MAX_DURATION_MS:  # dur != dur is True only for NaN
        return None, "duration out of range"
    return {"timestamp": ts, "module": module, "event_type": event.upper(),
            "status": status, "duration_ms": dur}, None


def parse_log_text(text):
    """Parse CSV text. Returns (table of valid rows, list of rejected rows with reasons)."""
    if not text.strip():                      # empty file -> empty result, no crash
        return _empty_df(), []
    reader = csv.DictReader(io.StringIO(text))
    # Header must contain all required columns
    if reader.fieldnames is None or any(c not in reader.fieldnames for c in REQUIRED):
        raise ValueError("Header must contain: " + ", ".join(REQUIRED))
    good, rejected = [], []
    for line_no, row in enumerate(reader, start=2):   # start=2 because line 1 is the header
        clean, reason = _validate_row(row)
        if clean:
            good.append(clean)
        else:
            # Only the line number and reason are kept, not the raw (possibly malicious) content
            rejected.append({"line": line_no, "reason": reason})
    return (pd.DataFrame(good, columns=REQUIRED) if good else _empty_df()), rejected


def parse_log_bytes(data):
    """Used for uploaded files. Enforces the 2 MB limit before parsing."""
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("File exceeds 2 MB limit")
    return parse_log_text(data.decode("utf-8", errors="replace"))


def parse_log_file(path):
    """Read a file from disk (reads at most limit+1 bytes so huge files are caught)."""
    with open(path, "rb") as f:
        return parse_log_bytes(f.read(MAX_FILE_BYTES + 1))


def summarize(df):
    """Per-module event count, errors, error rate, average and median duration."""
    cols = ["module", "events", "errors", "error_rate", "avg_ms", "median_ms"]
    if df.empty:
        return pd.DataFrame(columns=cols)
    g = df.groupby("module")
    out = pd.DataFrame({
        "events": g.size(),
        "errors": g["status"].apply(lambda s: int((s == "ERROR").sum())),
        "avg_ms": g["duration_ms"].mean().round(1),
        "median_ms": g["duration_ms"].median().round(1),
    })
    out["error_rate"] = (out["errors"] / out["events"]).round(4)
    return out.reset_index()[cols]


def flag_modules(summary, threshold=DEFAULT_THRESHOLD):
    """Flag modules whose error rate is strictly greater than the threshold."""
    if not 0 <= threshold <= 1:
        raise ValueError("Threshold must be between 0 and 1")
    out = summary.copy()
    out["flagged"] = out["error_rate"] > threshold
    return out


def sanitize_cell(value):
    """Stops spreadsheet formula injection: text starting with = + - @ gets a leading apostrophe."""
    s = str(value)
    return "'" + s if s and s[0] in "=+-@\t\r" else s


def incident_summary(summary, threshold, n_valid, n_rejected):
    """Builds the downloadable incident summary text (extension challenge)."""
    lines = ["INCIDENT SUMMARY (synthetic data)",
             f"Generated: {datetime.now():%Y-%m-%d %H:%M}",
             f"Valid records: {n_valid} | Rejected rows: {n_rejected} | Threshold: {threshold:.0%}", ""]
    flagged = summary[summary["flagged"]] if "flagged" in summary else summary.iloc[0:0]
    if flagged.empty:
        lines.append("No modules exceeded the threshold.")
    for _, r in flagged.iterrows():
        lines.append(f"- {sanitize_cell(r['module'])}: {r['error_rate']:.1%} errors "
                     f"({r['errors']}/{r['events']}), median {r['median_ms']} ms")
    lines += ["", "NOTE: A flag is a prompt to investigate, not proof of an attack."]
    return "\n".join(lines)