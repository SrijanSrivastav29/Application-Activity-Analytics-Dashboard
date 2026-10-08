"""Application Activity Analytics Dashboard (Streamlit)."""
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import audit, log_analyzer as la

ROOT = Path(__file__).resolve().parent.parent
DB = Path(__file__).resolve().parents[2] / "database" / "audit.db"
DEFAULT_LOG = ROOT / "data" / "activity_logs.csv"

st.set_page_config(page_title="Activity Analytics", layout="wide")
st.title("Application Activity Analytics Dashboard")
st.caption("Synthetic data only. Flags are indicators, not proof of an attack.")

# ---- Load data: uploaded file if given, otherwise the default synthetic file ----
up = st.sidebar.file_uploader("Upload synthetic CSV log (max 2 MB)", type=["csv"])
try:
    df, rejected = la.parse_log_bytes(up.getvalue()) if up else la.parse_log_file(DEFAULT_LOG)
except (ValueError, FileNotFoundError) as e:
    st.error(f"Could not load log: {e}")
    st.stop()

if df.empty:
    st.warning("No valid records to display.")
    st.stop()

# ---- Sidebar filters ----
mods = sorted(df["module"].unique())
sel = st.sidebar.multiselect("Modules", mods, default=mods)
status = st.sidebar.selectbox("Status", ["ALL", "SUCCESS", "ERROR"])
d0, d1 = df["timestamp"].min().date(), df["timestamp"].max().date()
dates = st.sidebar.date_input("Date range", (d0, d1), min_value=d0, max_value=d1)
threshold = st.sidebar.slider("Error-rate threshold", 0.01, 0.50, la.DEFAULT_THRESHOLD, 0.01)
if len(dates) != 2:
    st.info("Select both start and end dates.")
    st.stop()

# ---- Apply filters ----
f = df[df["module"].isin(sel) & df["timestamp"].dt.date.between(*dates)]
if status != "ALL":
    f = f[f["status"] == status]

# ---- Audit: record that a filter was applied (no sensitive data stored) ----
audit.record_filter(DB, sel, status, dates[0], dates[1], threshold, len(f))

# ---- Metrics ----
summary = la.flag_modules(la.summarize(f), threshold)
c1, c2, c3 = st.columns(3)
c1.metric("Valid records shown", len(f))
c2.metric("Rejected rows", len(rejected))
c3.metric("Modules flagged", int(summary["flagged"].sum()) if not summary.empty else 0)

st.subheader("Per-module summary")
st.dataframe(summary)
if rejected:
    with st.expander(f"Rejected rows ({len(rejected)})"):
        st.dataframe(pd.DataFrame(rejected))

# ---- Charts ----
if not summary.empty:
    a, b = st.columns(2)
    fig1, ax1 = plt.subplots()
    ax1.bar(summary["module"], summary["error_rate"] * 100,
            color=["tab:red" if x else "tab:blue" for x in summary["flagged"]])
    ax1.axhline(threshold * 100, ls="--", color="gray")
    ax1.set_ylabel("Error rate (%)")
    ax1.set_title("Error rate by module")
    a.pyplot(fig1)

    fig2, ax2 = plt.subplots()
    ax2.bar(summary["module"], summary["median_ms"])
    ax2.set_ylabel("Median duration (ms)")
    ax2.set_title("Median duration by module")
    b.pyplot(fig2)

    st.subheader("Events per day")
    st.line_chart(f.groupby(f["timestamp"].dt.date).size())

st.subheader("Filtered records")
st.dataframe(f.head(500))

# ---- Extension: downloadable incident summary ----
st.subheader("Incident summary (extension)")
txt = la.incident_summary(summary, threshold, len(f), len(rejected))
st.text(txt)
st.download_button("Download incident summary", txt, "incident_summary.txt")

with st.expander("Audit trail of filter use (last 10)"):
    st.dataframe(pd.DataFrame(audit.recent(DB, 10),
                 columns=["time", "modules", "status", "from", "to", "threshold", "rows"]))

with st.expander("Limitations"):
    st.markdown(
        "- The 15% threshold is a fixed rule tuned to synthetic data (baseline ~5%, ~3x margin); real systems need their own baseline.\n"
        "- A high error rate can come from deployments, outages or bad input, not only attacks; a normal rate can hide a real attack.\n"
        "- Small samples give unstable rates. Rules cannot see patterns across modules or over time.")