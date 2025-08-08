# app.py
import streamlit as st
import pandas as pd
import os
from pathlib import Path
from datetime import datetime, timedelta
from utils.parser import parse_log_file, extract_alarm_events
from utils.visuals import draw_root_cause_diagram_pil, plot_timeline_altair, plot_alarm_counts

st.set_page_config(layout="wide", page_title="TSMC Log Analyzer")

BASE_DIR = Path(__file__).parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

st.title("TSMC / Endpoint Log Analyzer")
st.markdown("Upload log files or select existing files from the `logs/` folder. The app will parse alarms, errors, restarts and produce tables and diagrams.")

# --- Sidebar: file selection / upload ---
st.sidebar.header("Load logs")

uploaded = st.sidebar.file_uploader("Upload one or more log files (txt / log)", accept_multiple_files=True, type=["txt","log"])
if uploaded:
    for up in uploaded:
        save_path = LOGS_DIR / up.name
        with open(save_path, "wb") as f:
            f.write(up.getbuffer())
    st.sidebar.success(f"Saved {len(uploaded)} file(s) to `logs/`")

# allow browsing existing log files
all_logs = sorted([p for p in LOGS_DIR.iterdir() if p.is_file()])
selected_files = st.sidebar.multiselect("Select log files from logs/", options=[p.name for p in all_logs])

if not selected_files and not uploaded:
    st.info("No files selected. Upload files or choose from the logs/ folder in the sidebar to start.")
    st.stop()

# --- Parse selected files ---
dfs = []
events_list = []
file_summaries = {}

for fname in selected_files:
    path = LOGS_DIR / fname
    raw_lines = path.read_text(errors="ignore").splitlines()
    parsed = parse_log_file(raw_lines)
    # parsed is a list of dicts for all log lines (timestamp, level, component, message)
    df = pd.DataFrame(parsed)
    df["source_file"] = fname
    dfs.append(df)

    # extract higher-level alarm events (alarm codes, restart, internal errors)
    events = extract_alarm_events(df)
    events_list.extend(events)
    file_summaries[fname] = {
        "lines": len(raw_lines),
        "events": len(events)
    }

if not events_list:
    st.warning("No alarm/error events detected in the selected files. But logs were parsed into raw events.")

events_df = pd.DataFrame(events_list)
events_df["Raise Date"] = pd.to_datetime(events_df["Raise Date"], errors="coerce")
events_df["Terminated Date"] = pd.to_datetime(events_df["Terminated Date"], errors="coerce")

# --- Filtering controls ---
st.sidebar.header("Filters")
min_dt = events_df["Raise Date"].min() if len(events_df) else None
max_dt = events_df["Raise Date"].max() if len(events_df) else None
if min_dt is None:
    min_dt = datetime.now() - timedelta(days=1)
if max_dt is None:
    max_dt = datetime.now()

date_range = st.sidebar.date_input("Date range (Raise Date)", [min_dt.date(), max_dt.date()])
start_time = st.sidebar.time_input("Start time", value=min_dt.time() if min_dt else datetime.min.time())
end_time = st.sidebar.time_input("End time", value=max_dt.time() if max_dt else datetime.max.time())

start_dt = datetime.combine(date_range[0], start_time)
end_dt = datetime.combine(date_range[1], end_time)

levels = st.sidebar.multiselect("Severity / Level", options=sorted(events_df["Severity"].unique()) if not events_df.empty else [], default=sorted(events_df["Severity"].unique()) if not events_df.empty else [])
alarm_name_filter = st.sidebar.text_input("Alarm name/code filter (partial)", "")
text_search = st.sidebar.text_input("Full-text search in message", "")

# Apply filters
df_filtered = events_df.copy()
df_filtered = df_filtered[(df_filtered["Raise Date"] >= pd.to_datetime(start_dt)) & (df_filtered["Raise Date"] <= pd.to_datetime(end_dt))]
if levels:
    df_filtered = df_filtered[df_filtered["Severity"].isin(levels)]
if alarm_name_filter:
    df_filtered = df_filtered[df_filtered["Alarm Name"].str.contains(alarm_name_filter, case=False, na=False)]
if text_search:
    df_filtered = df_filtered[df_filtered["Message"].str.contains(text_search, case=False, na=False)]

# --- Main layout ---
st.header("Summary of parsed files")
cols = st.columns(len(file_summaries) or 1)
for i, (fname, summary) in enumerate(file_summaries.items()):
    cols[i % len(cols)].metric(fname, f"{summary['events']} events\n{summary['lines']} lines")

st.markdown("### Event Details")
st.write("You can download the filtered table as Excel.")

def to_xlsx_bytes(df):
    import io
    b = io.BytesIO()
    df.to_excel(b, index=False)
    return b.getvalue()

if not df_filtered.empty:
    st.dataframe(df_filtered[["Device Name","Alarm Name","Severity","Status","Raise Date","Terminated Date","Message","source_file"]].sort_values("Raise Date"), height=350)
    st.download_button("Download filtered events (Excel)", data=to_xlsx_bytes(df_filtered), file_name="events_filtered.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
else:
    st.info("No events match the current filters.")

# --- Graphical representations ---
st.markdown("### Graphical representation")

if not df_filtered.empty:
    # timeline chart
    st.subheader("Alarm timeline")
    st.altair_chart(plot_timeline_altair(df_filtered), use_container_width=True)

    # counts
    st.subheader("Alarm counts")
    st.plotly_chart(plot_alarm_counts(df_filtered), use_container_width=True)
else:
    st.info("No chart to show with current filters.")

# --- Root cause diagram generation per-file -->
st.markdown("### Root cause / Flow diagrams")
selected_for_diagram = st.multiselect("Choose a file to generate diagram for", options=selected_files)
for fname in selected_for_diagram:
    path = LOGS_DIR / fname
    raw_lines = path.read_text(errors="ignore").splitlines()
    parsed = parse_log_file(raw_lines)
    df_file = pd.DataFrame(parsed)
    events_file = extract_alarm_events(df_file)
    if not events_file:
        st.write(f"No notable events in `{fname}` to create diagram.")
        continue
    # draw
    img = draw_root_cause_diagram_pil(events_file, title=fname)
    st.image(img, caption=f"Root cause diagram for {fname}")

st.markdown("---")
st.write("App created by: automated analyzer. To push to GitHub, see README.md in the repo.")
