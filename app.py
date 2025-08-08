# app.py
# app.py
import streamlit as st
from pathlib import Path
import pandas as pd
from datetime import datetime, timedelta, time as dtime
from utils.parser import parse_log_file, extract_alarm_events
from utils.visuals import draw_root_cause_diagram_pil, plot_timeline_altair, plot_alarm_counts
import io

st.set_page_config(layout="wide", page_title="TSMC Log Analyzer")
BASE_DIR = Path(__file__).parent
LOGS_DIR = BASE_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

st.title("TSMC / Endpoint Log Analyzer")
st.markdown("Upload logs or select files from `logs/`. Supports TSMC and McScript formats (from this session).")

# Sidebar - upload & select
st.sidebar.header("Load logs")
uploaded = st.sidebar.file_uploader("Upload log file(s)", accept_multiple_files=True, type=["txt","log"])
if uploaded:
    for f in uploaded:
        out = LOGS_DIR / f.name
        with open(out, "wb") as fh:
            fh.write(f.getbuffer())
    st.sidebar.success(f"Saved {len(uploaded)} file(s) to logs/")

all_logs = sorted([p for p in LOGS_DIR.iterdir() if p.is_file()])
choices = [p.name for p in all_logs]
selected_files = st.sidebar.multiselect("Select files (logs/)", options=choices, default=choices[:1] if choices else [])

if not selected_files:
    st.info("No files selected. Upload or choose logs to begin.")
    st.stop()

# Parse files
raw_dfs = []
events = []
file_summaries = {}
for fname in selected_files:
    path = LOGS_DIR / fname
    try:
        text = path.read_text(errors="ignore")
    except Exception as e:
        st.error(f"Failed to read {fname}: {e}")
        continue
    lines = text.splitlines()
    parsed = parse_log_file(lines)  # list of dicts
    df_parsed = pd.DataFrame(parsed)
    df_parsed["source_file"] = fname
    raw_dfs.append(df_parsed)

    # Extract events (list of dicts)
    evts = extract_alarm_events(df_parsed)
    file_summaries[fname] = {"lines": len(lines), "events": len(evts)}
    for e in evts:
        e["source_file"] = fname
    events.extend(evts)

# Events DataFrame (may be empty)
events_df = pd.DataFrame(events)
# Normalize columns
required_cols = ["Device Name","Alarm Name","Severity","Status","Raise Date","Terminated Date","Message","source_file"]
for col in required_cols:
    if col not in events_df.columns:
        events_df[col] = pd.NA

# Convert Raise Date/Terminated Date to datetimes
events_df["Raise Date"] = pd.to_datetime(events_df["Raise Date"], errors="coerce")
events_df["Terminated Date"] = pd.to_datetime(events_df["Terminated Date"], errors="coerce")

# Sidebar filters
st.sidebar.header("Filters")
if not events_df.empty and events_df["Raise Date"].notna().any():
    min_dt = events_df["Raise Date"].min()
    max_dt = events_df["Raise Date"].max()
else:
    # default to last 7 days to avoid NaT errors
    max_dt = pd.Timestamp.now()
    min_dt = max_dt - pd.Timedelta(days=7)

# date picker requires date objects
try:
    date_range = st.sidebar.date_input("Date range (Raise Date)", [min_dt.date(), max_dt.date()])
except Exception:
    # fallback to safe values
    date_range = [min_dt.date(), max_dt.date()]

# time inputs
start_time = st.sidebar.time_input("Start time", value=dtime(0,0))
end_time = st.sidebar.time_input("End time", value=dtime(23,59,59))

start_dt = datetime.combine(date_range[0], start_time)
end_dt = datetime.combine(date_range[1], end_time)

severities = sorted(events_df["Severity"].dropna().unique()) if not events_df.empty else []
selected_sev = st.sidebar.multiselect("Severity", options=severities, default=severities)
alarm_name_filter = st.sidebar.text_input("Alarm name/code filter (partial)", "")
text_search = st.sidebar.text_input("Full-text search", "")

# Apply filters safely
df_filtered = events_df.copy()
if not df_filtered.empty:
    # filter by datetime if Raise Date exists
    if df_filtered["Raise Date"].notna().any():
        df_filtered = df_filtered[(df_filtered["Raise Date"] >= pd.to_datetime(start_dt)) & (df_filtered["Raise Date"] <= pd.to_datetime(end_dt))]
    if selected_sev:
        df_filtered = df_filtered[df_filtered["Severity"].isin(selected_sev)]
    if alarm_name_filter:
        df_filtered = df_filtered[df_filtered["Alarm Name"].astype(str).str.contains(alarm_name_filter, case=False, na=False)]
    if text_search:
        df_filtered = df_filtered[df_filtered["Message"].astype(str).str.contains(text_search, case=False, na=False)]

# UI - file summary
st.header("Summary of parsed files")
cols = st.columns(len(file_summaries) or 1)
i = 0
for fname, s in file_summaries.items():
    cols[i % len(cols)].metric(fname, f"{s['events']} events\n{s['lines']} lines")
    i += 1

# Event table & download
st.markdown("### Event Details")
if df_filtered.empty:
    st.info("No events match filters or no events found in selected files.")
else:
    # Ensure required columns exist before selecting
    for col in required_cols:
        if col not in df_filtered.columns:
            df_filtered[col] = pd.NA

    display_df = df_filtered[required_cols].sort_values("Raise Date").reset_index(drop=True)
    st.dataframe(display_df, height=350)

    # Excel download
    buf = io.BytesIO()
    display_df.to_excel(buf, index=False)
    buf.seek(0)
    st.download_button("Download filtered events (Excel)", data=buf, file_name="events_filtered.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

# Graphs
st.markdown("### Graphical representation")
if not df_filtered.empty:
    st.subheader("Alarm timeline")
    try:
        chart = plot_timeline_altair(df_filtered)
        st.altair_chart(chart, use_container_width=True)
    except Exception as e:
        st.error(f"Failed to render timeline: {e}")

    st.subheader("Alarm counts")
    try:
        fig_counts = plot_alarm_counts(df_filtered)
        # plotly or altair returned
        if hasattr(fig_counts, "to_html") or hasattr(fig_counts, "data"):
            st.plotly_chart(fig_counts, use_container_width=True)
        else:
            st.altair_chart(fig_counts, use_container_width=True)
    except Exception as e:
        st.error(f"Failed to render counts: {e}")
else:
    st.info("No charts to show for current filters.")

# Root cause diagrams per-file
st.markdown("### Root cause / Flow diagrams (per-file)")
chosen = st.multiselect("Choose file(s) to generate diagram for", options=selected_files)
for fname in chosen:
    # gather events for that file
    ev_for_file = [e for e in events if e.get("source_file") == fname]
    if not ev_for_file:
        st.write(f"No notable events in `{fname}` to create diagram.")
        continue
    img = draw_root_cause_diagram_pil(ev_for_file, title=fname)
    st.image(img, caption=f"Root cause diagram — {fname}")

st.write("App built for the log formats seen in this session. Parser and visual heuristics can be extended if you have other formats.")

