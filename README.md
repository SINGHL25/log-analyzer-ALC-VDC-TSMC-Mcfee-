# log-analyzer-ALC-VDC-TSMC-Mcfee-

# TSMC/MCFEE Log Analyzer (Streamlit)

Small Streamlit app to parse TSMC and endpoint logs, extract alarms/errors, show tables, filters and diagrams.

It includes:

robust parsing of your provided logs,

event extraction (alarms, restarts, McScript install errors and info),

filters (date/time range, severity/alarm name, full-text),

table view with Excel download,

timeline and counts visualization (Altair + Plotly fallback),

generated root-cause flow diagram (PIL) per-file,

safe error handling for missing columns / missing dates.
