# utils/visuals.py
# utils/visuals.py
from PIL import Image, ImageDraw, ImageFont
import io
import pandas as pd
import altair as alt
from datetime import datetime

# Try to import plotly; fallback handled in functions
try:
    import plotly.express as px
    _HAS_PLOTLY = True
except Exception:
    _HAS_PLOTLY = False

def draw_root_cause_diagram_pil(events, title="diagram"):
    width, height = 1000, max(400, 120 + 80 * len(events))
    img = Image.new("RGBA", (width, height), "white")
    d = ImageDraw.Draw(img)
    try:
        title_font = ImageFont.truetype("DejaVuSans.ttf", 18)
        font = ImageFont.truetype("DejaVuSans.ttf", 14)
    except Exception:
        title_font = ImageFont.load_default()
        font = ImageFont.load_default()
    d.text((20, 10), f"Root cause flow — {title}", fill="black", font=title_font)

    start_y = 50
    box_w = width - 120
    x = 60
    for i, ev in enumerate(events):
        y = start_y + i * 70
        sev = (ev.get("Severity") or "").lower()
        if "crit" in sev or "critical" in sev:
            color = "#ff9999"
        elif "RESTART" in (ev.get("Alarm Name","") or ""):
            color = "#ffcc99"
        else:
            color = "#ffff99"
        d.rounded_rectangle([x, y, x+box_w, y+50], radius=10, fill=color, outline="black")
        name = f"{ev.get('Alarm Name','')}"
        dt = ev.get("Raise Date")
        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S") if isinstance(dt, datetime) else str(dt)
        msg = ev.get("Message","")
        text = f"{name}  |  {ev.get('Status','')}  |  {dt_str}\n{msg[:180]}"
        d.text((x+12, y+8), text, fill="black", font=font)
        if i < len(events)-1:
            d.line([(x+box_w/2, y+50), (x+box_w/2, y+60)], fill="black", width=2)
            d.polygon([(x+box_w/2-6, y+60-10),(x+box_w/2+6, y+60-10),(x+box_w/2, y+60)], fill="black")
    return img

def plot_timeline_altair(events_df):
    df = events_df.copy()
    df = df.dropna(subset=["Raise Date"])
    df["Raise Date"] = pd.to_datetime(df["Raise Date"])
    chart = alt.Chart(df).mark_circle(size=80).encode(
        x=alt.X("Raise Date:T", title="Raise Date"),
        y=alt.Y("Alarm Name:N", title="Alarm"),
        color=alt.Color("Severity:N", legend=alt.Legend(title="Severity")),
        tooltip=["Alarm Name", "Severity", "Device Name", "Raise Date", "Message"]
    ).interactive()
    return chart

def plot_alarm_counts(events_df):
    df = events_df.copy()
    df = df.dropna(subset=["Raise Date"])
    df["Raise Date"] = pd.to_datetime(df["Raise Date"])
    df["date"] = df["Raise Date"].dt.floor("1D")
    counts = df.groupby(["date","Alarm Name"]).size().reset_index(name="count")
    if _HAS_PLOTLY:
        fig = px.bar(counts, x="date", y="count", color="Alarm Name", title="Alarm counts per day", labels={"date":"Date","count":"Count"})
        return fig
    else:
        # Build an altair bar chart grouped by Alarm Name (fallback)
        chart = alt.Chart(counts).mark_bar().encode(
            x=alt.X("date:T", title="Date"),
            y=alt.Y("count:Q", title="Count"),
            color=alt.Color("Alarm Name:N", title="Alarm Name"),
            tooltip=["date","Alarm Name","count"]
        ).properties(title="Alarm counts per day")
        return chart


