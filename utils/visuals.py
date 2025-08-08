# utils/visuals.py
from PIL import Image, ImageDraw, ImageFont
import io
import pandas as pd
import altair as alt
import plotly.express as px
from datetime import datetime

def draw_root_cause_diagram_pil(events, title="diagram"):
    """
    Create a simple vertical flow diagram (PNG) from events list.
    events: list of dicts with Alarm Name, Severity, Status, Raise Date, Message
    Returns image bytes or PIL Image
    """
    # Create a canvas
    width, height = 1000, max(500, 120 + 80 * len(events))
    img = Image.new("RGBA", (width, height), "white")
    d = ImageDraw.Draw(img)

    # try to get a default font
    try:
        font = ImageFont.truetype("DejaVuSans.ttf", 14)
        title_font = ImageFont.truetype("DejaVuSans.ttf", 18)
    except Exception:
        font = ImageFont.load_default()
        title_font = font

    # title
    d.text((20, 10), f"Root cause flow — {title}", fill="black", font=title_font)

    # compute boxes
    start_y = 50
    box_w = width - 120
    x = 60
    for i, ev in enumerate(events):
        y = start_y + i * 70
        # color by severity
        sev = ev.get("Severity","")
        if sev and sev.lower().startswith("crit"):
            color = "#ff9999"
        elif "RESTART" in (ev.get("Alarm Name","") or ""):
            color = "#ffcc99"
        else:
            color = "#ffff99"
        # draw rectangle
        d.rounded_rectangle([x, y, x+box_w, y+50], radius=10, fill=color, outline="black")
        # text inside
        name = f"{ev.get('Alarm Name','')}"
        dt = ev.get("Raise Date")
        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S") if isinstance(dt, datetime) else str(dt)
        msg = ev.get("Message","")
        text = f"{name}  |  {ev.get('Status','')}  |  {dt_str}\n{msg[:200]}"
        d.text((x+12, y+8), text, fill="black", font=font)

        # draw arrow to next
        if i < len(events)-1:
            arrow_y = y+60
            d.line([(x+box_w/2, y+50), (x+box_w/2, y+60)], fill="black", width=2)
            d.polygon([(x+box_w/2-6, y+60-10),(x+box_w/2+6, y+60-10),(x+box_w/2, y+60)], fill="black")

    # return PIL Image
    return img

def plot_timeline_altair(events_df):
    """
    events_df columns: Raise Date, Alarm Name, Severity, Device Name
    returns an Altair chart object
    """
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
    fig = px.bar(counts, x="date", y="count", color="Alarm Name", title="Alarm counts per day", labels={"date":"Date","count":"Count"})
    return fig

