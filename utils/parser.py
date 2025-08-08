# utils/parser.py
# utils/parser.py
import re
from dateutil import parser as dtparser
from datetime import datetime
from typing import List, Dict

# Regex patterns
re_mcscript_full = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
    r'(?P<level>[IEWF])\s+'
    r'#(?P<thread>\d+)\s+'
    r'(?P<comp>\S+)\s+'
    r'(?P<msg>.*)$'
)
re_tsmc = re.compile(r'/\)(?P<date>\d{8})/(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)')
re_iso = re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)')

# McScript subpatterns
re_install_run = re.compile(r'RunScript.*ThreatPreventionInstall', re.IGNORECASE)
re_start_marker = re.compile(r'\bSTART\b', re.IGNORECASE)
re_key_imported = re.compile(r'Key imported successfully', re.IGNORECASE)
re_msgbus_connected = re.compile(r'msgbus connectvity status\s*:\s*Connected', re.IGNORECASE)
re_added_file_watcher = re.compile(r'Added file watcher', re.IGNORECASE)
re_no_of_products = re.compile(r'No of products to be installed\s+(\d+)', re.IGNORECASE)
re_version_info = re.compile(r'Got Build Version\s*:\s*([0-9A-Za-z\.\_:-]+)', re.IGNORECASE)
re_spec_success = re.compile(r'getting spec file from policy successfully', re.IGNORECASE)

# generic error patterns
re_alarm_raised = re.compile(r'Alarm\s+([0-9A-Fa-f]{3,4})\s+has\s+been\s+raised', re.IGNORECASE)
re_alarm_terminated = re.compile(r'Alarm\s+([0-9A-Fa-f]{3,4})\s+has\s+been\s+terminated', re.IGNORECASE)
re_uncontrolled_restart = re.compile(r'uncontrolled restart', re.IGNORECASE)
re_controlled_restart = re.compile(r'controlled restart', re.IGNORECASE)
re_software_err = re.compile(r'Software error\. System error\s+(\d+)', re.IGNORECASE)
re_failed_symbol = re.compile(r'Could not find symbol for dereferencing\s+(\S+)', re.IGNORECASE)
re_failed_generic = re.compile(r'Failed to|Could not|Error trace', re.IGNORECASE)

def try_parse_datetime(text: str):
    if not text:
        return None
    m = re_tsmc.search(text)
    if m:
        date = m.group("date")
        time = m.group("time")
        try:
            time_part = time.split(".")[0]
            return datetime.strptime(date + " " + time_part, "%Y%m%d %H:%M:%S")
        except Exception:
            pass
    m = re_iso.search(text)
    if m:
        try:
            return dtparser.parse(m.group("ts"))
        except Exception:
            pass
    return None

def parse_log_file(lines: List[str]) -> List[Dict]:
    entries = []
    for line in lines:
        line = line.rstrip("\n")
        # McScript structured
        m = re_mcscript_full.match(line)
        if m:
            try:
                ts = dtparser.parse(m.group("ts"))
            except Exception:
                ts = try_parse_datetime(line)
            level = m.group("level")
            thread = m.group("thread")
            comp = m.group("comp")
            msg = m.group("msg").strip()
            entries.append({
                "Timestamp": ts,
                "Level": level,
                "ThreadID": thread,
                "Component": comp,
                "Message": msg,
                "Raw": line
            })
            continue

        # Fallback for TSMC style and others
        ts = try_parse_datetime(line)
        level = None
        if "/W/" in line or " W/" in line or " W " in line:
            level = "W"
        elif "/I/" in line or " I/" in line or " I " in line:
            level = "I"
        elif "/F/" in line or " F/" in line or " F " in line:
            level = "F"
        comp_match = re.search(r'//(?P<comp>[^/]+)/', line)
        comp = comp_match.group("comp") if comp_match else None
        entries.append({
            "Timestamp": ts,
            "Level": level,
            "ThreadID": None,
            "Component": comp,
            "Message": line.strip(),
            "Raw": line
        })
    return entries

def extract_alarm_events(parsed_entries) -> List[Dict]:
    events = []
    # accept DataFrame-like or list
    if hasattr(parsed_entries, "iterrows"):
        parsed_entries = [r[1].to_dict() for r in parsed_entries.iterrows()]

    for row in parsed_entries:
        msg = (row.get("Message") or "")[:2000]
        ts = row.get("Timestamp") or try_parse_datetime(row.get("Raw", ""))

        # McScript informational events
        if re_install_run.search(msg):
            events.append({
                "Device Name": "Endpoint",
                "Alarm Name": "INSTALL_RUN",
                "Severity": "Info",
                "Status": "Started",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": msg
            })
            continue
        if re_start_marker.search(msg) and "START" in msg:
            events.append({
                "Device Name": "Endpoint",
                "Alarm Name": "SCRIPT_START",
                "Severity": "Info",
                "Status": "Started",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": msg
            })
            continue
        if re_key_imported.search(msg):
            events.append({
                "Device Name": "Endpoint",
                "Alarm Name": "KEY_IMPORTED",
                "Severity": "Info",
                "Status": "OK",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": msg
            })
            continue
        if re_msgbus_connected.search(msg):
            events.append({
                "Device Name": "Endpoint",
                "Alarm Name": "MSGBUS_CONNECTED",
                "Severity": "Info",
                "Status": "OK",
                "Raise Date": ts,


