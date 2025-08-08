# utils/parser.py
import re
from dateutil import parser as dtparser
from datetime import datetime
from typing import List, Dict

# Regular expressions
# 1) McScript lines like:
# 2025-07-31 22:37:42    I    #4552    ScrptMain    START [C:\Program Files\McAfee\Agent\...]
re_mcscript_full = re.compile(
    r'^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+'
    r'(?P<level>[IEWF])\s+'
    r'#(?P<thread>\d+)\s+'
    r'(?P<comp>\S+)\s+'
    r'(?P<msg>.*)$'
)

# 2) TSMC style embedded date/time: ':/20250731/22:40:11.103000/...'
re_tsmc = re.compile(r'/\)(?P<date>\d{8})/(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)')

# 3) ISO timestamp fallback like '2025-07-31 22:40:11.103000'
re_iso = re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)')

# McScript subpatterns for useful info
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
    """Attempt to parse multiple timestamp formats used in logs."""
    if not text:
        return None
    # TSMC style
    m = re_tsmc.search(text)
    if m:
        date = m.group("date")
        time = m.group("time")
        try:
            # drop microseconds if present for stable parsing
            time_part = time.split(".")[0]
            return datetime.strptime(date + " " + time_part, "%Y%m%d %H:%M:%S")
        except Exception:
            pass
    # direct ISO
    m = re_iso.search(text)
    if m:
        try:
            return dtparser.parse(m.group("ts"))
        except Exception:
            pass
    # no timestamp found
    return None

def parse_log_file(lines: List[str]) -> List[Dict]:
    """
    Parse log lines into structured dicts:
    { Timestamp, Level, ThreadID, Component, Message, Raw }
    """
    entries = []
    for line in lines:
        line = line.rstrip("\n")
        # Try McScript full pattern first (most structured)
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

        # Fallback to TSMC/legacy parsing heuristics
        ts = try_parse_datetime(line)
        # determine Level heuristically
        level = None
        if "/W/" in line or " W/" in line or " W " in line:
            level = "W"
        elif "/I/" in line or " I/" in line or " I " in line:
            level = "I"
        elif "/F/" in line or " F/" in line or " F " in line:
            level = "F"
        # component extraction for tsmc lines (//component/)
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

def extract_alarm_events(parsed_entries: List[Dict]) -> List[Dict]:
    """
    Convert parsed lines into consolidated event records:
    Device Name, Alarm Name, Severity, Status, Raise Date, Terminated Date, Message
    """
    events = []
    # If input is a DataFrame, coerce to list of dicts
    if hasattr(parsed_entries, "iterrows"):
        parsed_entries = [r[1].to_dict() for r in parsed_entries.iterrows()]

    for row in parsed_entries:
        msg = (row.get("Message") or "")[:2000]  # avoid extremely long messages
        ts = row.get("Timestamp") or try_parse_datetime(row.get("Raw", ""))

        # McScript useful info -> produce informational events (Endpoint device)
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
                "Terminated Date": ts,
                "Message": msg
            })
            continue
        if re_added_file_watcher.search(msg):
            events.append({
                "Device Name": "Endpoint",
                "Alarm Name": "FILE_WATCHER_ADDED",
                "Severity": "Info",
                "Status": "OK",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": msg
            })
            continue
        mprod = re_no_of_products.search(msg)
        if mprod:
            events.append({
                "Device Name": "Endpoint",
                "Alarm Name": "PRODUCT_COUNT",
                "Severity": "Info",
                "Status": "Info",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": f"No of products to be installed: {mprod.group(1)}"
            })
            continue
        mver = re_version_info.search(msg)
        if mver:
            events.append({
                "Device Name": "Endpoint",
                "Alarm Name": "BUILD_VERSION",
                "Severity": "Info",
                "Status": "Info",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": f"Build Version: {mver.group(1)}"
            })
            continue
        if re_spec_success.search(msg):
            events.append({
                "Device Name": "Endpoint",
                "Alarm Name": "SPECFILE_OK",
                "Severity": "Info",
                "Status": "Info",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": msg
            })
            continue

        # TSMC style alarms
        m = re_alarm_raised.search(msg)
        if m:
            events.append({
                "Device Name": "TSMC",
                "Alarm Name": m.group(1),
                "Severity": "Unknown",
                "Status": "Raised",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": msg
            })
            continue

        m2 = re_alarm_terminated.search(msg)
        if m2:
            events.append({
                "Device Name": "TSMC",
                "Alarm Name": m2.group(1),
                "Severity": "Unknown",
                "Status": "Terminated",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": msg
            })
            continue

        if re_uncontrolled_restart.search(msg):
            events.append({
                "Device Name": "TSMC",
                "Alarm Name": "UNCONTROLLED_RESTART",
                "Severity": "Critical",
                "Status": "Occurred",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": msg
            })
            continue

        if re_controlled_restart.search(msg):
            events.append({
                "Device Name": "TSMC",
                "Alarm Name": "CONTROLLED_RESTART",
                "Severity": "Info",
                "Status": "Occurred",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": msg
            })
            continue

        m3 = re_software_err.search(msg)
        if m3:
            code = m3.group(1)
            events.append({
                "Device Name": "TSMC",
                "Alarm Name": f"SYS_ERR_{code}",
                "Severity": "Critical" if code != "0" else "Warning",
                "Status": "Occurred",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": msg
            })
            continue

        m_sym = re_failed_symbol.search(msg)
        if m_sym:
            symbol = m_sym.group(1)
            events.append({
                "Device Name": "Endpoint",
                "Alarm Name": f"INSTALL_FAIL_{symbol}",
                "Severity": "Critical",
                "Status": "Failed",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": msg
            })
            continue

        if re_failed_generic.search(msg):
            events.append({
                "Device Name": "TSMC" if "TSMC" in (row.get("Raw","") or "") else "Endpoint",
                "Alarm Name": "FAILED_ACTION",
                "Severity": "Warning",
                "Status": "Occurred",
                "Raise Date": ts,
                "Terminated Date": ts,
                "Message": msg
            })
            continue

    return events

