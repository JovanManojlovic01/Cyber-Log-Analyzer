import re
import json
from collections import defaultdict, deque
from datetime import datetime, timedelta
from dateutil import parser as dateparser
import os

# Config
LOG_FILE = "samples/generated_auth.log"
OUTPUT_PREFIX = "outputs/alerts"

# Config - Thresholds
FAIL_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5
MULTI_USER_THRESHOLD = 3

# REGEX PATTERNS
AUTH_FAIL_REGEX = re.compile(
    r'^(?P<ts>[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+\S+:\s+(?P<message>.*)$'
)
SSH_FAIL_REGEX = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})'
)
GENERIC_TS_REGEX = re.compile(
    r'(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
)

# Helper Functions
# Parse syslog timestamp
def parse_syslog_timestamp(ts_str, year_hint=None):
    try:
        dt = datetime.strptime(ts_str.strip(), '%b %d %H:%M:%S')
    except ValueError:
        dt = datetime.strptime(' '.join(ts_str.split()), '%b %d %H:%M:%S')
    year = year_hint or datetime.now().year
    return dt.replace(year=year)

# Helper - extracting timestamp, IP, username, and message from one line
def extract_event(line):
    match_auth = AUTH_FAIL_REGEX.match(line)
    if match_auth:
        ts_raw = match_auth.group('ts')
        msg = match_auth.group('message')
        try:
            ts = parse_syslog_timestamp(ts_raw)
        except Exception:
            ts = datetime.now()
        match_ssh = SSH_FAIL_REGEX.search(msg)
        if match_ssh:
            return ts, match_ssh.group('ip'), match_ssh.group('user'), msg

    match_generic = GENERIC_TS_REGEX.search(line)
    if match_generic:
        try:
            ts = dateparser.parse(match_generic.group('iso'))
        except Exception:
            ts = datetime.now()
        match_ip = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
        match_user = re.search(r'user[:= ]?(\S+)', line, re.IGNORECASE)
        ip = match_ip.group(1) if match_ip else None
        user = match_user.group(1) if match_user else None
        return ts, ip, user, line
    return None

# Analyzing log and returning the list of detected alerts
def analyze_log_file(path):
    ip_attempts = defaultdict(deque)
    ip_users = defaultdict(set)
    alerts = []
    with open(path, 'r', errors='ignore') as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line:
                continue
            event = extract_event(line)
            if not event:
                continue
            ts, ip, user, msg = event
            if ip is None:
                continue

            ip_attempts[ip].append(ts)
            if user:
                ip_users[ip].add(user)

            window_start = ts - timedelta(minutes=TIME_WINDOW_MINUTES)
            while ip_attempts[ip] and ip_attempts[ip][0] < window_start:
                ip_attempts[ip].popleft()

            if len(ip_attempts[ip]) >= FAIL_THRESHOLD:
                alerts.append({
                    "type": "brute_force",
                    "ip": ip,
                    "count": len(ip_attempts[ip]),
                    "window_minutes": TIME_WINDOW_MINUTES,
                    "last_seen": ts.isoformat(),
                    "sample_message": msg
                })
                ip_attempts[ip].clear()

            if len(ip_users[ip]) >= MULTI_USER_THRESHOLD:
                alerts.append({
                    "type": "multi_user_attempt",
                    "ip": ip,
                    "usernames": sorted(list(ip_users[ip])),
                    "count_usernames": len(ip_users[ip]),
                    "last_seen": ts.isoformat(),
                    "sample_message": msg
                })
                ip_users[ip].clear()
    return alerts

# Saving alerts in JSON and CSV formats
def save_outputs(alerts, prefix):
    os.makedirs(os.path.dirname(prefix) or '.', exist_ok = True)
    json_path = prefix + ".json"
    csv_path = prefix + ".csv"

    with open(json_path, 'w') as jf:
        json.dump(alerts, jf, indent = 2)

    if alerts:
        import csv
        keys = sorted({k for alert in alerts for k in alert.keys()})
        with open(csv_path, 'w', newline = '') as cf:
            writer = csv.DictWriter(cf, fieldnames = keys)
            writer.writeheader()
            for alert in alerts:
                writer.writerow(alert)
    return json_path, csv_path

def main():
    print(f"Reading log file: {LOG_FILE}")
    alerts = analyze_log_file(LOG_FILE)
    json_path, csv_path = save_outputs(alerts, OUTPUT_PREFIX)
    print(f"Analysis complete - {len(alerts)} alerts found.")
    print(f"JSON output: {json_path}")
    print(f"CSV output: {csv_path}")
    print("Done.")

if __name__ == "__main__":
    main()