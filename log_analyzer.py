import argparse
import csv
import json
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from statistics import mean

SYSLOG_REGEX = re.compile(
    r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>\S+)\[(?P<pid>\d+)\]:\s+\((?P<severity>[A-Z]+)\)\s+(?P<message>.*)$"
)
SSH_REGEX = re.compile(
    r"(Failed|Accepted)\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
GENERIC_IP_REGEX = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")

def parse_syslog_timestamp(value):
    dt = datetime.strptime(value.strip(), "%b %d %H:%M:%S")
    return dt.replace(year=datetime.now().year)

def infer_format(path, override):
    if override:
        return override
    suffix = path.suffix.lower()
    if suffix == ".json":
        return "json"
    if suffix == ".csv":
        return "csv"
    return "syslog"

def extract_ip_user(message):
    ssh_match = SSH_REGEX.search(message)
    if ssh_match:
        return ssh_match.group("ip"), ssh_match.group("user")
    ip_match = GENERIC_IP_REGEX.search(message)
    ip = ip_match.group(1) if ip_match else None
    return ip, None

def categorize_message(message, severity):
    if "Failed password" in message or "authentication error" in message:
        return "auth_fail"
    if "Accepted password" in message or "session opened" in message:
        return "auth_success"
    if "openvpn" in message.lower():
        return "vpn_login"
    if "security update" in message.lower():
        return "maintenance"
    return severity.lower()

def load_syslog(path):
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            match = SYSLOG_REGEX.match(line)
            if not match:
                continue
            ts = parse_syslog_timestamp(match.group("ts"))
            message = match.group("message")
            ip, user = extract_ip_user(message)
            yield {
                "timestamp": ts,
                "host": match.group("host"),
                "process": match.group("proc"),
                "pid": int(match.group("pid")),
                "severity": match.group("severity"),
                "message": message,
                "ip": ip,
                "user": user,
                "category": categorize_message(message, match.group("severity")),
            }

def normalize_record(record):
    data = dict(record)
    raw_ts = data.get("timestamp")
    if raw_ts is None:
        return None
    if isinstance(raw_ts, datetime):
        ts = raw_ts
    else:
        try:
            ts = datetime.fromisoformat(str(raw_ts))
        except ValueError:
            return None
    data["timestamp"] = ts
    for key in ("pid",):
        if key in data and data[key] not in (None, "", "None"):
            try:
                data[key] = int(data[key])
            except ValueError:
                data[key] = None
    for key in ("ip", "user"):
        if key in data and (data[key] in ("", "None")):
            data[key] = None
    data.setdefault("severity", "INFO")
    data.setdefault("category", categorize_message(data.get("message", ""), data["severity"]))
    return data

def load_json(path):
    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    for entry in payload:
        normalized = normalize_record(entry)
        if normalized:
            yield normalized

def load_csv(path):
    with path.open("r", newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            normalized = normalize_record(row)
            if normalized:
                yield normalized

def load_events(path, fmt):
    if fmt == "json":
        yield from load_json(path)
    elif fmt == "csv":
        yield from load_csv(path)
    else:
        yield from load_syslog(path)

def analyze_events(events, fail_threshold, window_minutes, distinct_users, spike_multiplier):
    ip_attempts = defaultdict(deque)
    ip_users = defaultdict(set)
    per_minute = Counter()
    ip_counter = Counter()
    user_counter = Counter()
    severity_counter = Counter()
    alerts = []
    first_ts = None
    last_ts = None
    total_events = 0

    for event in events:
        ts = event["timestamp"]
        total_events += 1
        first_ts = ts if first_ts is None or ts < first_ts else first_ts
        last_ts = ts if last_ts is None or ts > last_ts else last_ts
        severity = event.get("severity") or "UNKNOWN"
        severity_counter[severity] += 1
        ip = event.get("ip")
        user = event.get("user")
        category = event.get("category") or ""
        message = event.get("message", "")
        minute_bucket = ts.replace(second=0, microsecond=0)
        per_minute[minute_bucket] += 1

        if ip:
            ip_counter[ip] += 1
            if user:
                user_counter[user] += 1

            if category in {"auth_fail", "sudo_fail"} or "Failed password" in message:
                window_start = ts - timedelta(minutes=window_minutes)
                q = ip_attempts[ip]
                q.append(ts)
                while q and q[0] < window_start:
                    q.popleft()
                if len(q) >= fail_threshold:
                    alerts.append({
                        "type": "brute_force",
                        "ip": ip,
                        "attempts": len(q),
                        "window_minutes": window_minutes,
                        "last_seen": ts.isoformat(),
                        "sample_message": message,
                    })
                    q.clear()

            if user:
                users = ip_users[ip]
                users.add(user)
                if len(users) >= distinct_users:
                    alerts.append({
                        "type": "multi_user",
                        "ip": ip,
                        "usernames": sorted(users),
                        "last_seen": ts.isoformat(),
                        "count": len(users),
                    })
                    ip_users[ip].clear()

            if category == "auth_success" and len(ip_attempts[ip]) >= max(1, fail_threshold - 1):
                alerts.append({
                    "type": "suspicious_success",
                    "ip": ip,
                    "recent_failures": len(ip_attempts[ip]),
                    "last_seen": ts.isoformat(),
                    "message": message,
                })
                ip_attempts[ip].clear()

    if per_minute:
        avg = mean(per_minute.values())
        for minute, count in per_minute.items():
            if avg > 0 and count >= avg * spike_multiplier and count >= fail_threshold:
                alerts.append({
                    "type": "volume_spike",
                    "minute": minute.isoformat(),
                    "count": count,
                    "baseline_avg": round(avg, 2),
                    "multiplier": spike_multiplier,
                })

    summary = {
        "events_total": total_events,
        "analysis_window": {
            "start": first_ts.isoformat() if first_ts else None,
            "end": last_ts.isoformat() if last_ts else None,
        },
        "top_ips": [{"ip": ip, "count": cnt} for ip, cnt in ip_counter.most_common(10)],
        "top_users": [{"user": usr, "count": cnt} for usr, cnt in user_counter.most_common(10)],
        "severity_counts": severity_counter,
        "per_minute_samples": [
            {"minute": minute.isoformat(), "count": count} for minute, count in sorted(per_minute.items())
        ],
        "alert_count": len(alerts),
    }
    return alerts, summary

def save_reports(alerts, summary, prefix):
    prefix = Path(prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    alerts_json = prefix.with_suffix(".json")
    alerts_csv = prefix.with_suffix(".csv")
    summary_json = prefix.with_suffix(".summary.json")

    alerts_json.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    summary_json.write_text(json.dumps(summary, default=str, indent=2), encoding="utf-8")

    if alerts:
        keys = sorted({key for alert in alerts for key in alert.keys()})
        with alerts_csv.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=keys)
            writer.writeheader()
            writer.writerows(alerts)
    else:
        alerts_csv.write_text("", encoding="utf-8")

    return alerts_json, alerts_csv, summary_json

def main():
    parser = argparse.ArgumentParser(description="Analyze synthetic auth logs for anomalies.")
    parser.add_argument("--log", type=Path, default=Path("samples/generated_auth.log"), help="Path to the log to inspect.")
    parser.add_argument("--format", choices=["syslog", "json", "csv"], help="Force input format (auto by default).")
    parser.add_argument("--fail-threshold", type=int, default=5, help="Failures per window before brute force alert.")
    parser.add_argument("--window-minutes", type=int, default=5, help="Sliding window for failure detection.")
    parser.add_argument("--distinct-users", type=int, default=3, help="Unique users per IP before multi-user alert.")
    parser.add_argument("--spike-multiplier", type=float, default=2.5, help="Per-minute spike factor over average.")
    parser.add_argument("--output-prefix", type=Path, default=Path("outputs/alerts"), help="Prefix for report files.")
    args = parser.parse_args()

    fmt = infer_format(args.log, args.format)
    events = list(load_events(args.log, fmt))
    alerts, summary = analyze_events(events, args.fail_threshold, args.window_minutes, args.distinct_users, args.spike_multiplier)
    alerts_json, alerts_csv, summary_json = save_reports(alerts, summary, args.output_prefix)

    print(f"Analyzed {summary['events_total']} events, found {summary['alert_count']} alerts.")
    print(f"Alerts JSON: {alerts_json}")
    print(f"Alerts CSV: {alerts_csv}")
    print(f"Summary JSON: {summary_json}")

if __name__ == "__main__":
    main()