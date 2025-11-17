import argparse
import csv
import json
import random
import uuid
from datetime import datetime, timedelta
from pathlib import Path

HOSTS = ["edge-fw", "web-01", "db-02", "vpn-01", "bastion"]
PROCESSES = ["sshd", "sudo", "systemd", "openvpn"]
USERS = ["root", "admin", "deploy", "oracle", "guest", "devops", "analyst"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "curl/8.0.1",
    "OpenSSH_8.4",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5)",
    "python-requests/2.31"
]
COUNTRIES = ["US", "DE", "SG", "BR", "ZA", "GB"]
ASNS = ["AS15169", "AS16509", "AS8075", "AS13335", "AS63949"]
EVENT_TYPES = [
    {"category": "auth_fail", "severity": "WARN", "weight": 0.45},
    {"category": "auth_success", "severity": "INFO", "weight": 0.2},
    {"category": "sudo_fail", "severity": "ERROR", "weight": 0.1},
    {"category": "sudo_success", "severity": "INFO", "weight": 0.1},
    {"category": "vpn_login", "severity": "INFO", "weight": 0.1},
    {"category": "maintenance", "severity": "INFO", "weight": 0.05},
]

def random_ip() -> str:
    return ".".join(str(random.randint(2, 254)) for _ in range(4))

def weighted_event_type():
    total = sum(t["weight"] for t in EVENT_TYPES)
    pick = random.random() * total
    for t in EVENT_TYPES:
        pick -= t["weight"]
        if pick <= 0:
            return t
    return EVENT_TYPES[-1]

def build_message(event_type, user, ip, port, geo, ua, corr_id):
    if event_type["category"] == "auth_fail":
        prefix = "Failed password for "
        invalid = "invalid user " if random.random() < 0.35 else ""
        base = f"{prefix}{invalid}{user} from {ip} port {port} ssh2"
    elif event_type["category"] == "auth_success":
        base = f"Accepted password for {user} from {ip} port {port} ssh2"
    elif event_type["category"] == "sudo_fail":
        base = f"sudo: PAM authentication error for {user} from {ip}"
    elif event_type["category"] == "sudo_success":
        base = f"sudo: session opened for user {user} by root(uid=0)"
    elif event_type["category"] == "vpn_login":
        base = f"openvpn: user {user} authenticated from {ip}"
    else:
        base = "systemd: Finished daily security update service"
    metadata = f"[geo={geo}] [asn={random.choice(ASNS)}] [ua=\"{ua}\"] [corr={corr_id}]"
    return f"{base} {metadata}".strip()

def synthesize_events(count, start_ts, window_minutes, burst_prob):
    window_seconds = max(1, int(window_minutes * 60))
    offsets = []
    cursor = 0
    step_base = max(2, window_seconds // max(count, 1))
    for _ in range(count):
        step = random.randint(0, 5) if random.random() < burst_prob else random.randint(step_base // 2, step_base * 2)
        cursor = min(window_seconds, cursor + step)
        offsets.append(cursor)
    offsets.sort()
    events = []
    for idx, offset in enumerate(offsets):
        ts = start_ts + timedelta(seconds=offset)
        event_type = weighted_event_type()
        host = random.choice(HOSTS)
        process = random.choice(PROCESSES)
        pid = random.randint(100, 9999)
        ip = random_ip() if event_type["category"] not in {"maintenance"} else None
        user_choice = random.choice(USERS)
        port = random.randint(40_000, 65_000)
        geo = random.choice(COUNTRIES)
        ua = random.choice(USER_AGENTS)
        corr_id = uuid.uuid4().hex[:10]
        message = build_message(event_type, user_choice, ip or "127.0.0.1", port, geo, ua, corr_id)
        events.append({
            "timestamp": ts.isoformat(),
            "host": host,
            "process": process,
            "pid": pid,
            "severity": event_type["severity"],
            "category": event_type["category"],
            "ip": ip,
            "user": user_choice,
            "message": message,
            "country": geo,
            "user_agent": ua,
            "correlation_id": corr_id,
        })
    return events

def write_syslog(events, path):
    lines = []
    for event in events:
        dt = datetime.fromisoformat(event["timestamp"])
        host = event["host"]
        proc = event["process"]
        pid = event["pid"]
        severity = event["severity"]
        lines.append(f"{dt:%b %d %H:%M:%S} {host} {proc}[{pid}]: ({severity}) {event['message']}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

def write_json(events, path):
    path.write_text(json.dumps(events, indent=2), encoding="utf-8")

def write_csv(events, path):
    if not events:
        path.write_text("", encoding="utf-8")
        return
    keys = sorted(events[0].keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=keys)
        writer.writeheader()
        writer.writerows(events)

def resolve_formats(selected):
    if "all" in selected:
        return ["syslog", "json", "csv"]
    return selected

def main():
    parser = argparse.ArgumentParser(description="Generate synthetic security logs.")
    parser.add_argument("--count", type=int, default=300, help="Number of events to generate.")
    parser.add_argument("--window-minutes", type=int, default=60, help="Time window for generated events.")
    parser.add_argument("--burst-prob", type=float, default=0.2, help="Probability that the next event occurs within a short burst.")
    parser.add_argument("--start", type=str, help="ISO8601 timestamp to start from, defaults to now.")
    parser.add_argument("--seed", type=int, help="Random seed for reproducibility.")
    parser.add_argument("--formats", nargs="+", default=["syslog"], choices=["syslog", "json", "csv", "all"])
    parser.add_argument("--output-root", type=Path, default=Path("samples/generated_auth"), help="Base path (suffix added per format).")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    base_ts = datetime.fromisoformat(args.start) if args.start else datetime.now()
    events = synthesize_events(args.count, base_ts, args.window_minutes, args.burst_prob)
    formats = resolve_formats(args.formats)
    args.output_root.parent.mkdir(parents=True, exist_ok=True)

    if "syslog" in formats:
        write_syslog(events, args.output_root.with_suffix(".log"))
    if "json" in formats:
        write_json(events, args.output_root.with_suffix(".json"))
    if "csv" in formats:
        write_csv(events, args.output_root.with_suffix(".csv"))

if __name__ == "__main__":
    main()