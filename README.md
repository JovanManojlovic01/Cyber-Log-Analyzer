Cyber Log Analyzer

Synthetic auth-log generator and anomaly analyzer that helps you model attack behavior, feed downstream tooling, and build detections without touching real production data.

Project layout

log_generator.py – CLI tool that emits synthetic security events (syslog, JSON, CSV).
log_analyzer.py – CLI analyzer that ingests generated logs, normalizes them, and produces alert + summary reports.

Features

    1. Weighted event synthesis for auth, sudo, VPN, and maintenance activity.
    2. Configurable time windows, burstiness, and reproducible runs via seeds.
    3. Multi-format export (syslog/JSON/CSV) for easy ingestion elsewhere.
    4. Parsing/normalization pipeline with IP/user extraction.
    5. Brute-force, multi-user, suspicious-success, and volume-spike alerting.
    6. Structured alert + summary outputs in JSON/CSV.
