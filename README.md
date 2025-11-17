# Cyber Log Analyzer

A Python-based tool for analyzing system authentication logs to detect potential security threats like brute-force attacks and suspicious multi-user login attempts from a single IP address.

## Features

*   **Log Parsing**: Efficiently parses common log formats, such as `auth.log`, to extract relevant event data like timestamps, IP addresses, and usernames.
*   **Brute-Force Detection**: Identifies potential brute-force attacks by tracking the number of failed login attempts from a single IP within a configurable time window.
*   **Multi-User Attempt Detection**: Flags suspicious activity when a single IP address attempts to log in using multiple different usernames.
*   **Flexible Output**: Generates detailed alert reports in both JSON and CSV formats for easy integration with other systems or for manual review.
*   **Sample Data Generation**: Includes a script to generate sample log files for testing and demonstration purposes.

## Project Structure

```
.
├── log_analyzer.py        # Main analysis script
├── log_generator.py       # Script to generate sample log data
├── samples/
│   └── generated_auth.log # Sample log file
└── outputs/
    ├── alerts.csv         # Generated alerts in CSV format
    └── alerts.json        # Generated alerts in JSON format
```

## Getting Started

### Prerequisites

*   Python 3
*   `python-dateutil` library

### Installation

1.  Clone the repository:
    ```sh
    git clone https://github.com/JovanManojlovic01/Cyber-Log-Analyzer.git
    cd Cyber-Log-Analyzer
    ```

2.  Install the required Python package:
    ```sh
    pip install python-dateutil
    ```

### Usage

1.  **Generate Sample Logs (Optional)**

    To create a sample `generated_auth.log` file for analysis, run the log generator:
    ```sh
    python log_generator.py
    ```
    This will create a new log file in the `samples/` directory.

2.  **Run the Analyzer**

    To analyze the log file specified in the script (default is `samples/generated_auth.log`), run the main analyzer:
    ```sh
    python log_analyzer.py
    ```

3.  **View Results**

    After the analysis is complete, the script will output the number of alerts found. The detailed reports will be saved in the `outputs/` directory as `alerts.json` and `alerts.csv`.

    ```
    Reading log file: samples/generated_auth.log
    Analysis complete - 42 alerts found.
    JSON output: outputs/alerts.json
    CSV output: outputs/alerts.csv
    Done.
    ```

## Configuration

You can customize the analyzer's behavior by modifying the configuration variables at the top of `log_analyzer.py`:

*   `LOG_FILE`: Path to the input log file.
    *   Default: `"samples/generated_auth.log"`
*   `OUTPUT_PREFIX`: Base path and name for the output alert files.
    *   Default: `"outputs/alerts"`
*   `FAIL_THRESHOLD`: The number of failed login attempts from an IP within the time window to trigger a `brute_force` alert.
    *   Default: `5`
*   `TIME_WINDOW_MINUTES`: The duration in minutes for the sliding window used in brute-force detection.
    *   Default: `5`
*   `MULTI_USER_THRESHOLD`: The number of unique usernames attempted from a single IP to trigger a `multi_user_attempt` alert.
    *   Default: `3`

## Output Format

The analyzer generates two types of alerts, which are saved in `outputs/alerts.json` and `outputs/alerts.csv`.

### Brute-Force Alert

Triggered when the number of failed login attempts from an IP exceeds `FAIL_THRESHOLD` within `TIME_WINDOW_MINUTES`.

**Example (`alerts.json`):**
```json
{
  "type": "brute_force",
  "ip": "192.0.2.12",
  "count": 5,
  "window_minutes": 5,
  "last_seen": "2025-10-23T20:27:20",
  "sample_message": "Failed password for invalid user guest from 192.0.2.12 port 43966 ssh2"
}
```

### Multi-User Attempt Alert

Triggered when an IP attempts to log in with a number of unique usernames exceeding `MULTI_USER_THRESHOLD`.

**Example (`alerts.json`):**
```json
{
  "type": "multi_user_attempt",
  "ip": "203.0.113.45",
  "usernames": [
    "root",
    "test",
    "user"
  ],
  "count_usernames": 3,
  "last_seen": "2025-10-23T20:00:49",
  "sample_message": "Failed password for invalid user user from 203.0.113.45 port 54433 ssh2"
}
