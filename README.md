# Vulnerability Alert Aggregation System

A dashboard and automated email system for network vulnerability alert aggregation, created for Uniti Fiber.

Created by the team 'Uniti or Nothing' from the University of South Alabama

## Team Members

- Sam Brister
- Sebastian Bustamante
- Daniel Forbes
- Ashton Surla

## Overview

This system processes vulnerability reports from Tenable Nessus Essentials, aggregates the data, and presents it through:
1. A Grafana dashboard with visual aids
2. Automated email alerts with vulnerability summaries

## Features

- Processes Nessus Essentials vulnerability scan outputs 
- Tracks new devices on the network
- Aggregates alerts based on priority
- Sends email notifications when thresholds are met
- Visual dashboard with color-coded risk levels

### Key Features

- Automated aggregation of Nessus vulnerability scan reports
- Detailed visualization dashboard with risk-based color coding
- New device detection between network scans
- Smart alerting based on configurable thresholds
- Historical tracking of network vulnerability status

## System Architecture

```
[Nessus Scans] → [CSV Export] → [Python Processing] → [SQLite Database] → [Grafana Dashboard] → [Grafana Alerts]
```

## Project Structure

```
uniti_vulnerability_system/
├── data/
│   ├── raw/                # Raw CSV files from Nessus
│   ├── processed/          # Aggregated CSV files
│   └── db/                 # SQLite database
├── scripts/
│   ├── vulnerability_aggregator.py  # Aggregation script
│   ├── dashboard_connector.py       # Grafana database connector
│   ├── nessus_connector.py          # Nessus API connector
│   ├── file_watcher.py              # File monitoring system
├── config.py           # Main configuration file 
├── run.py              # Main execution script
└── requirements.txt        # Required Python packages
```

## Installation and Setup

### 1. System Requirements

- Linux server with at least 4GB RAM
- Python 3.7+ with pip
- Tenable Nessus
- Grafana OSS

### 2. Python Dependencies

Install required Python packages:

```bash
pip install -r requirements.txt
```

### 3. Nessus Setup

- Configure Nessus for vulnerability scanning (basic scan configuration is sufficient)
- Create API access key and secret key in Nessus UI (Settings → API Keys)

### 4. Configuration

Update the `config.py` file with your specific settings:

```python
# Nessus settings
NESSUS_URL = 'https://your-nessus-server:8834'
ACCESS_KEY = 'your-access-key'
SECRET_KEY = 'your-secret-key'

# Directory paths
RAW_DATA_DIR = './data/raw'
PROCESSED_DATA_DIR = './data/processed'
LOG_DIR = './logs'

# Alert thresholds
ALERT_THRESHOLDS = {
    'Critical': 0,  # Any critical vulnerability triggers an alert
    'High': 5,      # 5 or more high vulnerabilities trigger an alert
    'Medium': 10,   # 10 or more medium vulnerabilities trigger an alert
    'Low': 20       # 20 or more low vulnerabilities trigger an alert
}
```

### 5. Grafana Setup

1. Install the SQLite plugin for Grafana:
   ```bash
   grafana-cli plugins install frser-sqlite-datasource
   ```
2. Configure SMTP for Grafana alerts by editing the `grafana.ini` file:
   ```ini
   [smtp]
   enabled = true
   host = smtp.example.com:587
   user = your-email@example.com
   password = your-email-password
   from_address = alerts@example.com
   from_name = Vulnerability Alert System
   startTLS_policy = OpportunisticStartTLS
   ```
3. Restart Grafana:
   ```bash
   sudo systemctl restart grafana-server
   ```

## Running the System

### Manual Execution

Run the main script to process vulnerability data:

```bash
python run.py
```

### Automated Execution

Use the file watcher to automatically process new CSV files:
   ```bash
   python scripts/file_watcher.py
   ```

## Dashboard Setup

1. Import the dashboard JSON (`Vulnerability Dashboard-####.json`) into Grafana:
   - Navigate to Dashboards → Import
   - Upload or paste the JSON content
   - Configure the SQLite data source

2. Configure the SQLite data source:
   - Name: `Vulnerability Database`
   - Path: `/path/to/uniti_vulnerability_system/data/db/vulnerability_data.db`
   - Test the connection

## Alert Configuration

Replace the email functionality with Grafana's built-in alerting:

1. Create Contact Points:
   - Navigate to Alerting → Contact points
   - Add an email contact point for your team
   - Configure with appropriate email addresses

2. Create Alert Rules:
   - Critical Vulnerabilities Alert
   - New Device Detection Alert
   - Weekly Vulnerability Summary

Example SQL for Critical Vulnerabilities alert:
```sql
SELECT COUNT(*) as critical_count
FROM vulnerabilities
WHERE risk = 'Critical'
AND is_new_scan = 1
```

### Modifying Alert Thresholds

Edit the `ALERT_THRESHOLDS` in `config.py` to adjust sensitivity based on your organization's risk tolerance.

## Troubleshooting

- **Error connecting to Nessus**: Verify API credentials and network connectivity
- **No data in dashboard**: Check SQLite database for data, ensure data connector is working
- **Missing alert emails**: Verify Grafana SMTP configuration, check spam folder
