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

## Key Features

- Automated aggregation of Nessus vulnerability scan reports
- Detailed visualization dashboard with risk-based color coding
- New device detection between network scans
- Email notifications with custom formatting and distribution lists
- Historical tracking of network vulnerability status

## System Architecture

```
[Nessus Scans] → [CSV Export] → [Python Processing] → [SQLite Database] → [Grafana Dashboard]
                                                    ↓
                                          [Email Alert System]
```

## Project Structure

```
uniti_vulnerability_system/            
├── data/
│   ├── raw/                 # Raw CSV files from Nessus
│   ├── processed/           # Aggregated CSV files
│   └── db/                  # SQLite database
├── scripts/
│   ├── vulnerability_aggregator.py  # Aggregation script
│   ├── dashboard_connector.py       # Database connector
│   ├── email_sender.py              # Email notification script
│   ├── nessus_connector.py          # Nessus API connector
│   └── file_watcher.py              # File monitoring system
├── config.py                # Main configuration file
├── run.py                   # Main execution script
└── requirements.txt         # Required Python packages
```

## Installation and Setup

### 1. System Requirements

- Linux server with at least 4GB RAM
- Python 3.7+ with pip
- Tenable Nessus Essentials
- Grafana OSS

### 2. Python Dependencies

Install required Python packages:

```bash
pip install -r requirements.txt
```

### 3. Nessus Setup

- Install Nessus Essentials on your server
- Configure vulnerability scanning (target specification, IP ranges)
- Create API access key and secret key in Nessus UI

### 4. Configuration

Update the `config.py` file with your settings:

```python
# Nessus settings
NESSUS_URL = 'https://your-nessus-server:8834'
ACCESS_KEY = 'your-access-key'
SECRET_KEY = 'your-secret-key'

# Email configuration
EMAIL_CONFIG = {
    'SMTP_SERVER': 'your-smtp-server',
    'SMTP_PORT': 587,
    'SMTP_USER': 'your-username',
    'SMTP_PASSWORD': 'your-password',
    'FROM_EMAIL': 'alerts@example.com',
    'FROM_NAME': 'Vulnerability Alert System'
}

# Email recipients
EMAIL_RECIPIENTS = [
    'security-team@example.com',
    'admin@example.com'
]
```

### 5. Grafana Setup

1. Install Grafana OSS and the SQLite plugin:
   ```bash
   grafana-cli plugins install frser-sqlite-datasource
   ```

2. Import the dashboard JSON file into Grafana

3. Configure the SQLite data source:
   - Name: `Vulnerability Database`
   - Path: `/path/to/data/db/vulnerability_data.db`

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

## Email Alerts

The system sends custom HTML emails when:
- New devices are detected on the network
- Critical vulnerabilities are found
- Threshold levels of High/Medium vulnerabilities are reached

Email alerts include:
- Color-coded risk levels
- Direct links to vulnerability details
- Tables of affected hosts and ports
- Summary statistics for quick assessment

To modify email recipients:
- Edit the `EMAIL_RECIPIENTS` list in `config.py`

## Troubleshooting

- **Error connecting to Nessus**: Verify API credentials and network connectivity
- **No data in dashboard**: Check SQLite database for data integrity
- **Missing email alerts**: Verify SMTP configuration, check spam folder
- **Processing errors**: Review log files for detailed error messages
