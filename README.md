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

## Setup Requirements

### Hardware
- Linux VM for Nessus Server
  - 4GB RAM minimum
  - 2-4 CPU cores
  - 20GB+ storage
- Additional VMs (with different OS configurations) for testing

### Software
- Tenable Nessus Essentials
- Python 3.x
- Grafana (OSS)

## Installation

1. Clone this repository:
```
git clone https://github.com/YOUR-USERNAME/Vulnerability-Alert-Aggregation-System.git
cd Vulnerability-Alert-Aggregation-System
```

2. Install Python dependencies:
```
pip install -r requirements.txt
```

3. Set up configuration:
   - Edit the `config.py` file with your settings:
     - Nessus server details
     - Email configuration
     - Directory paths
     - Alert thresholds

4. Create necessary directories:
```
mkdir -p data/raw data/processed data/db logs
```

5. Install and configure Nessus Essentials on your Linux VM.

6. Set up Grafana and import the dashboard.

## Usage

### Running the System

1. Use the main script to run the full process:
```
python run.py
```

2. For continuous monitoring, use the file watcher:
```
python scripts/file_watcher.py
```

### Email Alerts

To test email functionality without sending:
```
python scripts/email_sender.py
```
Then select option 2 to test without sending.

## File Structure

```
uniti_vulnerability_system/
├── config/
│   ├── config.py             # Configuration settings
├── data/
│   ├── raw/                  # Raw CSV files from Nessus
│   ├── processed/            # Aggregated CSV files
│   └── db/                   # Database files for Grafana
├── scripts/
│   ├── vulnerability_aggregator.py  # Data processing script
│   ├── email_sender.py              # Email notification script
│   ├── dashboard_connector.py       # Database update script
│   ├── file_watcher.py              # Monitors for new CSV files
│   └── run.py                       # Main script to run all processes
├── logs/                     # Log files directory
└── requirements.txt          # Required Python packages
```

## License

This project is not licensed for commercial use outside of Uniti Fiber.
