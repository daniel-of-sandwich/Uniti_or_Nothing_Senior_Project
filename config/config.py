# config.py
# Central configuration for the Uniti Fiber Vulnerability Alert System

import os
from datetime import datetime

# ======== File Paths ========
# Base directory is the parent directory of the config module
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Data directories
RAW_DATA_DIR = os.path.join(BASE_DIR, 'data', 'raw')
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, 'data', 'processed')

# Default output file for aggregated data
DEFAULT_OUTPUT_FILE = os.path.join(PROCESSED_DATA_DIR, f'aggregated_vulnerabilities_{datetime.now().strftime("%Y%m%d")}.csv')

# Log directory
LOG_DIR = os.path.join(BASE_DIR, 'logs')

# ======== Nessus Settings ========
# Columns expected in Nessus CSV output
REQUIRED_COLUMNS = ['Plugin ID', 'CVE', 'CVSS', 'Risk', 'Host', 'Protocol', 'Port', 'Name', 'Synopsis']

# ======== SMTP Server Settings ========
# For development/testing
SMTP_SERVER = "smtp.example.com"  # Replace with actual SMTP server in production
SMTP_PORT = 25  # Common port for SMTP (25, 587 for TLS)

# Authentication
SMTP_USER = "your_username"  # Replace with actual username
SMTP_PASSWORD = "your_password"  # Replace with actual password

# Email Settings
DEFAULT_SENDER = "vulnerability-alerts@uniti.com"
DEFAULT_RECIPIENTS = ["austin.carr@uniti.com", "rachel.carrey@uniti.com"]

# ======== Alert Thresholds ========
# When to send alerts - set to 0 to always send for that category
ALERT_THRESHOLDS = {
    "Critical": 0,   # Send alert if any Critical vulnerabilities
    "High": 5,       # Send alert if 5 or more High vulnerabilities
    "Medium": 10,    # Send alert if 10 or more Medium vulnerabilities
    "Low": 20        # Send alert if 20 or more Low vulnerabilities
}

# ======== Dashboard Settings ========
# Grafana connection settings (for future use)
GRAFANA_URL = "http://localhost:3000"  # Replace with actual Grafana URL
GRAFANA_API_KEY = "your_api_key"  # Replace with actual API key

# ======== Helper Functions ========
# Create directories if they don't exist
def ensure_directories_exist():
    """Create necessary directories if they don't exist."""
    for directory in [RAW_DATA_DIR, PROCESSED_DATA_DIR, LOG_DIR]:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"Created directory: {directory}")

# Call this when importing the config module
ensure_directories_exist()
