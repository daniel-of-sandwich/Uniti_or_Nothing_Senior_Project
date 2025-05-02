# config.py

# Nessus settings
NESSUS_URL = 'https://0.0.0.0:8834'  # Nessus server IP
ACCESS_KEY = 'yourAccessKey'  # Update with actual access key
SECRET_KEY = 'yourSecretKey'  # Update with actual secret key

# Directory paths
RAW_DATA_DIR = './data/raw'
PROCESSED_DATA_DIR = './data/processed'
LOG_DIR = './logs'

# Alert thresholds (# of vulnerabilities that trigger an alert)
ALERT_THRESHOLDS = {
    'Critical': 0,  # Any critical vulnerability triggers an alert
    'High': 5,      # 5 or more high vulnerabilities trigger an alert
    'Medium': 10,   # 10 or more medium vulnerabilities trigger an alert
    'Low': 20       # 20 or more low vulnerabilities trigger an alert
}

# CVSS score thresholds for alert levels
CVSS_THRESHOLD = {
    'Critical': 9.0,  # CVSS scores >= 9.0 are Critical
    'High': 7.0,      # CVSS scores >= 7.0 and < 9.0 are High
    'Medium': 4.0,    # CVSS scores >= 4.0 and < 7.0 are Medium
    'Low': 0.1        # CVSS scores > 0 and < 4.0 are Low
}

# Database settings
DB_PATH = './data/db/vulnerability_data.db'

# Folders to scan (All folders except 'Trash')
FOLDERS = []

# Features to keep from CSV exports
KEEP_FEATURES = [
    'Plugin ID', 'CVE', 'CVSS v2.0 Base Score', 
    'Risk', 'Host', 'Protocol', 'Port', 'Name',
    'Synopsis', 'Description', 'Solution'
]

# Email configuration (Mailtrap)
EMAIL_CONFIG = {
    'SMTP_SERVER': 'sandbox.smtp.mailtrap.io',
    'SMTP_PORT': 2525,          
    'SMTP_USER': 'user',
    'SMTP_PASSWORD': 'pass',
    'FROM_EMAIL': 'alerts@mail.com',   
    'FROM_NAME': 'Uniti Vulnerability Alert System'
}

# Email recipients
EMAIL_RECIPIENTS = [
    'youremail@mail.com'
]
