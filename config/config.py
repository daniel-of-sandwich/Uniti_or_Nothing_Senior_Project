# config.py

# Nessus configuration
NESSUS_URL = 'https://192.168.50.188:8834'
ACCESS_KEY = 'c0f9a8e531e747cfb55ff04c809b8e00f8b1711264e0f4a3f587e0c69cf47780'
SECRET_KEY = '355fa0f7f27a11282a7775bbe563a3665b2106de601c73a92ba16a21d8e5ea4e'

# Directory paths
RAW_DATA_DIR = '../data/raw'
PROCESSED_DATA_DIR = '../data/processed'
LOGS_DIR = '../logs'
DB_DIR = '../data/db'
DB_PATH = '../data/db/vulnerability_data.db'

# Email configuration
SMTP_SERVER = 'smtp.example.com'
SMTP_PORT = 25
SMTP_USER = 'alerts@example.com'
SMTP_PASSWORD = 'your_password'
EMAIL_SENDER = 'vulnerability-alerts@uniti.com'
EMAIL_RECIPIENTS = ['you@uniti.com', 'me@uniti.com']
EMAIL_SUBJECT = 'Vulnerability Alert Report'

# Alert thresholds
ALERT_ON_CRITICAL = True
ALERT_HIGH_THRESHOLD = 5
ALERT_ON_NEW_DEVICES = True

# Notification frequency
# Options: 'immediate', 'daily', 'weekly'
NOTIFICATION_FREQUENCY = 'immediate'
