# config.py (MAYBE DONT NEED???)
# Configuration settings for the email notification system

# SMTP Server Settings
SMTP_SERVER = "smtp.example.com"  # Replace with actual SMTP server
SMTP_PORT = 587  # Common port for TLS

# Authentication
SMTP_USER = "your_username"  # Replace with actual username
SMTP_PASSWORD = "your_password"  # Replace with actual password

# Email Settings
DEFAULT_SENDER = "vulnerability-alerts@uniti.com"
DEFAULT_RECIPIENTS = ["austin.carr@uniti.com", "rachel.carrey@uniti.com"]

# Alert Thresholds - when to send alerts
# Set to 0 to always send for that category
ALERT_THRESHOLDS = {
    "Critical": 0,   # Send alert if any Critical vulnerabilities
    "High": 5,       # Send alert if 5 or more High vulnerabilities
    "Medium": 10,    # Send alert if 10 or more Medium vulnerabilities
    "Low": 20        # Send alert if 20 or more Low vulnerabilities
}
