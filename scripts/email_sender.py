# email_sender.py

import os
import smtplib
import sqlite3
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import DB_PATH, ALERT_THRESHOLDS, EMAIL_CONFIG, EMAIL_RECIPIENTS

def connect_to_database():
    """Connect to the SQLite database"""
    try:
        conn = sqlite3.connect(DB_PATH)
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

def check_for_alerts():
    """
    Check for alerts in latest scan data
    Focuses on new devices and vulnerabilities with Medium+ severity
    """
    conn = connect_to_database()
    if not conn:
        return None
    
    alerts = []
    
    try:
        # Get the most recent batch_id
        cursor = conn.cursor()
        cursor.execute("SELECT batch_id FROM batches ORDER BY import_date DESC LIMIT 1")
        latest_batch = cursor.fetchone()
        
        if not latest_batch:
            print("No scan batches found in database")
            return None
            
        batch_id = latest_batch[0]
        
        # Check for new devices
        cursor.execute("""
            SELECT COUNT(*) FROM new_devices 
            WHERE batch_id = ?
        """, (batch_id,))
        new_device_count = cursor.fetchone()[0]
        
        if new_device_count > 0:
            # Get details about new devices including source file
            cursor.execute("""
                SELECT ip_address, vulnerability_count, source_file FROM new_devices
                WHERE batch_id = ?
            """, (batch_id,))
            new_devices = cursor.fetchall()
            
            alerts.append({
                "type": "NEW_DEVICES",
                "count": new_device_count,
                "details": new_devices
            })
        
        # Check for medium or higher vulnerabilities (Critical, High, Medium)
        cursor.execute("""
            SELECT COUNT(*) FROM vulnerabilities 
            WHERE batch_id = ? AND risk IN ('Critical', 'High', 'Medium') AND is_new_scan = 1
        """, (batch_id,))
        vuln_count = cursor.fetchone()[0]
        
        if vuln_count > 0:
            # Get details about vulnerabilities (Medium+) including source file
            cursor.execute("""
                SELECT host, cve_id, risk, cvss_score, name, source_file FROM vulnerabilities
                WHERE batch_id = ? AND risk IN ('Critical', 'High', 'Medium') AND is_new_scan = 1
                ORDER BY 
                  CASE 
                    WHEN risk = 'Critical' THEN 1
                    WHEN risk = 'High' THEN 2
                    WHEN risk = 'Medium' THEN 3
                    ELSE 4
                  END,
                  cvss_score DESC
            """, (batch_id,))
            vulns = cursor.fetchall()
            
            alerts.append({
                "type": "VULNERABILITIES",
                "count": vuln_count,
                "details": vulns
            })
        
        return alerts
        
    except Exception as e:
        print(f"Error checking for alerts: {e}")
        return None
    finally:
        conn.close()

def format_email_body(alerts):
    """Format email body with alert information"""
    if not alerts:
        return None
        
    current_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Create HTML email body
    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; color: #333; }}
            h1 {{ color: #003366; }}
            h2 {{ color: #0055a5; margin-top: 20px; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
            th {{ background-color: #0055a5; color: white; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .critical {{ color: #d9534f; font-weight: bold; }}
            .high {{ color: #f0ad4e; font-weight: bold; }}
            .medium {{ color: #5bc0de; font-weight: bold; }}
            .new-device {{ color: #5cb85c; font-weight: bold; }}
            .file {{ color: #666; font-size: 0.9em; font-style: italic; }}
        </style>
    </head>
    <body>
        <h1>Uniti Vulnerability Alert</h1>
        <p>The following security alerts were detected during the latest vulnerability scan on {current_date}:</p>
    """
    
    # Add sections for each alert type
    for alert in alerts:
        if alert['type'] == 'NEW_DEVICES':
            html += f"""
            <h2 class="new-device">New Devices Detected ({alert['count']})</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Vulnerability Count</th>
                    <th>Source File</th>
                </tr>
            """
            
            for device in alert['details']:
                html += f"""
                <tr>
                    <td>{device[0]}</td>
                    <td>{device[1]}</td>
                    <td class="file">{device[2]}</td>
                </tr>
                """
            
            html += "</table>"
            
        elif alert['type'] == 'VULNERABILITIES':
            html += f"""
            <h2>Vulnerabilities (Medium and Higher) ({alert['count']})</h2>
            <table>
                <tr>
                    <th>Host</th>
                    <th>CVE ID</th>
                    <th>Risk</th>
                    <th>CVSS Score</th>
                    <th>Description</th>
                    <th>Source File</th>
                </tr>
            """
            
            for vuln in alert['details']:
                # Apply CSS class based on risk level
                risk_class = vuln[2].lower()
                
                html += f"""
                <tr>
                    <td>{vuln[0]}</td>
                    <td>{vuln[1]}</td>
                    <td class="{risk_class}">{vuln[2]}</td>
                    <td>{vuln[3]}</td>
                    <td>{vuln[4]}</td>
                    <td class="file">{vuln[5]}</td>
                </tr>
                """
            
            html += "</table>"
    
    html += """
        <p>For more details, please check the Vulnerability Dashboard.</p>
        <p>This is an automated message from the Uniti Vulnerability Alert System.</p>
    </body>
    </html>
    """
    
    return html

def send_email(alerts, recipients=None):
    """Send email alerts to the specified recipients"""
    if not alerts:
        print("No alerts to send")
        return False
        
    if recipients is None:
        recipients = EMAIL_RECIPIENTS
        
    # Format email subject and body
    email_subject = f"ALERT: {len(alerts)} Security Issues Detected"
    email_body_html = format_email_body(alerts)
    
    if not email_body_html:
        print("Failed to format email body")
        return False
    
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = f"{EMAIL_CONFIG['FROM_NAME']} <{EMAIL_CONFIG['FROM_EMAIL']}>"
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = email_subject
        
        # Attach HTML content
        msg.attach(MIMEText(email_body_html, 'html'))
        
        # Connect to SMTP server
        smtp_obj = smtplib.SMTP(EMAIL_CONFIG['SMTP_SERVER'], EMAIL_CONFIG['SMTP_PORT'])
        smtp_obj.ehlo()
        smtp_obj.starttls()
        smtp_obj.login(EMAIL_CONFIG['SMTP_USER'], EMAIL_CONFIG['SMTP_PASSWORD'])
        
        # Send email
        smtp_obj.send_message(msg)
        smtp_obj.quit()
        
        print(f"Email alert sent to {len(recipients)} recipients via Mailtrap")
        return True
        
    except Exception as e:
        print(f"Error sending email: {e}")
        import traceback
        traceback.print_exc()
        return False

def process_alerts():
    """Main function to check for alerts and send emails"""
    print("\nChecking for security alerts...")
    
    alerts = check_for_alerts()
    
    if not alerts:
        print("No security alerts detected")
        return True
        
    print(f"Found {len(alerts)} security alerts")
    
    # Send email alert
    if send_email(alerts):
        print("Email alerts sent successfully")
        return True
    else:
        print("Failed to send email alerts")
        return False

if __name__ == "__main__":
    # Run the normal process
    process_alerts()
