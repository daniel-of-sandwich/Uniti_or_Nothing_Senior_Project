# email_sender.py
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pandas as pd
import os
from datetime import datetime
from config import SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, EMAIL_SENDER, EMAIL_RECIPIENTS

def create_html_report(csv_file):
    """Create a simple HTML report from the processed CSV file"""
    print(f"Creating report from: {csv_file}")
    
    # Check if file exists
    if not os.path.exists(csv_file):
        print(f"Error: File not found: {csv_file}")
        return None
    
    # Read CSV
    df = pd.read_csv(csv_file)
    
    # Count vulnerabilities by risk level
    risk_counts = df['Risk'].value_counts().to_dict() if 'Risk' in df.columns else {}
    
    # Get unique hosts
    hosts = df['Host'].unique().tolist() if 'Host' in df.columns else []
    
    # Create HTML
    html = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; }}
            table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .critical {{ background-color: #ffcccc; }}
            .high {{ background-color: #ffdacc; }}
            .medium {{ background-color: #ffffcc; }}
            .low {{ background-color: #e6ffcc; }}
        </style>
    </head>
    <body>
        <h2>Vulnerability Alert Report</h2>
        <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h3>Vulnerability Summary</h3>
        <table>
            <tr>
                <th>Risk Level</th>
                <th>Count</th>
            </tr>
    """
    
    # Add risk rows
    for risk in ['Critical', 'High', 'Medium', 'Low']:
        count = risk_counts.get(risk, 0)
        html += f"""
            <tr class="{risk.lower()}">
                <td>{risk}</td>
                <td>{count}</td>
            </tr>
        """
    
    html += """
        </table>
        
        <h3>Affected Hosts</h3>
        <ul>
    """
    
    # Add hosts
    for host in hosts:
        html += f"<li>{host}</li>"
    
    html += """
        </ul>
        
        <p>For detailed information, please check the dashboard.</p>
    </body>
    </html>
    """
    
    return html

def send_email(html_content, subject="Vulnerability Alert", recipients=None):
    """Send email with HTML content"""
    if recipients is None:
        recipients = EMAIL_RECIPIENTS
    
    print(f"Sending email to: {recipients}")
    
    msg = MIMEMultipart('alternative')
    msg['From'] = EMAIL_SENDER
    msg['To'] = ", ".join(recipients)
    msg['Subject'] = subject
    
    # Attach HTML
    msg.attach(MIMEText(html_content, 'html'))
    
    try:
        # Connect to SMTP server
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo()
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        
        # Send email
        server.send_message(msg)
        server.quit()
        
        print("Email sent successfully")
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def main():
    """Main function to test the email sender"""
    # Path to processed CSV file
    csv_file = '../data/processed/aggregated_vulnerabilities.csv'
    
    # Create HTML report
    html_content = create_html_report(csv_file)
    
    if html_content:
        # Send email
        send_email(html_content)
    else:
        print("No email content created")

if __name__ == "__main__":
    main()
