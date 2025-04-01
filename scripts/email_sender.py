# email_sender.py
# Email notification system for vulnerability alerts
# Uniti Fiber Senior Project

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import pandas as pd
from datetime import datetime
import os
import sys
import traceback

# Import configuration settings
try:
    from config import SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, DEFAULT_SENDER, DEFAULT_RECIPIENTS, ALERT_THRESHOLDS
except ImportError:
    print("Error: Could not import config.py. Make sure it exists in the same directory.")
    input("Press Enter to exit...")
    sys.exit(1)

def create_vulnerability_report(csv_file):
    """
    Create an HTML report of vulnerability findings from a CSV file.
    
    Args:
        csv_file (str): Path to the CSV file containing aggregated vulnerability data
        
    Returns:
        str: HTML content for the email or None if no alert is needed
    """
    try:
        print(f"Attempting to read CSV file: {csv_file}")
        
        # Check if file exists
        if not os.path.exists(csv_file):
            print(f"Error: File not found: {csv_file}")
            return None
            
        # Read the aggregated CSV file
        df = pd.read_csv(csv_file)
        print(f"Successfully read CSV with {len(df)} rows")
        
        # Check if the CSV has the required columns
        required_columns = ['Risk', 'Host', 'Name']
        missing_columns = [col for col in required_columns if col not in df.columns]
        if missing_columns:
            print(f"Error: CSV is missing required columns: {missing_columns}")
            return None
        
        # Get counts by risk level
        risk_counts = df['Risk'].value_counts().to_dict()
        print(f"Risk level counts: {risk_counts}")
        
        # Check if we should send an alert based on thresholds
        should_alert = False
        alert_reasons = []
        
        for risk, count in risk_counts.items():
            threshold = ALERT_THRESHOLDS.get(risk, 0)
            if threshold == 0 and count > 0:  # Any vulnerabilities of this type trigger alert
                should_alert = True
                alert_reasons.append(f"Found {count} {risk} vulnerabilities (threshold: any)")
            elif count >= threshold and threshold > 0:  # Count exceeds threshold
                should_alert = True
                alert_reasons.append(f"Found {count} {risk} vulnerabilities (threshold: {threshold})")
        
        if not should_alert:
            print("No alert thresholds reached. No email will be sent.")
            return None
        
        print(f"Alert triggered because: {', '.join(alert_reasons)}")
        
        # Get top 10 vulnerabilities by count
        top_vulns = df['Name'].value_counts().head(10)
        
        # Get unique hosts with vulnerabilities
        hosts = df['Host'].unique()
        
        # Create the HTML content
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
                h2, h3 {{ color: #333366; }}
            </style>
        </head>
        <body>
            <h2>Vulnerability Alert Summary</h2>
            <p>Report generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <h3>Vulnerability Counts by Risk Level</h3>
            <table>
                <tr>
                    <th>Risk Level</th>
                    <th>Count</th>
                </tr>
        """
        
        # Add rows for each risk level
        for risk in ['Critical', 'High', 'Medium', 'Low']:
            count = risk_counts.get(risk, 0)
            css_class = risk.lower()
            html += f"""
                <tr class="{css_class}">
                    <td>{risk}</td>
                    <td>{count}</td>
                </tr>
            """
        
        html += """
            </table>
            
            <h3>Top 10 Most Common Vulnerabilities</h3>
            <table>
                <tr>
                    <th>Vulnerability</th>
                    <th>Count</th>
                </tr>
        """
        
        # Add rows for top vulnerabilities
        for vuln, count in top_vulns.items():
            html += f"""
                <tr>
                    <td>{vuln}</td>
                    <td>{count}</td>
                </tr>
            """
        
        html += """
            </table>
            
            <h3>Affected Hosts</h3>
            <ul>
        """
        
        # Add list of hosts
        for host in hosts:
            host_vulns = df[df['Host'] == host]
            critical_count = len(host_vulns[host_vulns['Risk'] == 'Critical'])
            high_count = len(host_vulns[host_vulns['Risk'] == 'High'])
            
            html += f"""
                <li>{host} - Critical: {critical_count}, High: {high_count}</li>
            """
        
        html += """
            </ul>
            
            <p>For full details, please check the vulnerability dashboard.</p>
        </body>
        </html>
        """
        
        print("Successfully created HTML report")
        return html
    
    except Exception as e:
        print(f"Error creating vulnerability report: {e}")
        traceback.print_exc()
        return None

def send_email(email_message, sender=DEFAULT_SENDER, subject="Vulnerability Alert Report", recipients=DEFAULT_RECIPIENTS):
    """
    Send an email with the vulnerability report.
    
    Args:
        email_message (str): HTML content of the email
        sender (str): Email address of the sender
        subject (str): Subject line of the email
        recipients (list): List of recipient email addresses
        
    Returns:
        bool: True if email was sent successfully, False otherwise
    """
    try:
        print(f"Preparing to send email from {sender} to {recipients}")
        
        # Create MIME message
        msg = MIMEMultipart('alternative')
        msg['From'] = sender
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = subject
        
        # Attach HTML content
        email_body = MIMEText(email_message, 'html')
        msg.attach(email_body)
        
        print(f"Connecting to SMTP server: {SMTP_SERVER}:{SMTP_PORT}")
        
        # Connect to SMTP server and send
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp_obj:
            print("SMTP connection established")
            
            smtp_obj.ehlo()
            print("EHLO completed")
            
            smtp_obj.starttls()
            print("TLS started")
            
            smtp_obj.login(SMTP_USER, SMTP_PASSWORD)
            print("Login successful")
            
            smtp_obj.send_message(msg)
            print("Message sent")
            
        print(f"Email sent successfully to {', '.join(recipients)}")
        return True
    
    except smtplib.SMTPAuthenticationError:
        print("Error: SMTP authentication failed. Check username and password.")
        return False
    except smtplib.SMTPConnectError:
        print(f"Error: Could not connect to SMTP server {SMTP_SERVER}:{SMTP_PORT}")
        return False
    except Exception as e:
        print(f"Error sending email: {e}")
        traceback.print_exc()
        return False

def test_email_without_sending():
    """
    Generate the email content but don't actually send it.
    Useful for testing without SMTP server access.
    """
    try:
        # Get the location of the aggregated CSV file
        csv_file = input("Enter the path to the aggregated CSV file: ")
        
        if not os.path.exists(csv_file):
            print(f"Error: File not found: {csv_file}")
            return
        
        # Create the report
        email_content = create_vulnerability_report(csv_file)
        
        if email_content:
            # Create a directory to save the test email if it doesn't exist
            output_dir = "test_emails"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                print(f"Created directory: {output_dir}")
            
            # Generate a unique filename based on timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = os.path.join(output_dir, f"test_email_{timestamp}.html")
            
            # Save the HTML to a file instead of sending
            with open(output_file, "w") as f:
                f.write(email_content)
            print(f"Test email content saved to '{output_file}'")
            
            # Open the file automatically if on Windows
            try:
                if os.name == 'nt':  # Windows
                    os.startfile(output_file)
                    print("Opening file in default browser...")
            except Exception as e:
                print(f"Could not open file automatically: {e}")
            
            # Print email details
            print("\nEmail would be sent with the following details:")
            print(f"From: {DEFAULT_SENDER}")
            print(f"To: {', '.join(DEFAULT_RECIPIENTS)}")
            print(f"Subject: Vulnerability Alert Report")
            print("Content: HTML report with vulnerability summary")
        else:
            print("No email content generated - alert thresholds not met.")
    
    except Exception as e:
        print(f"Error in test email function: {e}")
        traceback.print_exc()

def main():
    """
    Main function to test the email sender.
    """
    try:
        print("\n" + "="*50)
        print("Vulnerability Alert Email System")
        print("="*50)
        
        print("\nThis system allows you to generate and send email alerts")
        print("based on vulnerability data from Nessus CSV exports.")
        
        # Offer options
        print("\nOptions:")
        print("1 - Send a real email with vulnerability report")
        print("2 - Test email generation without sending")
        print("3 - Exit")
        
        choice = input("\nEnter your choice (1-3): ")
        
        if choice == "1":
            # Send a real email
            csv_file = input("Enter the path to the aggregated CSV file: ")
            if not os.path.exists(csv_file):
                print(f"Error: File not found: {csv_file}")
                return
            
            email_content = create_vulnerability_report(csv_file)
            if email_content:
                recipients = input("Enter recipient email(s) separated by commas, or press Enter for defaults: ")
                if recipients:
                    recipient_list = [email.strip() for email in recipients.split(",")]
                else:
                    recipient_list = DEFAULT_RECIPIENTS
                    
                subject = input("Enter email subject or press Enter for default: ")
                if not subject:
                    subject = "Vulnerability Alert Report"
                
                confirm = input(f"\nReady to send email to {', '.join(recipient_list)}. Proceed? (y/n): ")
                if confirm.lower() == 'y':
                    send_email(email_content, DEFAULT_SENDER, subject, recipient_list)
                else:
                    print("Email sending cancelled.")
        
        elif choice == "2":
            # Test without sending
            test_email_without_sending()
        
        else:
            print("Exiting.")
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        traceback.print_exc()
    finally:
        # Prevent the window from closing immediately
        print("\n" + "="*50)
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
