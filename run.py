# run.py
import os
import sys
import time
from datetime import datetime

# Get the base directory (project root)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(BASE_DIR, 'scripts')

# Add scripts directory to path
sys.path.append(SCRIPTS_DIR)

# Import scripts
from vulnerability_aggregator import aggregate_vulnerability_data
from dashboard_connector import update_database
from email_sender import create_html_report, send_email

def run_full_process():
    """Run the complete vulnerability analysis process"""
    start_time = time.time()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    print(f"\n=== Starting Vulnerability Analysis Process at {timestamp} ===")
    
    # Step 1: Aggregate vulnerability data
    print("\nStep 1: Aggregating vulnerability data...")
    if aggregate_vulnerability_data():
        print("Vulnerability aggregation completed successfully")
    else:
        print("Vulnerability aggregation failed")
        return False
    
    # Step 2: Update the dashboard database
    print("\nStep 2: Updating dashboard database...")
    if update_database():
        print("Dashboard database update completed successfully")
    else:
        print("Dashboard database update failed")
        return False
    
    # Step 3: Send email notification
    print("\nStep 3: Sending email notification...")
    # Path to processed CSV file
    csv_file = os.path.join(BASE_DIR, 'data', 'processed', 'aggregated_vulnerabilities.csv')
    
    # Create HTML report
    html_content = create_html_report(csv_file)
    
    if html_content:
        # Send email with timestamp in subject
        subject = f"Vulnerability Alert Report - {timestamp}"
        if send_email(html_content, subject=subject):
            print("Email notification sent successfully")
        else:
            print("Email notification sending failed")
    else:
        print("No email content created")
    
    # Calculate and display execution time
    execution_time = time.time() - start_time
    print(f"\n=== Process completed in {execution_time:.2f} seconds ===")
    
    return True

if __name__ == "__main__":
    run_full_process()
