# run.py
import os
import sys
import time
from datetime import datetime

# Add scripts directory to path
scripts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scripts')
sys.path.append(scripts_dir)

# Import scripts
import nessus_connector
import vulnerability_aggregator
import dashboard_connector
import email_sender

def run_full_process():
    """Run the full vulnerability management process"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    print(f"\n=== Starting vulnerability management process at {timestamp} ===\n")
    
    # Step 1: Download data from Nessus
    print("\n--- Step 1: Downloading data from Nessus ---")
    if nessus_connector.get_nessus_data():
        print("Data download successful")
        
        # Step 2: Aggregate vulnerability data
        print("\n--- Step 2: Aggregating vulnerability data ---")
        if vulnerability_aggregator.aggregate_vulnerability_data():
            print("Data aggregation successful")
            
            # Step 3: Update dashboard data
            print("\n--- Step 3: Updating dashboard data ---")
            if dashboard_connector.create_database():
                print("Dashboard data update successful")
                
                # Step 4: Send email notifications
                print("\n--- Step 4: Sending email notifications ---")
                csv_file = '../data/processed/aggregated_vulnerabilities.csv'
                html_content = email_sender.create_html_report(csv_file)
                
                if html_content and email_sender.send_email(html_content):
                    print("Email notifications sent successfully")
                else:
                    print("Email notifications failed")
            else:
                print("Dashboard data update failed")
        else:
            print("Data aggregation failed")
    else:
        print("Data download failed")
    
    print(f"\n=== Vulnerability management process completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n")

if __name__ == "__main__":
    # Create required directories
    os.makedirs('../data/raw', exist_ok=True)
    os.makedirs('../data/processed', exist_ok=True)
    os.makedirs('../logs', exist_ok=True)
    
    # Run process
    run_full_process()
