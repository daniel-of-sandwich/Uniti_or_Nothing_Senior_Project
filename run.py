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
from nessus_connector import get_nessus_data

# Import email_sender from scripts directory
sys.path.append(os.path.join(BASE_DIR, 'scripts'))
from email_sender import process_alerts

def run_full_process():
    """Run the complete vulnerability analysis process"""
    start_time = time.time()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    print(f"\n=== Starting Vulnerability Analysis Process at {timestamp} ===")
    
    # Step 1: Pull data from Nessus
    print("\nStep 1: Retrieving data from Nessus...")
    if get_nessus_data():
        print("Nessus data retrieval completed successfully")
    else:
        print("Nessus data retrieval failed")
        return False
    
    # Step 2: Aggregate vulnerability data
    print("\nStep 2: Aggregating vulnerability data...")
    if aggregate_vulnerability_data():
        print("Vulnerability aggregation completed successfully")
    else:
        print("Vulnerability aggregation failed")
        return False
    
    # Step 3: Update the dashboard database
    print("\nStep 3: Updating dashboard database...")
    if update_database():
        print("Dashboard database update completed successfully")
    else:
        print("Dashboard database update failed")
        return False
    
    # Step 4: Process and send email alerts
    print("\nStep 4: Processing email alerts...")
    if process_alerts():
        print("Email alert processing completed successfully")
    else:
        print("Email alert processing failed")
        # Continue execution even if alerts fail
    
    # Calculate and display execution time
    execution_time = time.time() - start_time
    print(f"\n=== Process completed in {execution_time:.2f} seconds ===")
    
    return True

if __name__ == "__main__":
    run_full_process()
