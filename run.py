# run.py

import os
import sys
import subprocess
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/run.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def ensure_directory_exists(directory):
    """Ensure a directory exists, create it if it doesn't"""
    if not os.path.exists(directory):
        os.makedirs(directory)
        logger.info(f"Created directory: {directory}")

def run_script(script_path):
    """Run a Python script and return success status"""
    try:
        logger.info(f"Running script: {script_path}")
        result = subprocess.run([sys.executable, script_path], check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running script {script_path}: {e}")
        return False

def main():
    # Create necessary directories
    ensure_directory_exists("logs")
    ensure_directory_exists("data/raw")
    ensure_directory_exists("data/processed")
    ensure_directory_exists("data/db")
    
    # Step 1: Download scan data from Nessus
    if run_script("scripts/nessus_connector.py"):
        logger.info("Successfully downloaded scan data from Nessus")
        
        # Step 2: Aggregate vulnerability data
        if run_script("scripts/vulnerability_aggregator.py"):
            logger.info("Vulnerability aggregation completed successfully")
            
            # Step 3: Connect to dashboard (prepare data for Grafana)
            if run_script("scripts/dashboard_connector.py"):
                logger.info("Dashboard connector completed successfully")
                
                # Step 4: Send email notifications (if enabled)
                if run_script("scripts/email_sender.py"):
                    logger.info("Email notifications sent successfully")
                else:
                    logger.error("Failed to send email notifications")
            else:
                logger.error("Dashboard connector failed")
        else:
            logger.error("Vulnerability aggregation failed")
    else:
        logger.error("Failed to download scan data from Nessus")

if __name__ == "__main__":
    logger.info("Starting vulnerability processing run")
    main()
    logger.info("Run completed")
