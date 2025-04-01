# file_watcher.py
import os
import time
import subprocess
import sys
import logging
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/file_watcher.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
RAW_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'data', 'raw')
AGGREGATOR_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vulnerability_aggregator.py')
DASHBOARD_CONNECTOR_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'dashboard_connector.py')
EMAIL_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'email_sender.py')

# Keep track of processed files to avoid duplicate processing
processed_files = set()

def run_script(script_path):
    """Run a Python script and return success status"""
    try:
        logger.info(f"Running script: {script_path}")
        result = subprocess.run([sys.executable, script_path], check=True)
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        logger.error(f"Error running script {script_path}: {e}")
        return False

def process_data_pipeline():
    """Run the full data processing pipeline"""
    logger.info("Starting data processing pipeline")
    
    # Step 1: Aggregate vulnerability data
    if run_script(AGGREGATOR_SCRIPT):
        logger.info("Vulnerability aggregation completed successfully")
        
        # Step 2: Update dashboard data
        if run_script(DASHBOARD_CONNECTOR_SCRIPT):
            logger.info("Dashboard data updated successfully")
            
            # Step 3: Send email notifications (if enabled)
            if run_script(EMAIL_SCRIPT):
                logger.info("Email notifications sent successfully")
            else:
                logger.error("Failed to send email notifications")
        else:
            logger.error("Failed to update dashboard data")
    else:
        logger.error("Vulnerability aggregation failed")

class NewFileHandler(FileSystemEventHandler):
    """Handler for file system events"""
    
    def on_created(self, event):
        """Handle file creation events"""
        if event.is_directory:
            return
            
        # Check if the file has a .csv extension
        if not event.src_path.lower().endswith('.csv'):
            return
            
        # Get absolute path
        file_path = os.path.abspath(event.src_path)
        
        # Skip if already processed
        if file_path in processed_files:
            return
            
        logger.info(f"New file detected: {file_path}")
        
        # Wait a moment to ensure file is fully written
        time.sleep(2)
        
        # Add to processed files
        processed_files.add(file_path)
        
        # Run processing pipeline
        process_data_pipeline()
    
    def on_modified(self, event):
        """Handle file modification events"""
        if event.is_directory:
            return
            
        # Check if the file has a .csv extension
        if not event.src_path.lower().endswith('.csv'):
            return
            
        # Get absolute path
        file_path = os.path.abspath(event.src_path)
        
        # Only process files we haven't seen yet
        if file_path in processed_files:
            return
            
        logger.info(f"Modified file detected: {file_path}")
        
        # Wait a moment to ensure file is fully written
        time.sleep(2)
        
        # Add to processed files
        processed_files.add(file_path)
        
        # Run processing pipeline
        process_data_pipeline()

def initialize():
    """Initialize by processing existing files"""
    logger.info(f"Initializing file watcher for directory: {RAW_DATA_DIR}")
    
    # Get existing CSV files
    for filename in os.listdir(RAW_DATA_DIR):
        if filename.lower().endswith('.csv'):
            file_path = os.path.abspath(os.path.join(RAW_DATA_DIR, filename))
            processed_files.add(file_path)
    
    # Run initial processing if files exist
    if processed_files:
        logger.info(f"Found {len(processed_files)} existing CSV files")
        process_data_pipeline()
    else:
        logger.info("No existing CSV files found")

def main():
    # Initialize by processing existing files
    initialize()
    
    # Set up the file system observer
    event_handler = NewFileHandler()
    observer = Observer()
    observer.schedule(event_handler, RAW_DATA_DIR, recursive=False)
    observer.start()
    
    logger.info(f"File watcher started for directory: {RAW_DATA_DIR}")
    logger.info("Waiting for new CSV files...")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        logger.info("File watcher stopped by user")
    
    observer.join()

if __name__ == "__main__":
    main()
