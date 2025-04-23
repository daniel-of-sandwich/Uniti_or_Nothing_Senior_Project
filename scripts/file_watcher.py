# file_watcher.py
import os
import time
import sys
import subprocess
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add scripts directory to path
scripts_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.append(scripts_dir)

# Import run script
import run

class CsvFileHandler(FileSystemEventHandler):
    """Handler for CSV file events"""
    
    def on_created(self, event):
        """Handle creation of CSV files"""
        if event.is_directory or not event.src_path.lower().endswith('.csv'):
            return
            
        print(f"\nNew CSV file detected: {event.src_path}")
        
        # Wait for file to be fully written
        time.sleep(2)
        
        # Run the process
        run.run_full_process()
    
    def on_modified(self, event):
        """Handle modification of CSV files"""
        if event.is_directory or not event.src_path.lower().endswith('.csv'):
            return
            
        print(f"\nModified CSV file detected: {event.src_path}")
        
        # Wait for file to be fully written
        time.sleep(2)
        
        # Run the process
        run.run_full_process()

def main():
    """Main function to watch for file changes"""
    # Raw data directory path
    raw_data_dir = os.path.join(os.path.dirname(scripts_dir), 'data', 'raw')
    
    # Create directory if it doesn't exist
    os.makedirs(raw_data_dir, exist_ok=True)
    
    print(f"\nWatching directory for CSV files: {raw_data_dir}")
    
    # Set up watchdog
    event_handler = CsvFileHandler()
    observer = Observer()
    observer.schedule(event_handler, raw_data_dir, recursive=False)
    observer.start()
    
    try:
        print("Waiting for new CSV files... (Press Ctrl+C to stop)")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("\nFile watcher stopped")
    
    observer.join()

if __name__ == "__main__":
    main()
