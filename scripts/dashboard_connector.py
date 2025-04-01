# dashboard_connector.py
import os
import sqlite3
import pandas as pd
import sys
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join('..', 'logs', 'dashboard_connector.log')),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
PROCESSED_DATA_DIR = os.path.join('..', 'data', 'processed')
DB_DIR = os.path.join('..', 'data', 'db')
DB_PATH = os.path.join(DB_DIR, 'vulnerability_data.db')

def ensure_database_structure():
    """Ensure the database exists and has the correct structure"""
    try:
        # Create database directory if it doesn't exist
        os.makedirs(DB_DIR, exist_ok=True)
        
        # Connect to the SQLite database (creates it if it doesn't exist)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Create vulnerabilities table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            risk TEXT,
            host TEXT,
            protocol TEXT,
            port INTEGER,
            name TEXT,
            description TEXT,
            solution TEXT,
            scan_date TEXT,
            first_seen TEXT
        )
        ''')
        
        # Create new_devices table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS new_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            hostname TEXT,
            operating_system TEXT,
            scan_date TEXT,
            vulnerability_count INTEGER
        )
        ''')
        
        # Create scan_summary table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT,
            total_vulnerabilities INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,
            info_count INTEGER
        )
        ''')
        
        conn.commit()
        conn.close()
        
        return True
    except Exception as e:
        logger.error(f"Error ensuring database structure: {e}")
        return False

def update_database():
    """Update the database with the latest processed data"""
    try:
        # Ensure the database structure is correct
        if not ensure_database_structure():
            return False
        
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        
        # Update vulnerabilities table
        vulnerabilities_file = os.path.join(PROCESSED_DATA_DIR, 'vulnerabilities.csv')
        if os.path.exists(vulnerabilities_file):
            logger.info(f"Updating vulnerabilities from {vulnerabilities_file}")
            
            # Read the CSV file
            df_vulns = pd.read_csv(vulnerabilities_file)
            
            # Get existing vulnerabilities to avoid duplicates
            cursor = conn.cursor()
            cursor.execute("SELECT cve_id, host, scan_date FROM vulnerabilities")
            existing_vulns = set((cve, host, date) for cve, host, date in cursor.fetchall())
            
            # Filter out duplicates
            new_vulns = []
            for _, row in df_vulns.iterrows():
                key = (row['cve_id'], row['host'], row['scan_date'])
                if key not in existing_vulns:
                    new_vulns.append(row)
            
            # Insert new vulnerabilities
            if new_vulns:
                df_new_vulns = pd.DataFrame(new_vulns)
                df_new_vulns['first_seen'] = datetime.now().strftime('%Y-%m-%d')
                df_new_vulns.to_sql('vulnerabilities', conn, if_exists='append', index=False)
                logger.info(f"Added {len(new_vulns)} new vulnerabilities to database")
        
        # Update new devices table
        devices_file = os.path.join(PROCESSED_DATA_DIR, 'new_devices.csv')
        if os.path.exists(devices_file):
            logger.info(f"Updating new devices from {devices_file}")
            
            # Read the CSV file
            df_devices = pd.read_csv(devices_file)
            
            # Get existing devices to avoid duplicates
            cursor = conn.cursor()
            cursor.execute("SELECT ip_address, scan_date FROM new_devices")
            existing_devices = set((ip, date) for ip, date in cursor.fetchall())
            
            # Filter out duplicates
            new_devices = []
            for _, row in df_devices.iterrows():
                key = (row['ip_address'], row['scan_date'])
                if key not in existing_devices:
                    new_devices.append(row)
            
            # Insert new devices
            if new_devices:
                pd.DataFrame(new_devices).to_sql('new_devices', conn, if_exists='append', index=False)
                logger.info(f"Added {len(new_devices)} new devices to database")
        
        # Update scan summary table
        summary_file = os.path.join(PROCESSED_DATA_DIR, 'scan_summary.csv')
        if os.path.exists(summary_file):
            logger.info(f"Updating scan summaries from {summary_file}")
            
            # Read the CSV file
            df_summary = pd.read_csv(summary_file)
            
            # Get existing summaries to avoid duplicates
            cursor = conn.cursor()
            cursor.execute("SELECT scan_date FROM scan_summary")
            existing_summaries = set(date[0] for date in cursor.fetchall())
            
            # Filter out duplicates
            new_summaries = []
            for _, row in df_summary.iterrows():
                if row['scan_date'] not in existing_summaries:
                    new_summaries.append(row)
            
            # Insert new summaries
            if new_summaries:
                pd.DataFrame(new_summaries).to_sql('scan_summary', conn, if_exists='append', index=False)
                logger.info(f"Added {len(new_summaries)} new scan summaries to database")
        
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error updating database: {e}")
        return False

def main():
    logger.info("Starting dashboard connector")
    success = update_database()
    if success:
        logger.info("Database updated successfully")
    else:
        logger.error("Failed to update database")

if __name__ == "__main__":
    main()
