# dashboard_connector.py

import os
import pandas as pd
import sqlite3
from datetime import datetime
import sys
import logging

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('../logs/dashboard_connector.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Import configuration
sys.path.append('../config')
import config

def create_database():
    """Create SQLite database for Grafana to connect to"""
    try:
        # Create the database directory if it doesn't exist
        os.makedirs(config.DB_DIR, exist_ok=True)
        
        # Connect to the SQLite database (creates it if it doesn't exist)
        conn = sqlite3.connect(config.DB_PATH)
        cursor = conn.cursor()
        
        # Create vulnerabilities table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            plugin_id TEXT,
            cve_id TEXT,
            cvss_score REAL,
            risk TEXT,
            host TEXT,
            protocol TEXT,
            port INTEGER,
            name TEXT,
            description TEXT,
            solution TEXT,
            scan_date TEXT,
            first_seen TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create new_devices table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS new_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT,
            hostname TEXT,
            operating_system TEXT,
            scan_date TEXT,
            vulnerability_count INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create scan_summary table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_summary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_date TEXT,
            total_vulnerabilities INTEGER,
            critical_count INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,
            info_count INTEGER,
            new_findings INTEGER,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        conn.commit()
        logger.info("Database created successfully")
        return conn
    except Exception as e:
        logger.error(f"Error creating database: {e}")
        return None

def import_processed_data():
    """Import processed CSV data into SQLite database"""
    try:
        conn = create_database()
        if not conn:
            return False
        
        # Path to the processed CSV files
        vuln_file = os.path.join(config.PROCESSED_DATA_DIR, 'aggregated_vulnerabilities.csv')
        devices_file = os.path.join(config.PROCESSED_DATA_DIR, 'new_devices.csv')
        summary_file = os.path.join(config.PROCESSED_DATA_DIR, 'scan_summary.csv')
        
        # Import vulnerabilities data if file exists
        if os.path.exists(vuln_file):
            logger.info(f"Importing vulnerability data from {vuln_file}")
            df_vulns = pd.read_csv(vuln_file)
            # Clear existing data before importing new data
            conn.execute("DELETE FROM vulnerabilities")
            df_vulns.to_sql('vulnerabilities', conn, if_exists='append', index=False)
        
        # Import new devices data if file exists
        if os.path.exists(devices_file):
            logger.info(f"Importing new devices data from {devices_file}")
            df_devices = pd.read_csv(devices_file)
            # Clear existing data before importing new data
            conn.execute("DELETE FROM new_devices")
            df_devices.to_sql('new_devices', conn, if_exists='append', index=False)
        
        # Import scan summary data if file exists
        if os.path.exists(summary_file):
            logger.info(f"Importing scan summary data from {summary_file}")
            df_summary = pd.read_csv(summary_file)
            # Clear existing data before importing new data
            conn.execute("DELETE FROM scan_summary")
            df_summary.to_sql('scan_summary', conn, if_exists='append', index=False)
        
        conn.commit()
        conn.close()
        logger.info("Data import completed successfully")
        return True
    except Exception as e:
        logger.error(f"Error importing data: {e}")
        return False

def main():
    logger.info("Starting dashboard connector")
    success = import_processed_data()
    if success:
        logger.info("Data successfully prepared for Grafana")
    else:
        logger.error("Failed to prepare data for Grafana")

if __name__ == "__main__":
    main()
