# dashboard_connector.py

import os
import sqlite3
import pandas as pd
import re
from datetime import datetime

# Get the base directory (project root)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Use absolute paths
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, 'data', 'processed')
DB_DIR = os.path.join(BASE_DIR, 'data', 'db')
DB_PATH = os.path.join(DB_DIR, 'vulnerability_data.db')

def create_database_if_not_exists():
    """Create SQLite database with tables designed to store vulnerability data"""
    # Create directory if it doesn't exist
    os.makedirs(DB_DIR, exist_ok=True)
    
    # Connect to the SQLite database (creates it if it doesn't exist)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create vulnerabilities table with batch_id for tracking aggregation runs
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_id TEXT,           -- Unique identifier for each aggregation run
        cve_id TEXT,
        cvss_score REAL,         -- Added CVSS score field
        risk TEXT,
        host TEXT,
        protocol TEXT,
        port INTEGER,
        name TEXT,
        scan_date TEXT,
        scan_name TEXT,          -- Added scan name field
        import_date TEXT         -- When this record was imported
    )
    ''')
    
    # Create new_devices table with batch_id
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS new_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_id TEXT,           -- Unique identifier for each aggregation run
        ip_address TEXT,
        scan_date TEXT,
        import_date TEXT,        -- When this record was imported
        vulnerability_count INTEGER
    )
    ''')
    
    # Create scan_summary table with batch_id
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scan_summary (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        batch_id TEXT,           -- Unique identifier for each aggregation run
        scan_date TEXT,
        scan_name TEXT,          -- Added scan name field
        import_date TEXT,        -- When this record was imported
        total_vulnerabilities INTEGER,
        critical_count INTEGER,
        high_count INTEGER,
        medium_count INTEGER,
        low_count INTEGER
    )
    ''')
    
    # Create batches table to track each aggregation run
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS batches (
        batch_id TEXT PRIMARY KEY,
        import_date TEXT,
        description TEXT
    )
    ''')
    
    # Commit changes
    conn.commit()
    conn.close()
    
    print(f"Database schema setup complete at: {DB_PATH}")
    return True

def update_database():
    """Update SQLite database with latest vulnerability data for Grafana"""
    try:
        print("\nUpdating dashboard database...")
        
        # Make sure database exists with proper schema
        create_database_if_not_exists()
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        
        # Generate a unique batch ID for this import run
        import_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        batch_id = datetime.now().strftime('batch_%Y%m%d_%H%M%S')
        
        # Record this batch in the batches table
        conn.execute(
            "INSERT INTO batches (batch_id, import_date, description) VALUES (?, ?, ?)",
            (batch_id, import_date, f"Automated import on {import_date}")
        )
        
        # Process vulnerability data
        vuln_file = os.path.join(PROCESSED_DATA_DIR, 'aggregated_vulnerabilities.csv')
        if os.path.exists(vuln_file):
            print(f"Loading vulnerability data from {vuln_file}")
            
            # Read CSV
            vulns_df = pd.read_csv(vuln_file)
            
            # Insert data
            if not vulns_df.empty:
                counter = 0  # Counter for successful CVE extractions
                
                for _, row in vulns_df.iterrows():
                    # Extract CVE ID - using multiple possible sources
                    cve_id = 'Unknown'
                    
                    # Try to get CVE from the CVE column if it exists
                    if 'CVE' in vulns_df.columns and pd.notna(row.get('CVE')) and str(row.get('CVE')).strip() != '':
                        cve_id = str(row['CVE'])
                        counter += 1
                    
                    # If that didn't work, try to extract it from Plugin Output
                    elif 'Plugin Output' in vulns_df.columns and pd.notna(row.get('Plugin Output')):
                        plugin_output = str(row['Plugin Output'])
                        # Look for CVE pattern (CVE-YYYY-NNNNN)
                        cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', plugin_output)
                        if cve_matches:
                            cve_id = cve_matches[0]  # Take the first match
                            counter += 1
                    
                    # If that didn't work, try the Description field
                    elif 'Description' in vulns_df.columns and pd.notna(row.get('Description')):
                        description = str(row['Description'])
                        # Look for CVE pattern
                        cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', description)
                        if cve_matches:
                            cve_id = cve_matches[0]  # Take the first match
                            counter += 1
                    
                    # If that didn't work, try the Name field
                    elif 'Name' in vulns_df.columns and pd.notna(row.get('Name')):
                        name = str(row['Name'])
                        # Look for CVE pattern
                        cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', name)
                        if cve_matches:
                            cve_id = cve_matches[0]  # Take the first match
                            counter += 1
                    
                    # Get CVSS score
                    cvss_score = 0.0
                    if 'CVSS_v2_0_Base_Score' in vulns_df.columns and pd.notna(row.get('CVSS_v2_0_Base_Score')):
                        try:
                            cvss_score = float(row['CVSS_v2_0_Base_Score'])
                        except (ValueError, TypeError):
                            pass
                    
                    # Get values with defaults for missing columns
                    risk = row.get('Risk', 'Unknown')
                    host = row.get('Host', '')
                    protocol = row.get('Protocol', '')
                    port = row.get('Port', 0) if pd.notna(row.get('Port')) else 0
                    name = row.get('Name', '')
                    scan_date = row.get('scan_date', '')
                    scan_name = row.get('scan_name', '')
                    
                    # Insert into database with batch_id and import_date
                    conn.execute(
                        "INSERT INTO vulnerabilities (batch_id, cve_id, cvss_score, risk, host, protocol, port, name, scan_date, scan_name, import_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (batch_id, cve_id, cvss_score, risk, host, protocol, port, name, scan_date, scan_name, import_date)
                    )
                
                print(f"Added {len(vulns_df)} vulnerability records to database")
                print(f"Successfully extracted {counter} CVE IDs")
        
        # Process new devices data
        devices_file = os.path.join(PROCESSED_DATA_DIR, 'new_devices.csv')
        if os.path.exists(devices_file):
            print(f"Loading new devices data from {devices_file}")
            
            # Read CSV
            devices_df = pd.read_csv(devices_file)
            
            # Insert data
            if not devices_df.empty:
                for _, row in devices_df.iterrows():
                    conn.execute(
                        "INSERT INTO new_devices (batch_id, ip_address, scan_date, vulnerability_count, import_date) VALUES (?, ?, ?, ?, ?)",
                        (batch_id, row['ip_address'], row['scan_date'], row['vulnerability_count'], import_date)
                    )
                print(f"Added {len(devices_df)} device records to database")
        
        # Process scan summary data
        summary_file = os.path.join(PROCESSED_DATA_DIR, 'scan_summary.csv')
        if os.path.exists(summary_file):
            print(f"Loading scan summary data from {summary_file}")
            
            # Read CSV
            summary_df = pd.read_csv(summary_file)
            
            # Insert data
            if not summary_df.empty:
                for _, row in summary_df.iterrows():
                    conn.execute(
                        "INSERT INTO scan_summary (batch_id, scan_date, scan_name, total_vulnerabilities, critical_count, high_count, medium_count, low_count, import_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (batch_id, row['scan_date'], row.get('scan_name', ''), row['total_vulnerabilities'], row['critical_count'], row['high_count'], row['medium_count'], row['low_count'], import_date)
                    )
                print(f"Added {len(summary_df)} scan summary records to database")
        
        # Commit changes and close connection
        conn.commit()
        conn.close()
        
        print("Database update completed successfully")
        print(f"Data imported with batch ID: {batch_id}")
        return True
        
    except Exception as e:
        print(f"Error updating database: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # Test the database functions
    update_database()
