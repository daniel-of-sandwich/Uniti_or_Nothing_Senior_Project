# dashboard_connector.py

import os
import sqlite3
import pandas as pd
import re  # Add regex for CVE extraction

# Hardcode paths instead of importing from config
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DATA_DIR = os.path.join(BASE_DIR, 'data', 'processed')
DB_DIR = os.path.join(BASE_DIR, 'data', 'db')
DB_PATH = os.path.join(DB_DIR, 'vulnerability_data.db')

def create_database_if_not_exists():
    """Create SQLite database if it doesn't exist already"""
    # Create directory if it doesn't exist
    os.makedirs(DB_DIR, exist_ok=True)
    
    # Check if database already exists
    db_exists = os.path.exists(DB_PATH)
    
    # Connect to the SQLite database (creates it if it doesn't exist)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if not db_exists:
        print("\nCreating new database for dashboard connection...")
        
        # Create vulnerabilities table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT,
            risk TEXT,
            host TEXT,
            protocol TEXT,
            port INTEGER,
            name TEXT,
            scan_date TEXT
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
            vulnerability_count INTEGER
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
            low_count INTEGER
        )
        ''')
        
        print(f"Database created at: {DB_PATH}")
    else:
        print(f"\nUsing existing database at: {DB_PATH}")
    
    conn.commit()
    conn.close()
    return True

def update_database():
    """Update SQLite database with latest vulnerability data for Grafana"""
    try:
        print("\nUpdating dashboard database...")
        
        # Make sure database exists
        create_database_if_not_exists()
        
        # Connect to database
        conn = sqlite3.connect(DB_PATH)
        
        # Process vulnerability data
        vuln_file = os.path.join(PROCESSED_DATA_DIR, 'aggregated_vulnerabilities.csv')
        if os.path.exists(vuln_file):
            print(f"Loading vulnerability data from {vuln_file}")
            
            # Read CSV
            vulns_df = pd.read_csv(vuln_file)
            
            # Clear existing data
            conn.execute("DELETE FROM vulnerabilities")
            
            # Check if CSV contains a CVE column
            has_cve_column = 'CVE' in vulns_df.columns
            
            # Insert data
            if not vulns_df.empty:
                # Add rows to database
                counter = 0  # Counter for successful CVE extractions
                
                for _, row in vulns_df.iterrows():
                    # Extract CVE ID - using multiple possible sources
                    cve_id = 'Unknown'
                    
                    # Try to get CVE from the CVE column if it exists
                    if has_cve_column and pd.notna(row.get('CVE')) and str(row.get('CVE')).strip() != '':
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
                    
                    # Get values with defaults for missing columns
                    risk = row.get('Risk', 'Unknown')
                    host = row.get('Host', '')
                    protocol = row.get('Protocol', '')
                    port = row.get('Port', 0) if pd.notna(row.get('Port')) else 0
                    name = row.get('Name', '')
                    scan_date = row.get('scan_date', '')
                    
                    # Insert into database
                    conn.execute(
                        "INSERT INTO vulnerabilities (cve_id, risk, host, protocol, port, name, scan_date) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (cve_id, risk, host, protocol, port, name, scan_date)
                    )
                
                print(f"Added {len(vulns_df)} vulnerability records to database")
                print(f"Successfully extracted {counter} CVE IDs")
        
        # Process new devices data
        devices_file = os.path.join(PROCESSED_DATA_DIR, 'new_devices.csv')
        if os.path.exists(devices_file):
            print(f"Loading new devices data from {devices_file}")
            
            # Read CSV
            devices_df = pd.read_csv(devices_file)
            
            # Clear existing data
            conn.execute("DELETE FROM new_devices")
            
            # Insert data
            if not devices_df.empty:
                for _, row in devices_df.iterrows():
                    conn.execute(
                        "INSERT INTO new_devices (ip_address, hostname, operating_system, scan_date, vulnerability_count) VALUES (?, ?, ?, ?, ?)",
                        (row['ip_address'], row['hostname'], row['operating_system'], row['scan_date'], row['vulnerability_count'])
                    )
                print(f"Added {len(devices_df)} device records to database")
        
        # Process scan summary data
        summary_file = os.path.join(PROCESSED_DATA_DIR, 'scan_summary.csv')
        if os.path.exists(summary_file):
            print(f"Loading scan summary data from {summary_file}")
            
            # Read CSV
            summary_df = pd.read_csv(summary_file)
            
            # Clear existing data
            conn.execute("DELETE FROM scan_summary")
            
            # Insert data
            if not summary_df.empty:
                for _, row in summary_df.iterrows():
                    conn.execute(
                        "INSERT INTO scan_summary (scan_date, total_vulnerabilities, critical_count, high_count, medium_count, low_count) VALUES (?, ?, ?, ?, ?, ?)",
                        (row['scan_date'], row['total_vulnerabilities'], row['critical_count'], row['high_count'], row['medium_count'], row['low_count'])
                    )
                print(f"Added {len(summary_df)} scan summary records to database")
        
        # Commit changes and close connection
        conn.commit()
        conn.close()
        
        print("Database update completed successfully")
        return True
        
    except Exception as e:
        print(f"Error updating database: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # Test the database functions
    update_database()
