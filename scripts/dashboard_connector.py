# dashboard_connector.py

import os
import sqlite3

# Database path
DB_DIR = "data/db"
DB_PATH = os.path.join(DB_DIR, "vulnerability_data.db")

def create_database():
    """Create SQLite database for Grafana to connect to"""
    print("\nCreating database for dashboard connection...")
    
    # Create directory if it doesn't exist
    os.makedirs(DB_DIR, exist_ok=True)
    
    # Connect to the SQLite database (creates it if it doesn't exist)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("Creating tables...")
    
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
    
    print("Adding sample data...")
    
    # Add sample data for testing
    cursor.execute('''
    INSERT INTO vulnerabilities (cve_id, risk, host, protocol, port, name, scan_date)
    VALUES 
    ('CVE-2024-5678', 'Critical', '192.168.1.101', 'tcp', 80, 'Remote Code Execution', '2025-03-15')
    ''')
    
    conn.commit()
    conn.close()
    
    print(f"Database created at: {DB_PATH}")
    return True

if __name__ == "__main__":
    create_database()
