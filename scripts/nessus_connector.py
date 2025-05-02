# nessus_connector.py

import os
import sys
import requests
from requests.packages import urllib3
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import NESSUS_URL, ACCESS_KEY, SECRET_KEY, RAW_DATA_DIR, FOLDERS

def get(path, text=False):
    """GET request to Nessus"""
    if text:
        return requests.get(
            NESSUS_URL + path, 
            headers={'X-ApiKeys': f'accessKey={ACCESS_KEY}; secretKey={SECRET_KEY};'}, 
            verify=False
        ).text
    else:
        return requests.get(
            NESSUS_URL + path, 
            headers={'X-ApiKeys': f'accessKey={ACCESS_KEY}; secretKey={SECRET_KEY};'}, 
            verify=False
        ).json()

def post(path, payload):
    """POST request to Nessus"""
    return requests.post(
        NESSUS_URL + path, 
        headers={'X-ApiKeys': f'accessKey={ACCESS_KEY}; secretKey={SECRET_KEY};'}, 
        json=payload, 
        verify=False
    ).json()

def wait_for_export_status(scan_id, file_id, max_attempts=60, delay=2):
    """Wait for an export to be ready"""
    attempts = 0
    while attempts < max_attempts:
        status = get(f'/scans/{scan_id}/export/{file_id}/status')
        if status.get('status') == 'ready':
            return True
        time.sleep(delay)
        attempts += 1
    return False

def get_nessus_data():
    """Connect to Nessus and download scan reports to the raw data directory"""
    print("Connecting to Nessus...")
    
    # Create raw data directory if it doesn't exist
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    
    try:
        # Suppress certificate verification warning
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Get list of scans and folders
        r_scans = get('/scans')
        
        # Determine which folders to use
        folder_names = []
        if len(FOLDERS) == 0:
            # Get all folder names except 'Trash'
            for folder in r_scans['folders']:
                if folder['name'] != 'Trash':
                    folder_names.append(folder['name'])
        else:
            folder_names = FOLDERS
        
        # Get folder IDs for selected folders
        folder_ids = []
        for folder in r_scans['folders']:
            if folder['name'] in folder_names:
                folder_ids.append(folder['id'])
        
        # Get scan IDs for vulnerability scans in selected folders
        scan_ids = []
        scan_names = {}  # Store scan names for later use
        if 'scans' in r_scans:
            for scan in r_scans['scans']:
                if scan['folder_id'] in folder_ids and scan['scan_type'] == 'vuln':
                    scan_ids.append(scan['id'])
                    scan_names[scan['id']] = scan['name']
        
        if not scan_ids:
            print("No vulnerability scans found.")
            return False
        
        print(f"Found {len(scan_ids)} scans to download.")
        
        # Request download tokens for each scan
        template_id = 197  # Required by Nessus API
        export_data = {}
        for scan_id in scan_ids:
            try:
                r_export = post(f'/scans/{scan_id}/export', {'format': 'csv', 'template_id': template_id})
                if 'file' in r_export:
                    export_data[scan_id] = {
                        'file_id': r_export['file'],
                        'scan_name': scan_names.get(scan_id, f"scan_{scan_id}")
                    }
            except Exception as e:
                print(f"Error exporting scan {scan_id}")
        
        if not export_data:
            print("Failed to export any scans.")
            return False
        
        # Wait for exports to complete and download
        successful_downloads = 0
        for scan_id, data in export_data.items():
            file_id = data['file_id']
            scan_name = data['scan_name']
            
            # Wait for export to be ready
            if not wait_for_export_status(scan_id, file_id):
                continue
            
            # Create filename with scan ID and name
            safe_name = scan_name.replace(' ', '_').replace('/', '_').replace('\\', '_')
            filename = f"{scan_id}_{safe_name}.csv"
            file_path = os.path.join(RAW_DATA_DIR, filename)
            
            print(f"Downloading: {scan_name}")
            
            try:
                # Download the CSV file
                r_download = get(f'/scans/{scan_id}/export/{file_id}/download', True)
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(r_download)
                
                successful_downloads += 1
            except Exception as e:
                print(f"Error downloading scan {scan_name}")
        
        print(f"Downloaded {successful_downloads} scan reports.")
        
        # Wait for files to be fully written
        print("Writing to disk...")
        time.sleep(3)
        print("Done!")
        return True
        
    except Exception as e:
        print(f"Error connecting to Nessus: {e}")
        return False

if __name__ == "__main__":
    success = get_nessus_data()
    if success:
        print("Nessus data download completed successfully")
    else:
        print("Nessus data download failed")
