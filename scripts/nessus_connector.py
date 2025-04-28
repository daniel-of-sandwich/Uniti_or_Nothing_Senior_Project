# nessus_connector.py
import os
import sys
import requests
from requests.packages import urllib3
import pandas as pd
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import NESSUS_URL, ACCESS_KEY, SECRET_KEY, RAW_DATA_DIR, FOLDERS, KEEP_FEATURES

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

def get_nessus_data():
    """Connect to Nessus and download scan reports to the raw data directory"""
    print("\nConnecting to Nessus...")
    
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
        
        print(f"Using folders: {', '.join(folder_names)}")
        
        # Get folder IDs for selected folders
        folder_ids = []
        for folder in r_scans['folders']:
            if folder['name'] in folder_names:
                folder_ids.append(folder['id'])
        
        # Get scan IDs for vulnerability scans in selected folders
        scan_ids = []
        for scan in r_scans['scans']:
            if scan['folder_id'] in folder_ids and scan['scan_type'] == 'vuln':
                scan_ids.append(scan['id'])
        
        if not scan_ids:
            print("No vulnerability scans found in selected folders.")
            return False
        
        print(f"Found {len(scan_ids)} vulnerability scans to download.")
        
        # Request download tokens for each scan
        template_id = 197  # Required by Nessus API
        token_to_scan_id = {}
        for scan_id in scan_ids:
            r_export = post(f'/scans/{scan_id}/export', {'format': 'csv', 'template_id': template_id})
            if 'token' in r_export:
                token_to_scan_id[r_export['token']] = scan_id
        
        if not token_to_scan_id:
            print("Failed to get download tokens for any scans.")
            return False
        
        # Download each scan report
        for token, scan_id in token_to_scan_id.items():
            # Get scan name for the file
            scan_name = None
            for scan in r_scans['scans']:
                if scan['id'] == scan_id:
                    scan_name = scan['name']
                    break
            
            # Create filename with scan ID and name
            filename = f"{scan_id}_{scan_name.replace(' ', '_')}.csv"
            file_path = os.path.join(RAW_DATA_DIR, filename)
            
            print(f"Downloading scan: {scan_name} (ID: {scan_id})")
            
            # Download and save the CSV file
            r_download = get(f'/tokens/{token}/download', True)
            with open(file_path, 'w') as file:
                file.write(r_download)
            
            print(f"Downloaded to: {file_path}")
        
        print(f"Downloaded {len(token_to_scan_id)} scan reports successfully.")
        return True
        
    except Exception as e:
        print(f"Error connecting to Nessus: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = get_nessus_data()
    if success:
        print("Nessus data download completed successfully")
    else:
        print("Nessus data download failed :(")
