# nessus_connector.py
import requests
import os
from config import NESSUS_URL, ACCESS_KEY, SECRET_KEY, RAW_DATA_DIR

def get_nessus_data():
    """Connect to Nessus and download scan reports to the raw data directory"""
    print("\nConnecting to Nessus...")
    
    # Create headers with API keys
    headers = {'X-ApiKeys': f'accessKey={ACCESS_KEY}; secretKey={SECRET_KEY};'}
    
    # Create raw data directory if it doesn't exist
    os.makedirs(RAW_DATA_DIR, exist_ok=True)
    
    try:
        # Get list of scans
        response = requests.get(
            f"{NESSUS_URL}/scans", 
            headers=headers, 
            verify=False
        )
        
        # Check if request was successful
        if response.status_code == 200:
            scans = response.json()['scans']
            print(f"Found {len(scans)} scans")
            
            # Download each scan as CSV
            for scan in scans:
                scan_id = scan['id']
                scan_name = scan['name']
                
                print(f"Downloading scan: {scan_name} (ID: {scan_id})")
                
                # Request export
                export_response = requests.post(
                    f"{NESSUS_URL}/scans/{scan_id}/export",
                    headers=headers,
                    json={"format": "csv"},
                    verify=False
                )
                
                if export_response.status_code == 200:
                    file_id = export_response.json()['file']
                    
                    # Wait for export to be ready
                    status = "processing"
                    while status != "ready":
                        status_response = requests.get(
                            f"{NESSUS_URL}/scans/{scan_id}/export/{file_id}/status",
                            headers=headers,
                            verify=False
                        )
                        status = status_response.json()['status']
                    
                    # Download file
                    download_response = requests.get(
                        f"{NESSUS_URL}/scans/{scan_id}/export/{file_id}/download",
                        headers=headers,
                        verify=False
                    )
                    
                    # Save to file
                    file_path = os.path.join(RAW_DATA_DIR, f"{scan_name}_{scan_id}.csv")
                    with open(file_path, 'wb') as f:
                        f.write(download_response.content)
                    
                    print(f"Downloaded to: {file_path}")
                    
            return True
        else:
            print(f"Error connecting to Nessus: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    # Suppress certificate warnings
    from requests.packages import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    success = get_nessus_data()
    if success:
        print("Nessus data download completed successfully")
    else:
        print("Nessus data download failed")
