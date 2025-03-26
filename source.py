# v0.5

# Uniti or Nothing team
# CIS-497-101 Spring 2025
# University of South Alabama

# Resources---
# Nessus API: https://<nessus_server_ip>:<port>/api
# Python requests library, API: https://pypi.org/project/requests, https://requests.readthedocs.io/en/latest/api
# Python os library: https://docs.python.org/3/library/os.html
# akinnane cyber-security-nessus GitHub repo: https://github.com/alphagov-mirror/cyber-security-nessus

# get(), post(), put() code taken and modified from akinnane cyber-security-nessus repo

# Tested on an Oracle VM VirtualBox Debian 12.9.0 virtual machine

# Imports
import config # Local file config.py
import requests
from requests.packages import urllib3
import os
import csv

# Get Nessus URL and API keys from config file
NESSUS_URL = config.NESSUS_URL
ACCESS_KEY = config.ACCESS_KEY
SECRET_KEY = config.SECRET_KEY

# X-ApiKeys HTTP header. This is in place of a username-password login
API_KEYS = {'X-ApiKeys': f'accessKey={ACCESS_KEY}; secretKey={SECRET_KEY};'}

# Suppress certificate verificaion warning when connecting to Nessus server
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

# Get folder list from config file
FOLDERS = config.FOLDERS

######### HTTP request functions #########

# GET request to Nessus
def get(path, text=False):
    if text:
        return requests.get(
            NESSUS_URL + path, 
            headers=API_KEYS, 
            verify=False
        ).text
    else:
        return requests.get(
            NESSUS_URL + path, 
            headers=API_KEYS, 
            verify=False
        ).json()

# POST request to Nessus
def post(path, payload, headers=None):
    return requests.post(
        NESSUS_URL + path, 
        headers=headers if headers else API_KEYS, 
        json=payload, 
        verify=False
    ).json()

######### Download vulnerability scan reports #########

# For readability
print()

# Get an array of folder names to export scan reports of
r_folders_scans = get(r'/scans')
folder_names = []
# If there are no user-defined folders, use all folder names except 'Trash'
if (len(FOLDERS) == 0):
    # Get an array of all folder names
    for folder in r_folders_scans['folders']:
        folder_names.append(folder['name'])

    # Remove 'Trash' from folder name list
    if 'Trash' in folder_names:
        folder_names.remove('Trash')
# If there are, use those
else:
    folder_names = FOLDERS

# Get id of each selected folder
folder_ids = []
for folder in r_folders_scans['folders']:
    if folder['name'] in folder_names:
        folder_ids.append(folder['id'])

# Get id of each scan where scan_type is vuln in selected folders
scan_ids = []
for scan in r_folders_scans['scans']:
    if scan['folder_id'] in folder_ids:
        if scan['scan_type'] == 'vuln':
            scan_ids.append(scan['id'])

# FIXME delete -- Print names of selected folders
print('FIXME delete -- Selected folders:')
for folder in r_folders_scans['folders']:
    if folder['id'] in folder_ids:
        print('\t{}:{}'.format(folder['id'], folder['name']))
print()

# FIXME delete -- Print names of "vuln" scans
print('FIXME delete -- Scans of scan_type \"vuln\":')
for scan in r_folders_scans['scans']:
    if scan['id'] in scan_ids:
        print('\t{}:{}'.format(scan['id'], scan['name']))
print()

# Request a download token for each selected scan
template_id = 197 # CSV template
token_id_pairs = {}
for scan_id in scan_ids:
    r_token = post(path=f'/scans/{scan_id}/export', payload={'format': 'csv', 'template_id': template_id})
    token = None
    try:
        # If a token exists for the scan_id
        token = r_token['token']
    except:
        # If it doesn't for whatever reason, keep token as None
        token = None
    if token: # If not None
        token_id_pairs[token] = scan_id

# Download the selected scans to destination_path. If latter does not exist, create directory
destination_path = r'./reports'
os.makedirs(destination_path, exist_ok=True)
for token in token_id_pairs:
    r_download = get(path=f'/tokens/{token}/download', text=True)
    filename = f'{token_id_pairs[token]}.csv' # Filename is scan_id
    file_path = os.path.join(destination_path, filename)
    with open(file_path, 'w') as file:
        file.write(r_download) # Overwrites if <token_id>.csv already exists
    print(f'File written at {file_path}') # FIXME -- delete

######## Aggregate reports into a single CSV file ########

# Specify the directory containing your CSV files
input_directory = r'./reports'

# Find all CSV files in the specified directory
filenames = os.listdir(input_directory)
csv_files = []
for filename in filenames:
    csv_files.append(input_directory + '/' + filename)

# Check if any CSV files were found
if not csv_files:
    print(f"No CSV files found in directory: {input_directory}")
    exit()

# Open the output file
agg_filename = 'aggregated_reports.csv'
with open(agg_filename, 'w', newline='', encoding='utf-8') as outfile:
    # Flag to write headers only once
    headers_written = False

    # Iterate through each CSV file
    for csv_file in csv_files:
        try:
            with open(csv_file, 'r', encoding='utf-8') as infile:
                reader = csv.reader(infile)
                # Write headers only for the first file
                if not headers_written:
                    headers = next(reader)
                    csv.writer(outfile).writerow(headers)
                    headers_written = True
                else:
                    # Skip headers for subsequent files
                    next(reader)
                # Write data rows
                for row in reader:
                    csv.writer(outfile).writerow(row)

        except Exception as e:
            print(f"Error reading file {os.path.basename(csv_file)}: {e}")
    
    # If there are no CSV files (no scans, maybe)
    if not csv_files:
        print(f"No CSV files found in directory {input_directory}. Is ./reports directory empty?")
    
print(f"\nFile written at ./{agg_filename}")
print(f"Total files aggregated: {len(csv_files)}")

# For readability
print()
