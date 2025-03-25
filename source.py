# v0.2

# Daniel Forbes

# Resources---
# Nessus API: https://<nessus_server_ip>:<port>/api
# Python requests library, API: https://pypi.org/project/requests, https://requests.readthedocs.io/en/latest/api
# Python os library: https://docs.python.org/3/library/os.html
# akinnane cyber-security-nessus GitHub repo: https://github.com/alphagov-mirror/cyber-security-nessus

# get(), post(), put() code taken and modified from akinnane cyber-security-nessus repo

# Tested on an Oracle VM VirtualBox Debian 12.9.0 virtual machine

# Imports
import requests
from requests.packages import urllib3
import os

# Nessus API stuff

# Make sure the Tenable Nessus port (8834 by default) is open on the Nessus server's firewall
NESSUS_URL = 'https://10.20.120.133:8834'

# Get these from the Tenable Nessus GUI at Settings-->My Account--->API Keys--->Generate. Generating new keys invalidates old ones
ACCESS_KEY = '8c04ecd4caca9fc56e0fa18e999712f6cb76396f0c033aebb7e51b7f548fc1b2'
SECRET_KEY = '29a489ce023cd2422354a369055ba4aa1a4f7365c4c74733e00b59c78ee079dc'

# X-ApiKeys HTTP header. This is in place of a username-password login
API_KEYS = {'X-ApiKeys': f'accessKey={ACCESS_KEY}; secretKey={SECRET_KEY};'}

# Suppress certificate verificaion warning when connecting to Nessus server
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

# List of folders whose scan reports should be aggregated
FOLDERS = []

# HTTP request functions

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

# PUT request to Nessus
#def put(path, payload, headers=None):
#    return requests.put(
#        NESSUS_URL + path, 
#        headers=headers if headers else API_KEYS, 
#        json=payload, 
#        verify=False
#    ).json()

# Retrieve and aggregate vulnerability scan reports
# FIXME finish, replace hardcoded values

# For readability
print()

# Retrieve and print a list of folders
#r = get('/folders')
#print('folders:')
#for folder in r['folders']:
#    print('\t{}'.format(folder['name']))

# Get an array of folder names to export scan reports of
r_folders_scans = get('/scans')
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

# FIXME delete -- print names of "vuln" scans
print('FIXME delete -- Scans of scan_type \"vuln\":')
for scan in r_folders_scans['scans']:
    if scan['id'] in scan_ids:
        print('\t{}'.format(scan['name']))

# Request a download token for each selected scan
template_id = 197 # CSV template
tokens = []
for scan_id in scan_ids:
    r_token = post(path=f'/scans/{scan_id}/export', payload={'format': 'csv', 'template_id': template_id})
    try:
        # If a token exists for the scan_id
        token = r_token['token']
    except:
        # If it doesn't, e.g. cancelled scan
        token = None
    if token:
        tokens.append(token)

# FIXME delete -- print tokens
print(tokens)

# Download the selected scans to destination_path
destination_path = './reports'
os.makedirs(destination_path, exist_ok=True)
for token in tokens:
    r_download = get(path=f'/tokens/{token}/download', text=True)
    filename = f'{token}.csv'
    file_path = os.path.join(destination_path, filename)
    with open(file_path, 'w') as file:
        file.write(r_download)
    print(f'File created at {file_path}')

# Empty the destination_path directory
#os.rmdir(destination_path)

# Request a report export
#scan_id = 11 # FIXME hardcoded
#template_id = 197 # FIXME hardcoded
#r = post(path=f'/scans/{scan_id}/export', payload={'format': 'csv', 'template_id': template_id})

# A token is generated, use it to download the associated report
#token = r['token']
#r = get(path=f'/tokens/{token}/download', text=True)

# Create a file from the downloaded report to be saved locally
#dir = '.' # Same directory as this Python script
#filename = 'test.csv'
#os.makedirs(dir, exist_ok=True)
#file_path = os.path.join(dir, filename)
#with open(file_path, 'w') as file:
#    file.write(r)
#print(f'\nFile created at: {file_path}')

# For readability
print()
