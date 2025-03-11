# v0.1

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
NESSUS_URL = 'https://192.168.50.188:8834'

# Get these from the Tenable Nessus GUI at Settings-->My Account--->API Keys--->Generate. Generating new keys invalidates old ones
ACCESS_KEY = 'c0f9a8e531e747cfb55ff04c809b8e00f8b1711264e0f4a3f587e0c69cf47780'
SECRET_KEY = '355fa0f7f27a11282a7775bbe563a3665b2106de601c73a92ba16a21d8e5ea4e'

# X-ApiKeys HTTP header. This is in place of a username-password login
API_KEYS = {'X-ApiKeys': f'accessKey={ACCESS_KEY}; secretKey={SECRET_KEY};'}

# Suppress certificate verificaion warning when connecting to Nessus server
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

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

# Retrieve and print a list of scans
r = get('/scans')
print('scans:')
for scan in r['scans']:
    print('\t{}'.format(scan['name']))

# Initialize a list to store all scan data
all_scan_data = []

# Loop through each scan and aggregate the data
template_id = 197 # FIXME hardcoded
for scan in r['scans']:
    scan_id = scan['id']
    r = post(path=f'/scans/{scan_id}/export', payload={'format': 'csv', 'template_id': template_id})

    # A token is generated, use it to download the associated report
    token = r['token']
    r = get(path=f'/tokens/{token}/download', text=True)

    # Append the data to the list
    all_scan_data.append(r)

# Create a single CSV file to aggregate all scan data
dir = '.'  # Same directory as this Python script
filename = 'aggregated_scans.csv'
os.makedirs(dir, exist_ok=True)
file_path = os.path.join(dir, filename)

with open(file_path, 'w') as file:
    # Write each scan's data to the file
    for data in all_scan_data:
        file.write(data)
        file.write('\n')  # Add a newline between each scan's data
print(f'\nAggregated file created at: {file_path}')

# For readability
print()
