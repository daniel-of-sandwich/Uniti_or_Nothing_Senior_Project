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

# Imports for aggregation
import csv
import glob

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

# Specify the directory containing your CSV files
input_directory = r'[input directory folder path]'

# Find all CSV files in the specified directory
csv_files = glob.glob(os.path.join(input_directory, '*.csv'))

# Check if any CSV files were found
if not csv_files:
    print(f"No CSV files found in directory: {input_directory}")
    exit()

# Print found CSV files
print("Current CSV files:")
for file in csv_files:
    print(f"\t{os.path.basename(file)}")

# Open the output file
with open('aggregated_scans.csv', 'w', newline='', encoding='utf-8') as outfile:
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

print(f"\nAggregated CSV file created: aggregated_scans.csv")
print(f"Total files aggregated: {len(csv_files)}")
