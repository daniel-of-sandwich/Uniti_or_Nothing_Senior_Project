# v0.8

# Uniti or Nothing team
# CIS-497-101 Spring 2025
# University of South Alabama

# Requirements---
# Python 3.11.x
# Python requests package
# Python pandas package

# Resources---
# Nessus API: https://<nessus_server_ip>:<nessus_port>/api
# Python requests library, API: https://pypi.org/project/requests, https://requests.readthedocs.io/en/latest/api
# Python os library: https://docs.python.org/3/library/os.html
# akinnane cyber-security-nessus GitHub repo: https://github.com/alphagov-mirror/cyber-security-nessus for get() and post() code
# Python sqlite3 library: https://docs.python.org/3/library/sqlite3.html
# Python pandas library to_csv function: https://pandas.pydata.org/docs/user_guide/10min.html#csv

# Tested and developed on Debian GNU/Linux 12 (bookworm) virtual machine running Python 3.11.2

######## Setup 1/2 ########

# Imports
import config # Local file config.py
import requests
from requests.packages import urllib3
from os import path, mkdir, remove
import csv
import pandas as pd
import numpy as np
import sqlite3
from shutil import copy2

# Get Nessus URL and API keys from config file
NESSUS_URL = config.NESSUS_URL
ACCESS_KEY = config.ACCESS_KEY
SECRET_KEY = config.SECRET_KEY

# X-ApiKeys HTTP header. This is in place of a username-password login
API_KEYS = {'X-ApiKeys': f'accessKey={ACCESS_KEY}; secretKey={SECRET_KEY};'}

# Suppress certificate verificaion warning when connecting to Nessus server (not required)
urllib3.disable_warnings(category=urllib3.exceptions.InsecureRequestWarning)

# Get folder list from config file
FOLDERS = config.FOLDERS

# Get features to keep from config file
KEEP_FEATURES = config.KEEP_FEATURES

# Filenames of sqlite3 databases holding working and current vulnerability data
WORKING_DB = 'working.db'
DISPLAY_DB = 'display.db'

######## Functions ########

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

# Create sqlite3 database and tables
def create_sqlite3_database(database_filename):
    db = None
    try:
        # Create and connect to sqlite3 database
        db = sqlite3.connect(database_filename)
        cursor = db.cursor()
        
        # Create Folder table
        create_folder_table_sql = '''
            CREATE TABLE Folder (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                [type] TEXT NOT NULL
            );
        '''
        cursor.execute(create_folder_table_sql)
        
        # Commit changes
        db.commit()

        # Create Scan table
        create_scan_table_sql = '''
            CREATE TABLE Scan (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                last_modification_date DATETIME NOT NULL,
                folder_id INTEGER NOT NULL,
                FOREIGN KEY (folder_id) REFERENCES Folder(id)
            );
        '''
        cursor.execute(create_scan_table_sql)

        # Commit changes
        db.commit()
        
        # Create Host table
        create_host_table_sql = '''
            CREATE TABLE Host (
                Host TEXT NOT NULL,
                scan_id INTEGER NOT NULL,
                new_host INTEGER NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES Scan(id),
                PRIMARY KEY (Host, scan_id)
            );
        '''
        cursor.execute(create_host_table_sql)
        
        # Commit changes
        db.commit()
        
        # Create Vulnerability table
        create_vulnerability_table_sql = '''
            CREATE TABLE Vulnerability (
                CVE TEXT,
                CVSS_v2_0_Base_Score REAL,
                Risk TEXT,
                [Host] TEXT,
                Protocol TEXT,
                Port INTEGER,
                Name TEXT,
                new_vuln INTEGER NOT NULL,
                scan_id INTEGER NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES Scan(id),
                FOREIGN KEY (Host) REFERENCES Host(Host)
            );
        '''
        cursor.execute(create_vulnerability_table_sql)

        # Commit changes
        db.commit()

    except sqlite3.Error as e:
        print(f'Error with table creation: {e}')
        # Rollback changes if there is an error
        if db:
            db.rollback()

    finally:
        # Close the database connection
        if db:
            db.close()

# Insert data into sqlite3 database tables. *_data arguments are lists of lists, or None to skip
def insert_data(database_filename, folder_data, scan_data, host_data, vulnerability_data):
    db = None
    try:
        # Connect to sqlite3 database
        db = sqlite3.connect(database_filename)
        cursor = db.cursor()

        # Insert data into Folder table
        if folder_data: # If not None
            insert_folder_data_sql = '''
                INSERT INTO Folder (id, name, type)
                VALUES (?, ?, ?)
            '''
            cursor.executemany(insert_folder_data_sql, folder_data)
            db.commit()

        # Insert data into Scan table
        if scan_data:
            insert_scan_data_sql = '''
                INSERT INTO Scan (id, name, scan_type, last_modification_date, folder_id)
                VALUES (?, ?, ?, ?, ?)
            '''
            cursor.executemany(insert_scan_data_sql, scan_data)
            db.commit()

        # Insert data into Host table
        if host_data: # If not None
            insert_host_data_sql = '''
                INSERT INTO Host (Host, scan_id, new_host)
                VALUES (?, ?, ?)
            '''
            cursor.executemany(insert_host_data_sql, host_data)
            db.commit()

        # Insert data into Vulnerability table
        if vulnerability_data:
            insert_vulnerability_data_sql = '''
                INSERT INTO Vulnerability (CVE, CVSS_v2_0_Base_Score, Risk, Host, Protocol, Port, Name, new_vuln, scan_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            '''
            cursor.executemany(insert_vulnerability_data_sql, vulnerability_data)
            db.commit()

    except sqlite3.Error as e:
        print(f'Error with data insertion: {e}')
        # Rollback changes if there is an error
        if db:
            db.rollback()

    finally:
        # Close the database connection
        if db:
            db.close()

######## Setup 2/2 ########

# Create new reports directory
reports_path = r'./reports'
if path.isdir(reports_path):
    try:
        remove(reports_path)
        mkdir(reports_path)
    except:
        None
else:
    mkdir(reports_path)

# Create WORKING_DB
create_sqlite3_database(WORKING_DB)

######## Find vulnerability scans in selected folders ########

# For readability
print()

# Get an array of folder names to export scan reports of
r_scans = get(r'/scans') # Contains scan and folder information
folder_names = []
# If there are no user-defined folders, use all folder names except 'Trash'
if (len(FOLDERS) == 0):
    # Get an array of all folder names
    for folder in r_scans['folders']:
        folder_names.append(folder['name'])

    # Remove 'Trash' from folder name list
    if 'Trash' in folder_names:
        folder_names.remove('Trash')
        
# If there are, use those
else:
    folder_names = FOLDERS

# Get id of each selected folder
folder_ids = []
for folder in r_scans['folders']:
    if folder['name'] in folder_names:
        folder_ids.append(folder['id'])

# Get id of each scan where scan_type is vuln in selected folders
scan_ids = []
for scan in r_scans['scans']:
    if scan['folder_id'] in folder_ids:
        if scan['scan_type'] == 'vuln':
            scan_ids.append(scan['id'])

######## Prepare vulnerability scan report downloads ########

# Request a download token for each selected scan
template_id = 197 # Not sure what this does, but it's what the scans have on the API
token_to_scan_id = {}
good_scan_ids = [] # scan_ids that have tokens
for scan_id in scan_ids:
    r_export = post(path=f'/scans/{scan_id}/export', payload={'format': 'csv', 'template_id': template_id})
    token = None
    try:
        # If a token exists for the scan_id
        token = r_export['token']
    except:
        # If it doesn't for whatever reason, keep token as None
        token = None
    if token: # If not None
        token_to_scan_id[token] = scan_id
        good_scan_ids.append(scan_id)

######## Download scan reports, prepare Vulnerability and partial Host table data ########

vulnerability_df = pd.DataFrame()
host_df = pd.DataFrame()

# For every scan report able to be downloaded
for token in token_to_scan_id:
    # Get scan_id, create filename and file path for the current token
    scan_id = token_to_scan_id[token]
    filename = f'{scan_id}.csv'
    file_path = path.join(reports_path, filename)
    
    # Download the selected scans to reports_path
    r_download = get(path=f'/tokens/{token}/download', text=True)
    with open(file_path, 'w') as file:
        file.write(r_download) # Overwrites if <token_id>.csv already exists
    
    # Import the downloaded CSV into a DataFrame
    df = pd.read_csv(file_path)
    
    # Remove unwanted features
    keep_features = [df_feature for df_feature in KEEP_FEATURES if df_feature in df.columns]
    df = df[keep_features]
    
    # Append and populate new_vuln feature, will update later
    df['new_vuln'] = 1
    
    # Append and populate scan_id feature
    df['scan_id'] = scan_id
    
    # Get Host values before removing info rows
    if host_df.empty:
        host_df = df[['Host', 'scan_id']]
    else:
        host_df = pd.concat([host_df, df[['Host', 'scan_id']]], axis=0)
    
    # Remove info rows (non-vulnerability)
    df = df[df['Risk'] != 'None']
    
    # Concat preprocessed DataFrame to vulnerability_df
    if vulnerability_df.empty:
        vulnerability_df = df
    else:
        vulnerability_df = pd.concat([vulnerability_df, df], axis=0)

# Replace periods, spaces in column names to underscores
vulnerability_df.columns = vulnerability_df.columns.str.replace('.', '_', regex=False)
vulnerability_df.columns = vulnerability_df.columns.str.replace(' ', '_', regex=False)

######## Prepare Scan table data ########

# Scan table features
features = ['id', 'name', 'scan_type', 'last_modification_date', 'folder_id']
scan_df = pd.DataFrame(columns=features)

# For every scan
for scan in r_scans['scans']:
    # If the scan was downloaded
    if scan['id'] in good_scan_ids:
        # Get scan values
        values = [scan['id'], scan['name'], scan['scan_type'], scan['last_modification_date'], scan['folder_id']]
        
        # Format features and values into a DataFrame
        features_values_dict = dict(zip(features,values))
        new_row = pd.DataFrame([features_values_dict])
        scan_df = pd.concat([scan_df, new_row], axis=0, ignore_index=True)

######## Prepare Folder table data ########

# Folder table features
features = ['id', 'name', 'type']
folder_df = pd.DataFrame(columns=features)

for folder in r_scans['folders']:
    # Get folder values
    values = [folder['id'], folder['name'], folder['type']]
    
    # Format features and values into a DataFrame
    new_row = pd.DataFrame([dict(zip(features, values))])
    folder_df = pd.concat([folder_df, new_row], axis=0, ignore_index=True)

######## Prepare Host table data ########

# Create host_df from unique Host values
host_df = host_df.drop_duplicates()

# Append and populate new_host feature, will update later
host_df['new_host'] = 1

######## Get previous Vulnerability and Host table data from DISPLAY_DB ########

d_vulnerability_df = pd.DataFrame()
d_host_df = pd.DataFrame()

# If DISPLAY_DB exists
if path.exists(DISPLAY_DB):
    # Download previous table data
    try:
        # Connect to DISPLAY_DB
        db = sqlite3.connect(DISPLAY_DB)
        cursor = db.cursor()
        
        # Get Vulnerability table data
        select_vulnerability_data_sql = '''
            SELECT *
            FROM Vulnerability;
        '''
        cursor.execute(select_vulnerability_data_sql)
        values = cursor.fetchall()
        features = [description[0] for description in cursor.description]
        d_vulnerability_df = pd.DataFrame(values, columns=features)
        d_vulnerability_df['new_vuln'] = 1 # For comparing later
        
        # Get Host table data
        select_host_data_sql = '''
            SELECT *
            FROM Host;
        '''
        cursor.execute(select_host_data_sql)
        values = cursor.fetchall()
        features = [description[0] for description in cursor.description]
        d_host_df = pd.DataFrame(values, columns=features)
        d_host_df['new_host'] = 1 # For comparing later

    except sqlite3.Error as e:
        print(f'Error with data retrieval: {e}')
        # Rollback changes if there is an error
        if db:
            db.rollback()

    finally:
        # Close the database connection
        if db:
            db.close()

######## Compare current and previous Vulnerability data ########

# Get features
features = vulnerability_df.columns.tolist()

# Mask is true where vulnerability_df row is in d_vulnerability_df
mask = vulnerability_df.set_index(features).index.isin(d_vulnerability_df.set_index(features).index)

# Where mask is true (vulnerability found previously), set new_vuln to 0 (not a new vulnerability)
vulnerability_df.loc[mask, 'new_vuln'] = 0

######## Compare current and previous Host data ########

# Get features
features = host_df.columns.tolist()

# Mask is true where host_df row is in d_host_df
mask = host_df.set_index(features).index.isin(d_host_df.set_index(features).index)

# Where mask is true (host found previously), set new_host to 0 (not a new host)
host_df.loc[mask, 'new_host'] = 0

######## Insert Host, Folder, Scan, Vulnerability data into WORKING_DB ########

insert_data(WORKING_DB, folder_df.values.tolist(), scan_df.values.tolist(), host_df.values.tolist(), vulnerability_df.values.tolist())

######## Replace DISPLAY_DB with WORKING_DB ########

# Grafana OSS looks at DISPLAY_DB
# Replace in one go so that Grafana never displays changing / in-progress values
try:
    copy2(WORKING_DB, DISPLAY_DB)
    remove(WORKING_DB)
except:
    print('Could not replace database file.')

# For readability
print()
