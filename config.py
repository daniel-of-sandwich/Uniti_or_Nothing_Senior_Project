# Make sure the Tenable Nessus port (8834 by default) is open or allowed on the host machine's firewall. Be wary of dynamic ip assignment -- this will likely change if not using a static ip
# Should be of the form https://<ip_address>:<Nessus_port>, e.g. r'https://192.168.0.1:8834'
NESSUS_URL = r''

# Get these from the Tenable Nessus GUI at Settings-->My Account--->API Keys--->Generate. Generating new keys invalidates old ones
ACCESS_KEY = ''
SECRET_KEY = ''

# List of folders whose scan reports should be aggregated. If empty, uses all folders except 'Trash'
FOLDERS = []

# List of features to keep from the exported scan report CSVs. If empty, keeps all features
KEEP_FEATURES = ['CVE', 'CVSS v2.0 Base Score', 'Risk', 'Host', 'Protocol', 'Port', 'Name']
# Available features using default Tenable Nessus CSV export settings:
# 'Plugin ID', 'CVE', 'CVSS v2.0 Base Score', 'Risk', 'Host', 'Protocol', 'Port', 'Name', 'Synopsis', 'Description', 'Solution', 'See Also', 'Plugin Output'
# IMPORTANT -- If changed, the sqlite3 'Vulnerability' table features will need to be altered as well as any code interacting with them

