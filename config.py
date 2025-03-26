# NOTE -- Comes with hardcoded values. This would normally be blank / have dummy values for the user to put in

# Make sure the Tenable Nessus port (8834 by default) is open on the Nessus machine's firewall
# Should be of the form https://<ip_address>:<Nessus_port>
NESSUS_URL = r'https://192.168.50.188:8834'

# Get these from the Tenable Nessus GUI at Settings-->My Account--->API Keys--->Generate. Generating new keys invalidates old ones
ACCESS_KEY = '8c04ecd4caca9fc56e0fa18e999712f6cb76396f0c033aebb7e51b7f548fc1b2'
SECRET_KEY = '29a489ce023cd2422354a369055ba4aa1a4f7365c4c74733e00b59c78ee079dc'

# List of folders whose scan reports should be aggregated. If blank, uses all folders except 'Trash'
FOLDERS = []
