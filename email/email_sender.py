import smtplib
from email.mine.multipart import MIMEMultipart
from email.mime.text import MIMEText
from config import SMTP_SERVER , SMTP_USER, SMTP_PASSWORD

def send_vulnerability_alert(vulnerability_data, new_devices=None):

  #Send alert emails

  #============================================================================================================
  #EMAIL SETTINGS
  sender = "vulnerability-alerts@uniti.com
  recipients = "gary.stu.grafana@gmail.com", "sb2233@jagmail.southalabama.edu"
  subject = "VULNERABILITY ALERT REPORT"

  #Create email contents:
  email_message = create_email_html(vulnerability_data, new_devices)

#=============================================================================================================
  #SEND EMAIL
  try:
    send_email(email_message, sender, subject, recipients)
    print("Alert email sent successfully!")
  except Exception as e:
    print(f"ERROR SENDING EMAIL: {e}")
    #FALLBACK TO CONSOLE
    print_email_debug(email_message, sender, subject, recipients)

#================================================================================================================
#CREATE EMAIL CONTENTS
def create_email_html(vulnerability_data, new_devices=None):
  html = """
  <html>
  <head>
      <style>
          body {font-family: Arial, sans-serif; }
          table { border-collapse: collapse; width: 100%; }
          th, td { border: 1px solid #dddd; padding: 8px; text-align: left; }
          th { background-color: #ffffcc; }
          .critical { background-color: #ffdddd; }
          .high { background-color: #ffffccc; }
          .medium { background-color: #e6f3ff; }
          .low { background-color: #eafaea; }
          .header { background-color: #003366; color: white; padding: 10px; }
      </style>
  </head>
  <body>
      <div class="header">
           <h2>Vulnerability Alert Report</h2>
           <p>Generated On: """ + vulnerability_data.get('scan_date', '') + """</p>
      </div>

      <h3>Summary</h3>
      <p>
          Critical: """ + str(vulnerability_data.get('critical_count', 0)) + """ |
          High: """ + str(vulnerability_data.get('high_count', 0)) + """ |
          Medium: """ + str(vulnerability_data.get('medium_count', 0)) + """ |
          Low: """ + str(vulnerability_data.get('low_count', 0)) + """ |
      <p>
  """

