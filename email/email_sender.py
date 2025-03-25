import smtplib
from email.mine.multipart import MIMEMultipart
from email.mime.text import MIMEText

#Need to create this file - IMPORT CONFIG SETTINGS

from config import SMTP_SERVER , SMTP_USER, SMTP_PASSWORD

def send_vulnerability_alert(vulnerability_data, new_devices=None):

  #Send alert emails

  #Args:
    #vulnerability_data = dictionary
    ##new_devices = list

  #EMAIL SETTINGS
  sender = "vulnerability-alerts@uniti.com
  recipients = "gary.stu.grafana@gmail.com", "sb2233@jagmail.southalabama.edu"
  subject = "VULNERABILITY ALERT REPORT"

  #Create email contents:
  email_message = create_email_html(vulnerability_data, new_devices)

  #SEND EMAIL
  try:
    send_email(email_message, sender, subject, recipients)
    print("Alert email sent successfully!")
  except Exception as e:
    print(f"ERROR SENDING EMAIL: {e}")
    #FALLBACK TO CONSOLE
    print_email_debug(email_message, sender, subject, recipients)

def create_email_html(vulnerability_data, new_devices=None):



