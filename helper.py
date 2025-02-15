import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS

'''
Sends an email using configured credentials. 
'''
def send_email(recipient, subject, body):

    # Create message
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connect to SMTP server without SSL
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.ehlo()

        # Login to the SMTP server
        server.login(SMTP_USER, SMTP_PASS)

        # Send email
        server.sendmail(SMTP_USER, recipient, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"Error: {e}")
