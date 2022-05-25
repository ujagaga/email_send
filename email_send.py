#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
To send email using Gmail, go to your gmail account setup, choose "Security" and turn on the 2 step verification.
Then click on "App passwords" and add any app name (e.g. PythonApp) to get an auto generated SENDER_PASSWORD. Use this SENDER_PASSWORD
(without spaces) as the email SENDER_PASSWORD.

The message can also be a json formatted string like:
"{'m':'<msg to send>', 'r':'<optional recipient email>', 's':'<optional email subject>', 'a':'<optional file list>'}"
"""

import json
import argparse
import smtplib
import ssl
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


SMTP_PORT = 587
SMTP_USE_STARTTLS = True
SENDER_EMAIL = "youremail@gmail.com"
SENDER_PASSWORD = "yourAppPass"
SMTP_SERVER = "smtp.gmail.com"
recipient = "some@default.recipient"
subject = "Notification from IOT Portal"
sender_name = "OC IOT portal"
CFG_FILE = "config.json"


def sendmail(message, msg_recipient=recipient, msg_subject=subject, attach_file_list=None):
    # Test if the message is a json object
    try:
        params = json.loads(message)
        txt_msg = params.get('m', '')
        msg_recipient = params.get('r', recipient)
        msg_subject = params.get('s', subject)
        attach_file_list = params.get('a', "")
    except:
        # Not a json object. Just use as is.
        txt_msg = message

    # Create a multipart message and set headers
    message = MIMEMultipart()
    message["From"] = SENDER_EMAIL
    message["To"] = msg_recipient
    message["Subject"] = msg_subject
    # Add body to email
    message.attach(MIMEText(txt_msg, "plain"))

    if attach_file_list is not None:
        file_list = attach_file_list.split(',')
        for file_path in file_list:
            file_path = file_path.strip()
            if os.path.isfile(file_path):
                # Open file in binary mode
                with open(file_path, "rb") as attachment:
                    # Add file as application/octet-stream
                    # Email client can usually download this automatically as attachment
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(attachment.read())

                # Encode file in ASCII characters to send by email
                encoders.encode_base64(part)

                # Add header as key/value pair to attachment part
                file_name = os.path.basename(file_path)
                part.add_header(
                    "Content-Disposition",
                    f"attachment; filename= {file_name}",
                )

                # Add attachment to message and convert message to string
                message.attach(part)

    text = message.as_string()

    context = ssl.create_default_context()

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            if SMTP_USE_STARTTLS:
                server.starttls(context=context)
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, msg_recipient, text)
            server.close()

            return "OK"
    except Exception as e:
        return "ERROR: {}".format(e)


def load_config():
    global SMTP_PORT
    global SENDER_EMAIL
    global SENDER_PASSWORD
    global SMTP_SERVER
    global SMTP_USE_STARTTLS

    file_path = os.path.realpath(__file__)
    config_file = os.path.join(os.path.dirname(file_path), CFG_FILE)
    if not os.path.isfile(config_file):
        with open(config_file, "w") as cfile:
            data = {
                "smtp_port": SMTP_PORT,
                "smtp_server": SMTP_SERVER,
                "smtp_user": SENDER_EMAIL,
                "smtp_pass": SENDER_PASSWORD,
                "use_starttls": SMTP_USE_STARTTLS
            }
            cfile.write(json.dumps(data))

    data = {}
    with open(config_file, "r") as cfile:
        data = json.loads(cfile.read())

    SMTP_PORT = data.get("smtp_port", SMTP_PORT)
    SMTP_SERVER = data.get("smtp_server", SMTP_SERVER)
    SENDER_EMAIL = data.get("smtp_user", SENDER_EMAIL)
    SENDER_PASSWORD = data.get("smtp_pass", SENDER_PASSWORD)
    SMTP_USE_STARTTLS = data.get("smtp_pass", SMTP_USE_STARTTLS)


if __name__ == '__main__':
    load_config()

    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--message", help="Text message to send.", required=False)
    parser.add_argument("-s", "--subject", help='Subject of the email. Defaults to: "{}"'.format(subject),
                        required=False, default=subject)
    parser.add_argument("-r", "--recipient", help='Message recipient. Defaults to: "{}"'.format(recipient),
                        required=False, default=recipient)
    parser.add_argument("-a", "--attachment", help='Comma separated list of files to attach', required=False)

    args = parser.parse_args()

    recipient = args.recipient
    subject = args.subject

    if args.message is not None:
        status = sendmail(args.message, msg_recipient=recipient, msg_subject=subject, attach_file_list=args.attachment)
        print(status)
