#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
To send email using Gmail, go to your gmail account setup, choose "Security" and turn on the 2 step verification.
Then click on "App passwords" and add any app name (e.g. PythonApp) to get an auto generated SENDER_PASSWORD. Use this SENDER_PASSWORD
(without spaces) as the email SENDER_PASSWORD.

This script can send an email from the terminal and if run as a daemon, it will listen to "email" topic on a local
MQTT server and send what ever it receives (e.g mosquitto_pub -h localhost -t email -m "Some message to send").
It will also listen to an HTTP connection get request and send whatever arrives as a "m" parameter.
( e.g. http://localhost:5555/?m="Some%20message%20to%20send")

The message can also be a json formatted string like:
"{m:<msg to send>, r:<optional recipient email>, s:<optional email subject>}"

Before yopu start, make sure you have paho-mqtt library installed.
"""

import json
import argparse
import smtplib
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders


MQTT_RX_TOPIC = "email"
MQTT_TX_TOPIC = "email_response"
MQTT_SERVER_ADDR = "localhost"
MQTT_SERVER_PORT = 1883
HTTP_PORT = 5555
SMTP_PORT = 587
SMTP_USE_STARTTLS = True
SENDER_EMAIL = "youremail@gmail.com"
SENDER_PASSWORD = "yourAppPass"
SMTP_SERVER = "smtp.gmail.com"
recipient = "some@default.recipient"
subject = "Notification from IOT Portal"
sender_name = "OC IOT portal"
receiver = None
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


class MqttStatusReceiver:
    def __init__(self, host=MQTT_SERVER_ADDR, port=MQTT_SERVER_PORT, topic=MQTT_RX_TOPIC):
        self.host = host
        self.port = port
        self.topic = topic
        self.rx_msg = None

        self.client = mqtt.Client('email_sender')
        try:
            self.client.connect(host, port=port)
            self.client.on_connect = self.on_connect
            self.client.on_message = self.on_message
            self.client.loop_start()
        except:
            pass

    def on_connect(self, client, userdata, flags, rc):
        client.subscribe(self.topic)

    def on_message(self, client, userdata, msg):
        self.rx_msg = msg.payload.decode()
        if self.rx_msg is not None:
            response = sendmail(self.rx_msg)
            print(response)
            self.respond(response)

    def stop(self):
        self.client.disconnect()
        self.client.loop_stop()

    def respond(self, message):
        client = mqtt.Client('emailTx')
        client.connect(self.host, port=self.port)
        client.publish(MQTT_TX_TOPIC, message)


class HttpHandler(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_response()

        query = urlparse(self.path).query
        data_dict = parse_qs(query)

        try:

            msg_recipient = data_dict.get("r", [recipient])[0]
            msg_subject = data_dict.get("s", [subject])[0]
            msg_attachments = data_dict.get("a", [])[0]
            msg_text = data_dict["m"][0]

            result = sendmail(msg_text, msg_recipient=msg_recipient, msg_subject=msg_subject, attach_file_list=msg_attachments)
            self.wfile.write(result.encode('utf-8'))
        except:
            self.wfile.write("ERROR: No message text specified. Will not send email.".encode('utf-8'))


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
    parser.add_argument("-s", "--subject", help='Subject of the email. Defaults to: "{}"'.format(subject),
                        required=False, default=subject)
    parser.add_argument("-r", "--recipient", help='Message recipient. Defaults to: "{}"'.format(recipient),
                        required=False, default=recipient)
    parser.add_argument("-d", "--daemon", help='Run in background listening to local MQTT topic "email" with response '
                                               'on MQTT topic "email_response" and/or http get request on port {}. '
                                               'Valid values: m (use MQTT), h (use HTTP), mh (use both).'
                                               ''.format(HTTP_PORT), required=False, default="h")
    args = parser.parse_args()

    recipient = args.recipient
    subject = args.subject

    daemon_http = False
    daemon_mqtt = False
    if len(args.daemon) > 0:
        if args.daemon[0] == 'h':
            daemon_http = True
        elif args.daemon[0] == 'm':
            daemon_mqtt = True

        if len(args.daemon) > 1:
            if args.daemon[1] == 'h':
                daemon_http = True
            elif args.daemon[1] == 'm':
                daemon_mqtt = True

        if daemon_mqtt:
            try:
                import paho.mqtt.client as mqtt

                receiver = MqttStatusReceiver()
                if not daemon_http:
                    # Http server not requested, keep an infinite loop for MQTT
                    try:
                        while True:
                            pass
                    except:
                        pass
            except Exception as e:
                print("ERROR:", e)
                daemon_mqtt = False

        if daemon_http:
            # Run the http server
            server_address = ('0.0.0.0', HTTP_PORT)
            httpd = HTTPServer(server_address, HttpHandler)

            try:
                httpd.serve_forever()
            except:
                pass

            httpd.server_close()

        if daemon_mqtt:
            receiver.stop()
