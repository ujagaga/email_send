# Email send #

A Python script for simpler email sending from embedded devices and scripts.
I have my own home IOT ecosystem comprised of various WiFi devices on the same network. Most of them are low resource devices capable of performing an http get request or even an MQTT post.

The "email_send.py" is to be run in a one time mode with a text message as a parameter to send email to a predefined address using a predefined account. 
Run the script once to create a "config.json" file which you can then adjust to your needs.

The "email_send_daemon.py" can run in "daemon" mode. You can select HTTP and/or MQTT for access method. If you choose HTTP, the script will keep running an http server listening on port 5555 by default, 
but you can change it in the script. Then just make a simple GET request with parameters to use for email like:


	<script_ip>:5555/?m="Some message text"&r="optional@recipient.email"&s="email subject"&a="list of attachments"
	
	
If you use MQTT, it will subscribe to a local MQTT server on default port 1883, on topic "email" and respond via post to topic "email_response".

The message text (on both http and MQTT) can be a simple string or a Json formated string to override the subject and/or recipient like:


	mosquitto_pub -h <script_host_ip> -m '{"m":"Some message to send", "r":"new@recipient.email", "s":"email subject", "a":"list of files to attach"}'


## How to start ##

If you intend to use the MQTT feature, make sure you have "paho-mqtt" Python library installed. 


	pip install paho-mqtt
	
	
Then run the script with "-h" parameter for help. This will give you an overview of parameters.


## Contact ##

* web: http://www.radinaradionica.com
* email: ujagaga@gmail.com

