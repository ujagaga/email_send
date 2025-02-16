# Quick Mail

A simple service to help low-end devices to sends e-mail.
It is free to use with a limitation of default 10 recipient e-mail addresses for one account.
This is to prevent bots from spamming. If you need to reset the recipient history, there is a page for it.

You can find a running service at:

        http://quickmail.ujagaga.in.rs

## How to start

Install required python libraries:

        pip install flask pillow captcha
        
Rename config.py.example to config.py and edit necessary variables.
At first start, the admin user will be added to the database and an email sent to notify of the generated token.

## Sending an e-mail using HTTP GET request

To send an e-mail, just make a request at url of the app with parameters:

        http://<quickmail_url>/send?token=<your_user_token>&msg=<"HTML_safe_text_message"&to=<recipient_email>

## Running on a cgi based hosting

On your local machine you could run:

        python3 index.py

but on a cgi based hosting service, you would set up a python app via cpanel.
If the cpanel is not available, you would need to provide cgi_serve.py which is included here. 
A common pitfall is that this script must be executable, so:

        chmod +x cgi_serve.py

## TODO

- Make sure token is unique
