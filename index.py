#!/usr/bin/env python3
from flask import Flask, request, render_template, flash, redirect, abort, session, send_file, url_for
from config import ADMIN_EMAIL, FLASK_APP_SECRET_KEY, MAX_RECIPIENT_HISTORY, MIN_TIMEOUT
from helper import (send_email, generate_captcha_text, generate_token, is_valid_email, init_db, get_user_from_db,
                    add_user, delete_user, update_user, get_pending_user_count)
import json
from captcha.image import ImageCaptcha
import io
from time import time

app = Flask(__name__)
app.config['SECRET_KEY'] = FLASK_APP_SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)


def check_auth():
    token = request.cookies.get('authToken')
    if token:
        user = get_user_from_db(token=token)
        if user:
            return True
        else:
            return False


@app.before_request
def check_token():
    init_db()
    excluded_routes = ['home', 'login', 'subscribe', 'static', 'send', 'generate_captcha']  # Add routes to exclude
    if request.endpoint in excluded_routes:
        return  # Skip checking the cookie

    if not check_auth():
        return redirect(url_for('login', next_url=request.endpoint))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        token = request.form.get("token")

        if email and token:
            user = get_user_from_db(email=email)

            if user["token"] == token:
                next_url = request.form.get('next_url')
                if next_url and next_url != 'None':
                    target_url = next_url
                else:
                    target_url = url_for('home')

                response = redirect(target_url)
                response.set_cookie("authToken", token, httponly=True, secure=True, samesite="Strict")
                return response
            else:
                flash("Invalid email or token.")
        else:
            flash("Both email and password are necessary to login.")

    next_url=request.args.get('next_url')
    return render_template('login.html', hide_nav=True, next_url=next_url)


@app.route("/logout", methods=["GET"])
def logout():
    response = redirect('/')
    response.set_cookie('authToken', '', expires=0)

    return response


@app.route("/captcha")
def generate_captcha():
    captcha_text = generate_captcha_text()
    session["captcha"] = captcha_text  # Store in session
    image = ImageCaptcha()
    data = image.generate(captcha_text)

    return send_file(io.BytesIO(data.read()), mimetype="image/png")


@app.route("/", methods=["GET"])
def home():
    authorized = check_auth()
    return render_template('home.html', authorized=authorized)


@app.route("/subscribe", methods=["GET", "POST"])
def subscribe():
    if request.method == "POST":
        user_input = request.form.get("captcha")
        if user_input and user_input.upper() == session.get("captcha"):
            email = request.form.get("email")
            if email:
                if get_pending_user_count() > MAX_RECIPIENT_HISTORY:
                    flash("Maximum number of pending users reached. Please try later.")
                else:
                    token = generate_token()
                    if add_user(email, token):
                        send_email(
                            recipient=ADMIN_EMAIL,
                            subject="New user signed up",
                            body=f"New user: {email} signed up for quick mail service."
                                 f"\nThe token generated for them is: {token}"
                                 f"\nApprove or remove: {request.host_url}admin"
                        )
                        flash("Email submitted. You will be contacted by the administrator as soon as possible.")
                    else:
                        flash("This e-mail is already registered.")
        else:
            flash("Invalid CAPTCHA. Try again!")

    return render_template('subscribe.html')


@app.route("/send", methods=["GET", "POST"])
def send():
    # Get parameters from request
    data = request.args if request.method == "GET" else request.form
    token, msg, recipient, subject = data.get("token"), data.get("msg"), data.get("to"), data.get("sub", "")

    if not token:
        abort(401, description="Missing token parameter")

    user = get_user_from_db(token=token)
    if not user:
        abort(401, description="Provided token was not found in our records.")

    last_timestamp = int(user["timestamp"])
    time_since_last_mail = time() - last_timestamp
    if time_since_last_mail < MIN_TIMEOUT:
        abort(406, description=f"Please wait another {int(MIN_TIMEOUT - time_since_last_mail)}s before trying again")

    if not msg:
        abort(400, description='Missing message to email as "msg" parameter')

    # Load allowed recipients
    try:
        allowed_recipients = json.loads(user.get("recipients", "[]"))
    except (json.JSONDecodeError, TypeError):
        allowed_recipients = []

    # Process recipients
    accepted_recipients, rejected_recipients = [], []
    requested_recipients = [r.strip() for r in recipient.split(",")] if recipient else allowed_recipients

    for r in requested_recipients:
        if not is_valid_email(r):
            rejected_recipients.append(r)
        elif r in allowed_recipients or len(allowed_recipients) < MAX_RECIPIENT_HISTORY:
            accepted_recipients.append(r)
            if r not in allowed_recipients:
                allowed_recipients.append(r)
        else:
            rejected_recipients.append(r)

    update_user(user["email"], recipients=json.dumps(allowed_recipients))

    if not accepted_recipients:
        abort(400, description=f"No valid recipients found. Rejected: {json.dumps(rejected_recipients)}")

    # Send emails
    for r in accepted_recipients:
        send_email(recipient=r, subject=subject, body=msg)

    # Response message
    ret_message = "OK"
    if rejected_recipients:
        ret_message += f". Some recipients were rejected: {json.dumps(rejected_recipients)}. They are either malformed or exceeded the {MAX_RECIPIENT_HISTORY} limit."

    return ret_message


@app.route("/clear_history", methods=["GET", "POST"])
def clear_history():
    user = None
    token = request.cookies.get('authToken')
    if token:
        user = get_user_from_db(token=token)

    if not user:
        return redirect('/login')

    if request.method == "POST":
        user_input = request.form.get("captcha")
        if user_input and user_input.upper() == session.get("captcha"):
            update_user(email=user["email"], recipients=[])
            flash("History cleared!")
            user = get_user_from_db(token=token)
        else:
            flash("Invalid CAPTCHA. Try again!")

    saved_recipients = user.get("recipients", "[]")  # Default to an empty list
    try:
        allowed_recipient_list = json.loads(saved_recipients)
    except (json.JSONDecodeError, TypeError):
        allowed_recipient_list = []

    return render_template('clear_history.html', authorized=True, recipients=allowed_recipient_list)


@app.route("/admin", methods=["GET"])
def admin():
    administrator = None
    token = request.cookies.get('authToken')
    if token:
        administrator = get_user_from_db(token=token)

    if not administrator or administrator['status'] != 'admin':
        return redirect('/login')

    email = request.args.get('email')
    command = request.args.get('cmd')

    if email and command:
        if command == 'd':
            delete_user(email)
        else:
            update_user(email, status='approved')
            user = get_user_from_db(email=email)
            body = (f"You have been approved for using Quick Mail service."
                    f"\nYour token is: {token}"
                    f"\nYou may use it to login to {request.host_url}login"
                    f"\n\nTo send an e-mail, you can use the following URL example:\n"
                    f'{request.host_url}send?token={token}&msg="Some test message"&to={email}&sub="Test mail subject"'
                    f"\n\nYou can also use a POST request with parameters in the request body."
                    f"\nOnce you send an e-mail, the recipient will be added to your recipient list. "
                    f'Up to {MAX_RECIPIENT_HISTORY} recipients will be saved, so if you omit the "to" parameter,'
                    f'the recipient list will be populated from the history. While this simplifies sending mail for you, '
                    f'it also prevents bots from using this service to spam a large number of e-mail addresses.'
                    )
            send_email(
                recipient=email,
                subject="Approved for Quick Mail",
                body=body
            )

        return redirect('/admin')

    users = get_user_from_db(exclude=administrator['email'])
    return render_template('admin.html', authorized=True, users=users)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
