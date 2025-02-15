#!/usr/bin/env python3
from flask import Flask, request, render_template, flash, redirect, abort, session, send_file, url_for
import sqlite3
from config import ADMIN_EMAIL, DB_FILE, FLASK_APP_SECRET_KEY, DOMAIN, MAX_RECIPIENT_HISTORY
from helper import send_email
import json
import re
from captcha.image import ImageCaptcha
import random
import string
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = FLASK_APP_SECRET_KEY
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)

def generate_captcha_text():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))


def generate_token():
    return ''.join(random.choices(string.ascii_letters, k=32))


def is_valid_email(email):
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email))


def init_db():
    try:
        with sqlite3.connect(DB_FILE) as conn:
            create_table_sql_query = """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    status TEXT NOT NULL,
                    token TEXT,
                    recipients TEXT
                )
            """
            cursor = conn.cursor()
            cursor.execute(create_table_sql_query)

            conn.commit()

            token = generate_token()
            add_admin_sql_query = f"INSERT INTO users (email, status, token) VALUES ('{ADMIN_EMAIL}', 'admin', '{token}')"
            cursor.execute(add_admin_sql_query)

            conn.commit()

            send_email(
                recipient=ADMIN_EMAIL,
                subject="Your Admin Credentials",
                body=f"You have been added as Admin of {DOMAIN}. Your login token is:{token}"
            )
    except:
        pass


def get_user_from_db(email=None, token=None, exclude=None):
    one = True
    if email:
        sql_query = "SELECT * FROM users WHERE email = ? AND status != 'pending'"
        params = (email,)
    elif token:
        sql_query = "SELECT * FROM users WHERE token = ? AND status != 'pending'"
        params = (token,)
    else:
        if exclude:
            sql_query = "SELECT * FROM users WHERE email != ?"
            params = (exclude,)
        else:
            sql_query = "SELECT * FROM users"
            params = ()
        one = False

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row  # Enables dictionary-like row access
        cursor = conn.cursor()
        cursor.execute(sql_query, params)

        if one:
            data = cursor.fetchone()
            return dict(data) if data else None  # Convert row to dict if found
        else:
            data = cursor.fetchall()
            return [dict(row) for row in data]  # Convert each row to dict


def add_user(email, token):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("INSERT INTO users (email, status, token) VALUES (?, ?, ?)",
                           (email, "pending", token))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            pass

    return False


def delete_user(email):
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(f"DELETE FROM users WHERE email = '{email}'")
        conn.commit()


def update_user(email, status=None, recipients=None):
    if status:
        sql_query = f"UPDATE users SET status = '{status}' WHERE email = '{email}'"
    elif recipients is not None:
        sql_query = f"UPDATE users SET recipients = '{recipients}' WHERE email = '{email}'"
    else:
        return False

    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute(sql_query)
        conn.commit()

    return True

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
                target_url = request.form.get('next_url') or url_for('home')
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
    if request.method == "GET":
        token = request.args.get('token')
        msg = request.args.get('msg')
        recipient = request.args.get('to')
        subject = request.args.get('sub', "")
    else:
        token = request.form.get('token')
        msg = request.form.get('msg')
        recipient = request.form.get('to')
        subject = request.form.get('sub', "")

    if not token:
        abort(401, description="Missing token parameter")

    user = get_user_from_db(token=token)
    if not user:
        abort(401, description="Unauthorized. Provided token was not found in our records.")

    if not msg:
        abort(400, description='Missing message to email as "msg" parameter')

    rejected_recipient_list = []
    accepted_recipient_list = []

    # Load saved recipients from user data
    saved_recipients = user.get("recipients", "[]")  # Default to an empty list
    try:
        allowed_recipient_list = json.loads(saved_recipients)
    except  (json.JSONDecodeError, TypeError):
        allowed_recipient_list = []

    if recipient:
        requested_recipient_list = [r.strip() for r in recipient.split(",")]

        for test_item in requested_recipient_list:
            if not is_valid_email(test_item):
                rejected_recipient_list.append(test_item)
            elif test_item in allowed_recipient_list:
                accepted_recipient_list.append(test_item)
            elif len(allowed_recipient_list) < MAX_RECIPIENT_HISTORY:
                allowed_recipient_list.append(test_item)
                accepted_recipient_list.append(test_item)
            else:
                rejected_recipient_list.append(test_item)
    else:
        accepted_recipient_list = allowed_recipient_list

    update_user(user['email'], recipients=json.dumps(allowed_recipient_list))


    if not accepted_recipient_list:
        abort(400, description='No recipient specified in the quickmail request and none found in recorded history.')

    if len(accepted_recipient_list) == 0:
        ret_message = "ERROR. No valid recipient e-mail provided."
        if len(rejected_recipient_list) > 0:
            ret_message += f". Some recipients were rejected: {json.dumps(rejected_recipient_list)}. They are either malformed of you reached a limit of {MAX_RECIPIENT_HISTORY} allowed recipients"

        abort(400, description=ret_message)

    for recipient in accepted_recipient_list:
        send_email(
            recipient=recipient,
            subject=subject,
            body=msg
        )

    ret_message = "OK"
    if len(rejected_recipient_list) > 0:
        ret_message += f". Some recipients were rejected: {json.dumps(rejected_recipient_list)}. They are either malformed of you reached a limit of {MAX_RECIPIENT_HISTORY} allowed recipients"

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
            send_email(
                recipient=email,
                subject="Approved for Quick Mail",
                body=f"You have been approved for using Quick Mail service.\nYour token is: {user['token']}\nYou may use it to login to {request.host_url}login"
            )

        return redirect('/admin')

    users = get_user_from_db(exclude=administrator['email'])
    return render_template('admin.html', authorized=True, users=users)


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
