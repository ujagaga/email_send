import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASS, DB_FILE, ADMIN_EMAIL, DOMAIN
import sqlite3
import random
import string
import re

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
    except sqlite3.Error:
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