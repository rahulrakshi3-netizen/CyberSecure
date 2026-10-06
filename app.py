import os
import hashlib
import hmac
import re
import socket
import urllib.parse
import sqlite3
import random
import secrets
import smtplib
import ssl
import datetime
import string
from collections import Counter
from functools import wraps
from io import BytesIO
from email.message import EmailMessage
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
import joblib
import tldextract
from werkzeug.security import generate_password_hash, check_password_hash
from fpdf import FPDF

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'false').lower() in (
    '1', 'true', 'yes', 'on',
)
app.config['HOST'] = os.environ.get('APP_HOST', '127.0.0.1')
app.config['PORT'] = int(os.environ.get('APP_PORT', '5000'))

# Load ML Model for Phishing Detection
model_path = os.path.join(os.path.dirname(__file__), 'model', 'phishing_model.pkl')
phishing_model = None
try:
    if os.path.exists(model_path):
        phishing_model = joblib.load(model_path)
    else:
        print("Warning: Phishing model not found. Please run model/train_model.py first.")
except Exception as e:
    print(f"Error loading model: {e}")

# Database connection and initialization
def get_db_connection():
    db_path = os.path.join(os.path.dirname(__file__), 'database.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT
        )
    ''')
    user_columns = {
        column['name'] for column in conn.execute("PRAGMA table_info(users)")
    }
    if 'email' not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email "
        "ON users(email COLLATE NOCASE) WHERE email IS NOT NULL"
    )
    conn.execute('''
        CREATE TABLE IF NOT EXISTS otp_challenges (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            code_hash TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            expires_at DATETIME NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip_address TEXT,
            status TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL,
            risk_level TEXT NOT NULL,
            score INTEGER NOT NULL,
            status TEXT NOT NULL,
            solution TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insert default admin and user
    admin = conn.execute("SELECT * FROM users WHERE username = 'admin'").fetchone()
    if not admin:
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                     ('admin', generate_password_hash('admin123'), 'admin'))
    user = conn.execute("SELECT * FROM users WHERE username = 'user'").fetchone()
    if not user:
        conn.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                     ('user', generate_password_hash('user123'), 'user'))
    conn.commit()
    conn.close()

init_db()

# Decorators for auth
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('otp_verified'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin' or not session.get('otp_verified'):
            flash("Admin access required.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def log_login_attempt(username, ip_address, status):
    conn = get_db_connection()
    conn.execute("INSERT INTO login_attempts (username, ip_address, status) VALUES (?, ?, ?)",
                 (username, ip_address, status))
    conn.commit()
    conn.close()

def log_scan(scan_type, target, result, risk_level, score, status, solution):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO scan_history (scan_type, target, result, risk_level, score, status, solution)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (scan_type, target, str(result), risk_level, score, status, solution))
    conn.commit()
    conn.close()

def pdf_text(value):
    return str(value).encode('latin-1', errors='replace').decode('latin-1')

def send_otp_email(recipient, otp):
    smtp_host = os.environ.get('SMTP_HOST')
    sender = os.environ.get('SMTP_FROM') or os.environ.get('SMTP_USERNAME')
    if not smtp_host or not sender:
        raise RuntimeError('SMTP_HOST and SMTP_FROM (or SMTP_USERNAME) must be configured.')

    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    smtp_username = os.environ.get('SMTP_USERNAME')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    if bool(smtp_username) != bool(smtp_password):
        raise RuntimeError('SMTP_USERNAME and SMTP_PASSWORD must both be configured.')

    message = EmailMessage()
    message['Subject'] = 'Your Cybersecurity Toolkit login code'
    message['From'] = sender
    message['To'] = recipient
    message.set_content(
        f'Your Cybersecurity Toolkit verification code is {otp}.\n\n'
        'This code expires in 5 minutes. If you did not request it, you can ignore this email.'
    )

    use_ssl = os.environ.get('SMTP_USE_SSL', '').lower() in ('1', 'true', 'yes')
    smtp_class = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    smtp_options = {'timeout': 15}
    if use_ssl:
        smtp_options['context'] = ssl.create_default_context()

    with smtp_class(smtp_host, smtp_port, **smtp_options) as server:
        if not use_ssl:
            server.ehlo()
            server.starttls(context=ssl.create_default_context())
            server.ehlo()
        if smtp_username:
            server.login(smtp_username, smtp_password)
        server.send_message(message)

def start_otp_challenge(user, email_override=None):
    email = user['email'] or email_override
    if not email:
        flash(
            'This account has no email address on file. Add an address to receive a verification code.',
            'danger',
        )
        return False

    otp = f"{secrets.randbelow(1_000_000):06d}"
    challenge_id = secrets.token_urlsafe(32)
    conn = get_db_connection()
    conn.execute("DELETE FROM otp_challenges WHERE user_id = ?", (user['id'],))
    conn.execute(
        "INSERT INTO otp_challenges (id, user_id, code_hash, expires_at) "
        "VALUES (?, ?, ?, datetime('now', '+5 minutes'))",
        (
            challenge_id,
            user['id'],
            hmac.new(
                app.secret_key.encode(),
                f'{challenge_id}:{otp}'.encode(),
                hashlib.sha256,
            ).hexdigest(),
        ),
    )
    conn.commit()
    conn.close()

    try:
        send_otp_email(email, otp)
    except (OSError, smtplib.SMTPException, RuntimeError, ValueError):
        app.logger.exception('Could not deliver login verification email.')
        conn = get_db_connection()
        conn.execute("DELETE FROM otp_challenges WHERE id = ?", (challenge_id,))
        conn.commit()
        conn.close()
        flash('Unable to send a verification email right now. Check mail configuration and try again.', 'danger')
        return False

    session['pending_user_id'] = user['id']
    session['pending_role'] = user['role']
    session['pending_username'] = user['username']
    session['otp_challenge_id'] = challenge_id
    if not user['email']:
        session['pending_email'] = email
    flash(f'A verification code was sent to {email}.', 'info')
    return True

def set_pending_login(user):
    session.clear()
    session['pending_user_id'] = user['id']
    session['pending_role'] = user['role']
    session['pending_username'] = user['username']

def find_login_user(email, admin_only=False):
    normalized_email = email.strip().lower()
    query = "SELECT * FROM users WHERE email = ? COLLATE NOCASE"
    parameters = [normalized_email]
    if admin_only:
        query += " AND role = 'admin'"
    conn = get_db_connection()
    user = conn.execute(query, parameters).fetchone()
    conn.close()
    return user

# --- Auth Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form['password']
        user = find_login_user(email)
        
        if user and check_password_hash(user['password'], password):
            set_pending_login(user)
            if start_otp_challenge(user):
                log_login_attempt(email, request.remote_addr, "Password accepted; OTP emailed")
                return redirect(url_for('otp'))
            log_login_attempt(email, request.remote_addr, "OTP delivery failed")
        else:
            log_login_attempt(email, request.remote_addr, "Failed")
            flash("Invalid email address or password.", "danger")
            
    return render_template('login.html', is_admin=False)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form['password']
        user = find_login_user(email, admin_only=True)
        
        if user and check_password_hash(user['password'], password):
            set_pending_login(user)
            if start_otp_challenge(user):
                log_login_attempt(email, request.remote_addr, "Admin password accepted; OTP emailed")
                return redirect(url_for('otp'))
            log_login_attempt(email, request.remote_addr, "Admin OTP delivery failed")
        else:
            log_login_attempt(email, request.remote_addr, "Failed (Admin)")
            flash("Invalid admin email address or password.", "danger")
            
    return render_template('login.html', is_admin=True)

@app.route('/login/email', methods=['GET', 'POST'])
def login_email():
    if 'pending_user_id' not in session or session.get('otp_verified'):
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute(
        "SELECT id, username, role, email FROM users WHERE id = ?",
        (session['pending_user_id'],),
    ).fetchone()
    conn.close()
    if user is None:
        session.clear()
        return redirect(url_for('login'))
    if user['email']:
        if start_otp_challenge(user):
            return redirect(url_for('otp'))
        return redirect(url_for('login'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
            flash('Enter a valid email address.', 'danger')
        else:
            conn = get_db_connection()
            email_in_use = conn.execute(
                "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE AND id != ?",
                (email, user['id']),
            ).fetchone()
            conn.close()
            if email_in_use:
                flash('That email address is already linked to another account.', 'danger')
            elif start_otp_challenge(user, email):
                log_login_attempt(
                    user['username'], request.remote_addr,
                    "Password accepted; OTP sent to new email",
                )
                return redirect(url_for('otp'))

    return render_template('login_email.html', username=user['username'])

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email', '').strip().lower()
        if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
            flash("Enter a valid email address.", "danger")
            return render_template('register.html', is_admin=False)
        
        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ? COLLATE NOCASE",
            (username, email),
        ).fetchone()
        
        if user:
            conn.close()
            flash("Username or email is already registered.", "danger")
        else:
            conn.execute(
                "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), 'user', email),
            )
            conn.commit()
            conn.close()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for('login'))
            
    return render_template('register.html', is_admin=False)

@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email', '').strip().lower()
        if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
            flash("Enter a valid email address.", "danger")
            return render_template('register.html', is_admin=True)
        
        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ? COLLATE NOCASE",
            (username, email),
        ).fetchone()
        
        if user:
            conn.close()
            flash("Username or email is already registered.", "danger")
        else:
            conn.execute(
                "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), 'admin', email),
            )
            conn.commit()
            conn.close()
            flash("Admin registration successful! Please login.", "success")
            return redirect(url_for('admin_login'))
            
    return render_template('register.html', is_admin=True)

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if 'pending_user_id' not in session or 'otp_challenge_id' not in session:
        return redirect(url_for('login'))
        
    if request.method == 'POST':
        user_otp = request.form.get('otp', '').strip()
        challenge_id = session['otp_challenge_id']
        conn = get_db_connection()
        challenge = conn.execute(
            "SELECT * FROM otp_challenges WHERE id = ? AND user_id = ? "
            "AND expires_at > CURRENT_TIMESTAMP AND attempts < 5",
            (challenge_id, session['pending_user_id']),
        ).fetchone()

        expected_hash = hmac.new(
            app.secret_key.encode(),
            f'{challenge_id}:{user_otp}'.encode(),
            hashlib.sha256,
        ).hexdigest()
        if challenge and hmac.compare_digest(challenge['code_hash'], expected_hash):
            pending_email = session.get('pending_email')
            if pending_email:
                try:
                    conn.execute(
                        "UPDATE users SET email = ? WHERE id = ? "
                        "AND (email IS NULL OR TRIM(email) = '')",
                        (pending_email, session['pending_user_id']),
                    )
                except sqlite3.IntegrityError:
                    conn.rollback()
                    conn.close()
                    session.clear()
                    flash(
                        'That email address was linked to another account. Log in again and use a different address.',
                        'danger',
                    )
                    return redirect(url_for('login'))
            conn.execute("DELETE FROM otp_challenges WHERE id = ?", (challenge_id,))
            conn.commit()
            conn.close()
            log_login_attempt(
                session['pending_username'], request.remote_addr, "Success"
            )
            session['user_id'] = session['pending_user_id']
            session['role'] = session['pending_role']
            session['username'] = session['pending_username']
            session['otp_verified'] = True
            
            # Clean up pending session vars
            session.pop('pending_user_id', None)
            session.pop('pending_role', None)
            session.pop('pending_username', None)
            session.pop('pending_email', None)
            session.pop('otp_challenge_id', None)
            
            flash("Login successful!", "success")
            if session['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            if challenge:
                conn.execute(
                    "UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ?",
                    (challenge_id,),
                )
                conn.commit()
            conn.close()
            log_login_attempt(
                session['pending_username'], request.remote_addr, "Failed OTP"
            )
            flash("Invalid or expired verification code.", "danger")
            
    return render_template('otp.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for('landing'))

# --- Admin Routes ---
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    total_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
    total_malware = conn.execute("SELECT COUNT(*) FROM scan_history WHERE status = 'Harmful'").fetchone()[0]
    login_attempts = conn.execute("SELECT * FROM login_attempts ORDER BY timestamp DESC LIMIT 50").fetchall()
    conn.close()
    
    return render_template('admin_dashboard.html', total_scans=total_scans, 
                           total_malware=total_malware, login_attempts=login_attempts)

# --- Core Routes ---
@app.route('/')
def landing():
    return render_template('landing.html')

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    total_scans = conn.execute("SELECT COUNT(*) FROM scan_history").fetchone()[0]
    total_malware = conn.execute(
        "SELECT COUNT(*) FROM scan_history WHERE status = 'Harmful'"
    ).fetchone()[0]
    average_score = conn.execute(
        "SELECT COALESCE(ROUND(AVG(score)), 0) FROM scan_history"
    ).fetchone()[0]
    risk_rows = conn.execute(
        "SELECT risk_level, COUNT(*) AS count FROM scan_history GROUP BY risk_level"
    ).fetchall()
    scan_type_rows = conn.execute(
        "SELECT scan_type, COUNT(*) AS count FROM scan_history "
        "GROUP BY scan_type ORDER BY count DESC"
    ).fetchall()
    daily_rows = conn.execute(
        "SELECT date(timestamp) AS day, COUNT(*) AS count FROM scan_history "
        "WHERE date(timestamp) >= date('now', '-6 days') "
        "GROUP BY date(timestamp) ORDER BY day"
    ).fetchall()
    today = datetime.date.fromisoformat(
        conn.execute("SELECT date('now')").fetchone()[0]
    )
    alerts = conn.execute(
        "SELECT scan_type, target, status, risk_level, score, solution, timestamp "
        "FROM scan_history WHERE status IN ('Harmful', 'Moderate') "
        "ORDER BY timestamp DESC LIMIT 5"
    ).fetchall()
    conn.close()

    risk_counts = {row["risk_level"]: row["count"] for row in risk_rows}
    scan_type_counts = {row["scan_type"]: row["count"] for row in scan_type_rows}
    daily_counts = {row["day"]: row["count"] for row in daily_rows}
    trend_labels = [
        (today - datetime.timedelta(days=offset)).isoformat()
        for offset in range(6, -1, -1)
    ]
    trend_values = [daily_counts.get(day, 0) for day in trend_labels]

    insights = []
    if total_scans == 0:
        insights.append("Run a scan to start building your security baseline.")
    else:
        high_risk = risk_counts.get("High", 0)
        medium_risk = risk_counts.get("Medium", 0)
        if high_risk:
            insights.append(
                f"{high_risk} high-risk finding(s) are recorded. Review the latest alerts and recommendations."
            )
        elif medium_risk:
            insights.append(
                f"{medium_risk} medium-risk finding(s) are recorded. Review them and confirm the recommended controls."
            )
        else:
            insights.append("No medium- or high-risk findings are currently recorded.")
        if scan_type_rows:
            insights.append(
                f"{scan_type_rows[0]['scan_type']} is the most frequently used analysis "
                f"({scan_type_rows[0]['count']} scan(s))."
            )
        insights.append(
            "Dashboard insights summarize recorded scan trends; phishing predictions are produced by the trained model."
        )

    return render_template(
        'index.html',
        total_scans=total_scans,
        total_malware=total_malware,
        average_score=average_score,
        risk_counts=risk_counts,
        scan_type_counts=scan_type_counts,
        trend_labels=trend_labels,
        trend_values=trend_values,
        alerts=alerts,
        insights=insights,
    )

@app.route('/password', methods=['GET', 'POST'])
@login_required
def password_check():
    result = None
    if request.method == 'POST':
        password = request.form['password']
        score = 0
        feedback = []

        if len(password) >= 8: score += 1
        else: feedback.append("Password should be at least 8 characters long.")
        
        if re.search(r"[a-z]", password) and re.search(r"[A-Z]", password): score += 1
        else: feedback.append("Include both lowercase and uppercase letters.")
        
        if re.search(r"\d", password): score += 1
        else: feedback.append("Include at least one number.")
        
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1
        else: feedback.append("Include at least one special character.")

        final_score = (score / 4) * 100
        
        if final_score == 100:
            risk = "Low"
            status = "Safe"
            solution = "No action needed."
        elif final_score >= 50:
            risk = "Medium"
            status = "Moderate"
            solution = "Add special characters or numbers to make it stronger."
        else:
            risk = "High"
            status = "Harmful"
            solution = "Password is too weak. Use a mix of uppercase, lowercase, numbers, and symbols. Minimum 8 characters."
            
        result = {"status": status, "score": int(final_score), "feedback": feedback, "solution": solution}
        log_scan("Password Analysis", "N/A (Hidden)", ", ".join(feedback) if feedback else "Strong", risk, int(final_score), status, solution)
        
    return render_template('password.html', result=result)

@app.route('/password_gen', methods=['GET', 'POST'])
@login_required
def password_gen():
    generated_password = None
    if request.method == 'POST':
        length = int(request.form.get('length', 12))
        use_upper = request.form.get('use_upper')
        use_lower = request.form.get('use_lower')
        use_digits = request.form.get('use_digits')
        use_special = request.form.get('use_special')

        characters = ""
        if use_upper: characters += string.ascii_uppercase
        if use_lower: characters += string.ascii_lowercase
        if use_digits: characters += string.digits
        if use_special: characters += "!@#$%^&*(),.?\":{}|<>"

        if not characters:
            characters = string.ascii_letters + string.digits + "!@#$%^&*()"

        generated_password = ''.join(random.choice(characters) for i in range(length))
        log_scan("Password Gen", "Generated", "Success", "Low", 100, "Safe", "Password Generated Successfully")

    return render_template('password_gen.html', generated_password=generated_password)

@app.route('/hash', methods=['GET', 'POST'])
@login_required
def file_hash():
    result = None
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file:
            content = file.read()
            md5_hash = hashlib.md5(content).hexdigest()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
            result = {
                "filename": file.filename,
                "md5": md5_hash,
                "sha1": sha1_hash,
                "sha256": sha256_hash
            }
            log_scan("File Hash Gen", file.filename, "Hashes Generated", "Low", 100, "Safe", "File hashed successfully")
            
    return render_template('hash.html', result=result)

@app.route('/integrity', methods=['GET', 'POST'])
@login_required
def file_integrity():
    result = None
    if request.method == 'POST':
        uploaded_file = request.files.get('file')
        expected_hash = request.form.get('expected_sha256', '').strip().lower()
        if uploaded_file is None or uploaded_file.filename == '':
            flash('Choose a file to verify.', 'danger')
        elif not re.fullmatch(r'[a-f0-9]{64}', expected_hash):
            flash('Enter a valid 64-character SHA-256 hash.', 'danger')
        else:
            actual_hash = hashlib.sha256(uploaded_file.read()).hexdigest()
            is_match = hmac.compare_digest(actual_hash, expected_hash)
            status = 'Safe' if is_match else 'Harmful'
            risk = 'Low' if is_match else 'High'
            solution = (
                'The file matches the supplied SHA-256 reference.'
                if is_match else
                'The file does not match the supplied reference. Confirm its source before using it.'
            )
            result = {
                'filename': uploaded_file.filename,
                'actual_hash': actual_hash,
                'status': status,
                'solution': solution,
            }
            log_scan(
                'File Integrity', uploaded_file.filename, actual_hash,
                risk, 100 if is_match else 0, status, solution,
            )
    return render_template('integrity.html', result=result)

@app.route('/logs', methods=['GET', 'POST'])
@login_required
def security_log_analysis():
    result = None
    if request.method == 'POST':
        uploaded_file = request.files.get('file')
        if uploaded_file is None or uploaded_file.filename == '':
            flash('Choose a text log file to analyze.', 'danger')
        else:
            content = uploaded_file.read(1_000_001)
            if len(content) > 1_000_000:
                flash('Log files must be 1 MB or smaller.', 'danger')
            else:
                try:
                    text = content.decode('utf-8')
                except UnicodeDecodeError:
                    flash('The log file must be UTF-8 encoded text.', 'danger')
                else:
                    lines = [line.strip() for line in text.splitlines() if line.strip()]
                    failed_auth = [
                        line for line in lines
                        if re.search(r'failed|denied|unauthorized|invalid login', line, re.I)
                    ]
                    errors = [
                        line for line in lines
                        if re.search(r'\b(error|critical|fatal)\b', line, re.I)
                    ]
                    warnings = [
                        line for line in lines
                        if re.search(r'\bwarning\b', line, re.I)
                    ]
                    event_total = len(failed_auth) + len(errors) + len(warnings)
                    risk = 'High' if failed_auth or errors else ('Medium' if warnings else 'Low')
                    status = 'Harmful' if risk == 'High' else ('Moderate' if risk == 'Medium' else 'Safe')
                    score = max(0, 100 - min(event_total * 10, 100))
                    solution = (
                        'Investigate failed or denied access and critical error events.'
                        if risk == 'High' else
                        'Review warning events and confirm they are expected.'
                        if risk == 'Medium' else
                        'No common warning, error, or failed-authentication patterns were found.'
                    )
                    result = {
                        'filename': uploaded_file.filename,
                        'line_count': len(lines),
                        'failed_auth_count': len(failed_auth),
                        'error_count': len(errors),
                        'warning_count': len(warnings),
                        'sample_events': (failed_auth + errors + warnings)[:10],
                        'status': status,
                        'score': score,
                        'solution': solution,
                    }
                    log_scan(
                        'Security Log Analysis', uploaded_file.filename,
                        f"{event_total} events in {len(lines)} non-empty lines",
                        risk, score, status, solution,
                    )
    return render_template('logs.html', result=result)

@app.route('/network', methods=['GET', 'POST'])
@login_required
def network_scan():
    result = None
    if request.method == 'POST':
        target_ip = request.form['target_ip']
        ports = [21, 22, 80, 443, 3306, 8080]
        open_ports = []
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                res = sock.connect_ex((target_ip, port))
                if res == 0:
                    open_ports.append(port)
            except Exception:
                pass
            finally:
                sock.close()
                
        num_open = len(open_ports)
        if num_open == 0:
            score = 100
            status = "Safe"
            risk = "Low"
            solution = "No suspicious open ports detected."
        elif num_open <= 2:
            score = 60
            status = "Moderate"
            risk = "Medium"
            solution = "Review open ports and ensure they are necessary. Use firewalls to restrict access."
        else:
            score = 20
            status = "Harmful"
            risk = "High"
            solution = "Too many open ports. Immediately configure a firewall to block unused ports (e.g., 21, 3306) from public access."

        result = {"target": target_ip, "open_ports": open_ports, "score": score, "status": status, "solution": solution}
        log_scan("Port Scan", target_ip, f"Open Ports: {open_ports}", risk, score, status, solution)
        
    return render_template('network.html', result=result)

@app.route('/url', methods=['GET', 'POST'])
@login_required
def url_check():
    result = None
    if request.method == 'POST':
        url = request.form['url']
        parsed = urllib.parse.urlparse(url)
        
        issues = []
        if parsed.scheme != 'https':
            issues.append("URL does not use HTTPS.")
            
        if len(url) > 75:
            issues.append("URL is unusually long.")
            
        if "@" in url:
            issues.append("URL contains '@' symbol (often used to obscure target).")
            
        if len(issues) == 0:
            score = 100
            status = "Safe"
            risk = "Low"
            solution = "URL looks safe to visit."
        elif len(issues) == 1:
            score = 50
            status = "Moderate"
            risk = "Medium"
            solution = "Proceed with caution. " + " ".join(issues)
        else:
            score = 10
            status = "Harmful"
            risk = "High"
            solution = "Do not visit this URL. " + " ".join(issues)
        
        result = {"url": url, "status": status, "score": score, "issues": issues, "solution": solution}
        log_scan("URL Check", url, status, risk, score, status, solution)
        
    return render_template('url_check.html', result=result)

@app.route('/phishing', methods=['GET', 'POST'])
@login_required
def phishing_detect():
    result = None
    if request.method == 'POST':
        url = request.form['url']
        
        if phishing_model:
            url_length = len(url)
            has_special_chars = 1 if re.search(r"[-@_~?=&]", url) else 0
            
            ext = tldextract.extract(url)
            num_subdomains = len(ext.subdomain.split('.')) if ext.subdomain else 0
            
            is_https = 1 if url.startswith("https") else 0
            
            keywords = ['login', 'verify', 'update', 'secure', 'bank', 'account']
            has_suspicious_keywords = 1 if any(k in url.lower() for k in keywords) else 0
            
            features = [[url_length, has_special_chars, num_subdomains, is_https, has_suspicious_keywords]]
            prediction = phishing_model.predict(features)[0]
            
            if prediction == 1:
                score = 15
                status = "Harmful"
                risk = "High"
                solution = "This is a likely phishing attempt. Do not enter any personal credentials."
            else:
                score = 95
                status = "Safe"
                risk = "Low"
                solution = "URL appears legitimate based on our model."
            
            result = {"url": url, "status": status, "score": score, "features": features[0], "solution": solution}
            log_scan("Phishing Detect", url, status, risk, score, status, solution)
        else:
            flash("Machine learning model is not loaded. Please train it first.", "warning")
            
    return render_template('phishing.html', result=result)

@app.route('/history')
@login_required
def scan_history():
    conn = get_db_connection()
    history = conn.execute("SELECT * FROM scan_history ORDER BY timestamp DESC").fetchall()
    conn.close()
    return render_template('history.html', history=history)

@app.route('/download_report')
@login_required
def download_report():
    conn = get_db_connection()
    scans = conn.execute(
        "SELECT * FROM scan_history ORDER BY timestamp DESC"
    ).fetchall()
    conn.close()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Cybersecurity Toolkit Report", ln=True, align='C')
    pdf.set_font("Arial", size=10)
    pdf.cell(200, 10, txt=pdf_text(
        f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    ), ln=True, align='C')
    pdf.ln(10)

    counts = Counter(scan['status'] for scan in scans)
    average_score = (
        round(sum(scan['score'] for scan in scans) / len(scans))
        if scans else 0
    )
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 8, txt="Security Summary", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.cell(0, 7, txt=pdf_text(f"Total scans: {len(scans)}"), ln=True)
    pdf.cell(0, 7, txt=pdf_text(
        f"Safe: {counts.get('Safe', 0)}  Moderate: {counts.get('Moderate', 0)}  "
        f"Harmful: {counts.get('Harmful', 0)}"
    ), ln=True)
    pdf.cell(0, 7, txt=pdf_text(f"Average security score: {average_score}/100"), ln=True)
    pdf.ln(5)

    if not scans:
        pdf.cell(0, 8, txt="No scans have been recorded yet.", ln=True)
    else:
        for scan in scans:
            pdf.set_font("Arial", 'B', 11)
            pdf.multi_cell(
                0, 7,
                txt=pdf_text(
                    f"{scan['scan_type']} | {scan['status']} | "
                    f"Risk: {scan['risk_level']} | Score: {scan['score']}/100"
                ),
            )
            pdf.set_font("Arial", size=9)
            pdf.multi_cell(0, 6, txt=pdf_text(f"Date: {scan['timestamp']}"))
            pdf.multi_cell(0, 6, txt=pdf_text(f"Target: {scan['target']}"))
            pdf.multi_cell(0, 6, txt=pdf_text(f"Result: {scan['result']}"))
            pdf.multi_cell(
                0, 6, txt=pdf_text(f"Recommendation: {scan['solution'] or 'None'}")
            )
            pdf.ln(4)

    report_bytes = pdf.output(dest='S').encode('latin-1')
    report = BytesIO(report_bytes)
    report.seek(0)
    filename = f"cybersecurity-report-{datetime.date.today().isoformat()}.pdf"
    return send_file(
        report,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename,
    )

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

@app.route('/api/chat', methods=['POST'])
@login_required
def api_chat():
    data = request.json
    message = data.get('message', '').lower()
    
    response = "I'm a cybersecurity assistant. I can help with basic queries about phishing, passwords, ports, or securing your system. Ask me something!"
    
    if 'phishing' in message:
        response = "Phishing is a type of social engineering where an attacker sends a fraudulent message designed to trick a person into revealing sensitive information. Always check the sender's URL and don't click suspicious links."
    elif 'password' in message:
        response = "A strong password should be at least 12 characters long, include uppercase and lowercase letters, numbers, and special characters. Consider using a password manager!"
    elif 'port' in message or 'network' in message:
        response = "Open ports can be a security risk if not properly managed. Ensure you have a firewall blocking unnecessary ports from public access, especially ports like 21 (FTP), 23 (Telnet), and 3306 (MySQL)."
    elif 'malware' in message or 'virus' in message:
        response = "Malware is malicious software designed to harm or exploit systems. Keep your OS and antivirus updated, and avoid downloading files from untrusted sources."
    elif 'hello' in message or 'hi' in message:
        response = "Hello! How can I assist you with your cybersecurity needs today?"
        
    return jsonify({"response": response})

if __name__ == '__main__':
    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        debug=app.config['DEBUG'],
    )
