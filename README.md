# Cybersecurity Toolkit

A Flask-based, educational defensive security application that brings common security checks, scan history, visual analytics, and PDF reporting together in one interface.

## Features

- **Password analysis and generation:** Evaluate password composition and generate random passwords.
- **File security:** Generate MD5, SHA-1, and SHA-256 hashes, or compare a file's SHA-256 digest against a trusted reference to check integrity.
- **Authorized network analysis:** Check a small set of common TCP ports on a host you own or are authorized to assess.
- **URL security and phishing detection:** Apply basic URL checks and a scikit-learn Random Forest model using URL-derived features.
- **Security log analysis:** Review UTF-8 text logs (up to 1 MB) for common failed-authentication, warning, and error patterns.
- **Security dashboard:** View scan totals, average score, recent alerts, scan-type and risk charts, and trend-based security insights. The dashboard's insight text is generated from recorded scan statistics; it is not a generative AI service.
- **AI assistant:** Get basic cybersecurity guidance through the built-in intent-based assistant.
- **Scan history and PDF reports:** Review recorded scans and export a PDF summary with scan results and recommendations.
- **Authentication:** User and admin login flows with a six-digit OTP sent to the account email.

## Technology and data storage

- Python and Flask
- SQLite (`database.db`), initialized automatically by `app.py`
- scikit-learn, pandas, NumPy, and joblib for the phishing model
- Bootstrap, Chart.js, and Font Awesome in the web interface
- FPDF for PDF report generation

The current application uses SQLite. MySQL is not wired into the runtime; `database.sql` provides the SQLite table definitions.

## Requirements

- Python 3.9–3.12 (matches the pinned scientific Python dependencies)
- pip
- Network access in the browser for the Bootstrap, Chart.js, and Font Awesome CDN assets

## Setup and run

From the project directory:

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python model\train_model.py
python app.py
```

Alternatively, if the model file `model/phishing_model.pkl` is already present, you can skip model training.

### Configure application and email settings

The application loads settings from the `.env` file in the project directory when it starts. Edit that file with a long, random `SECRET_KEY`, your SMTP provider settings, and (if needed) the application host/port/debug settings. For Gmail, use a Google **App Password**, not your normal account password. Other providers should use their SMTP host, port, and credentials. Use `SMTP_USE_SSL=true` for an SSL-only SMTP server (commonly port 465); otherwise the app uses STARTTLS. Keep `FLASK_DEBUG=false` except during local development.

Keep `.env` private and never commit real credentials. Restart `app.py` after changing settings.

Open `http://127.0.0.1:5000/` in a browser and register with an email address you can access. The SQLite database and demo accounts are created on first startup. If an existing account has no email saved, a successful password check takes you to an email setup step. The app sends an OTP to the submitted address and links it to that account only after the OTP is verified. Demo credentials are for local evaluation only; replace or remove them before exposing the app to other users.

### Demo login credentials

The app creates these accounts on first startup if they do not already exist:

| Login page | Username | Password |
|---|---|---|
| Admin Login (`/admin/login`) | `admin` | `admin123` |
| User Login (`/login`) | `user` | `user123` |

Sign in using the account's **registered email address** and password; usernames are not accepted on the login forms. Both accounts require email OTP verification. Existing accounts need an email saved in the `users.email` database field before they can sign in this way. To set an address for the initial admin account, stop the app and run this command from the project folder, replacing the address with an email you control:

```powershell
python -c "import sqlite3; c=sqlite3.connect('database.db'); c.execute('UPDATE users SET email=? WHERE username=?', ('you@example.com', 'admin')); c.commit(); c.close()"
```

For a different existing account, replace `admin` with its account username. Change or remove the demo passwords before exposing the application to other users.

## Reports and history

The report download is available to authenticated users and contains the application's recorded scan history, a status summary, and recommendations. The current database schema does not associate scans with individual accounts, so history, dashboard metrics, and reports are shared across users on the local instance.

## Safety and limitations

- Use network analysis only against systems for which you have explicit authorization.
- The phishing model is trained using a small synthetic demonstration dataset. Its predictions are not a substitute for threat intelligence or a production detection system.
- The log analyzer uses simple keyword patterns and does not perform full log-format parsing or anomaly detection.
- The dashboard's trend insights are deterministic summaries of local scan records; there is no external AI API.
- This project is intended for education and defensive analysis, not as a replacement for professional security tooling.
