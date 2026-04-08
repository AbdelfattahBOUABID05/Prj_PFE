import os
os.environ['NO_PROXY'] = 'generativelanguage.googleapis.com,smtp.gmail.com'

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_cors import CORS
from datetime import datetime, timezone
import paramiko
from dotenv import load_dotenv
from werkzeug.utils import secure_filename  # ← add this
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from src.parser import parse_log_file
from config import Config
from models import db, User

load_dotenv()

app = Flask(__name__)
CORS(app)
app.config.from_object(Config)

# --- Auth / DB ---
db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None


def admin_required(fn):
    from functools import wraps

    @wraps(fn)
    @login_required
    def wrapper(*args, **kwargs):
        if not getattr(current_user, "is_admin", False):
            flash("Accès refusé: Admin uniquement.", "danger")
            return redirect(url_for("index"))
        return fn(*args, **kwargs)

    return wrapper


def ensure_default_admin():
    if User.query.count() > 0:
        return
    u = User(
        username=app.config.get("DEFAULT_ADMIN_USERNAME", "admin"),
        email=app.config.get("DEFAULT_ADMIN_EMAIL", "admin@local"),
        role="Admin",
    )
    u.set_password(app.config.get("DEFAULT_ADMIN_PASSWORD", "Admin@12345"))
    db.session.add(u)
    db.session.commit()

_gemini_model = None


def get_gemini_model():
    global _gemini_model
    if _gemini_model is not None:
        return _gemini_model

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("Missing GEMINI_API_KEY")

    import google.generativeai as genai
    genai.configure(api_key=api_key)
    _gemini_model = genai.GenerativeModel('gemini-1.5-flash')
    return _gemini_model

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

with app.app_context():
    db.create_all()
    ensure_default_admin()

# --- ROUTES DE NAVIGATION ---

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/details')
@login_required
def details():
    return render_template('details.html')

@app.route('/ssh')
@login_required
def ssh_page():
    return render_template('ssh_config.html')

@app.route('/report')
@login_required
def report_page():
    return render_template('report.html')

@app.route('/send-report-page')
@login_required
def send_report_page():
    return render_template('send_report.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == 'POST':
        username_or_email = (request.form.get('identifier') or "").strip()
        password = request.form.get('password') or ""

        if not username_or_email or not password:
            flash("Veuillez remplir tous les champs.", "danger")
            return redirect(url_for("login"))

        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()

        if not user or not user.check_password(password):
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

        login_user(user)
        flash("Connexion réussie.", "success")
        return redirect(url_for("index"))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
@admin_required
def register():
    if request.method == 'POST':
        username = (request.form.get('username') or "").strip()
        email = (request.form.get('email') or "").strip().lower()
        password = request.form.get('password') or ""
        confirm = request.form.get('confirm_password') or ""
        role = (request.form.get('role') or "Analyst").strip()

        if role not in ("Admin", "Analyst"):
            role = "Analyst"

        if not username or not email or not password:
            flash("Veuillez remplir tous les champs.", "danger")
            return redirect(url_for("register"))
        if password != confirm:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(url_for("register"))
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Utilisateur déjà existant (username ou email).", "danger")
            return redirect(url_for("register"))

        u = User(username=username, email=email, role=role)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        flash("Compte créé avec succès.", "success")
        return redirect(url_for("register"))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Vous êtes déconnecté.", "success")
    return redirect(url_for("login"))

# --- ROUTES API DE TRAITEMENT ---

def json_error(message: str, status_code: int = 500, *, code: str | None = None, details=None):
    payload = {"status": "error", "message": message}
    if code:
        payload["code"] = code
    if details is not None:
        payload["details"] = details
    return jsonify(payload), status_code


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def file_metadata(path: str):
    try:
        st = os.stat(path)
        return {
            "file_size_bytes": int(st.st_size),
            "last_modified_utc": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        }
    except Exception:
        return {
            "file_size_bytes": None,
            "last_modified_utc": None,
        }


@app.route('/upload', methods=['POST'])  # ← NEW: missing upload route
@login_required
def upload_file():
    """ Handles local log file uploads """
    try:
        if 'file' not in request.files:
            return json_error("No file provided", 400, code="NO_FILE")

        file = request.files['file']
        if file.filename == '':
            return json_error("Empty filename", 400, code="EMPTY_FILENAME")

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        results = parse_log_file(filepath)
        meta = file_metadata(filepath)
        return jsonify({
            "status": "success",
            "generated_at": utc_now_iso(),
            "meta": {
                "source_type": "upload",
                "source_path": filepath,
                "server_ip": None,
                **meta
            },
            "segments": results,
            "stats": {
                "errors": len(results.get('ERROR', [])),
                "warnings": len(results.get('WARNING', [])),
                "info": len(results.get('INFO', [])),
                "total": sum(len(v) for v in results.values())
            }
        })
    except Exception as e:
        return json_error(str(e), 500, code="UPLOAD_FAILED")

@app.route('/ssh-analyze', methods=['POST'])
@login_required
def ssh_analyze():
    ssh = None
    try:
        data = request.get_json(silent=True) or {}
        ip = (data.get('ip') or "").strip()
        user = (data.get('username') or "").strip()
        pwd = data.get('password') or ""
        path = (data.get('path') or "/var/log/messages").strip()

        try:
            limit = int(data.get('limit', 100))
        except Exception:
            return json_error("Invalid limit", 400, code="INVALID_LIMIT")

        if not ip or not user or not pwd:
            return json_error("Missing SSH credentials", 400, code="MISSING_SSH_FIELDS")

        # Basic command-injection hardening: only allow safe path chars and clamp limit
        limit = max(1, min(limit, 5000))
        if any(c in path for c in [';', '&', '|', '`', '$', '>', '<', '\n', '\r']):
            return json_error("Invalid path", 400, code="INVALID_PATH")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=user, password=pwd, timeout=10, banner_timeout=10, auth_timeout=10)

        stdin, stdout, stderr = ssh.exec_command(f"tail -n {limit} {path}")
        log_content = stdout.read().decode('utf-8', errors='replace')
        error_content = stderr.read().decode('utf-8', errors='replace')

        if error_content:
            return json_error(error_content.strip(), 400, code="SSH_COMMAND_ERROR")

        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], "ssh_temp.log")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(log_content)

        results = parse_log_file(temp_path)
        meta = file_metadata(temp_path)
        return jsonify({
            "status": "success",
            "generated_at": utc_now_iso(),
            "meta": {
                "source_type": "ssh",
                "source_path": path,
                "server_ip": ip,
                **meta
            },
            "segments": results,
            "stats": {
                "errors": len(results.get('ERROR', [])),
                "warnings": len(results.get('WARNING', [])),
                "info": len(results.get('INFO', [])),
                "total": sum(len(v) for v in results.values())
            }
        })
    except paramiko.AuthenticationException:
        return json_error("Authentication failed", 401, code="SSH_AUTH_FAILED")
    except paramiko.SSHException as e:
        return json_error(str(e), 502, code="SSH_ERROR")
    except Exception as e:
        return json_error(str(e), 500, code="SSH_ANALYZE_FAILED")
    finally:
        try:
            if ssh:
                ssh.close()
        except Exception:
            pass

@app.route('/ai-analyze-line', methods=['POST'])
@login_required
def ai_analyze_line():
    try:
        data = request.get_json(silent=True) or {}
        log_line = data.get('line')
        if not log_line:
            return json_error("Missing 'line'", 400, code="MISSING_LINE")
        model = get_gemini_model()
        prompt = f"En tant qu'expert Linux, analyse ce log de Fedora et donne une solution : {log_line}"
        response = model.generate_content(prompt)
        return jsonify({"analysis": response.text})
    except Exception as e:
        return json_error(str(e), 500, code="AI_ANALYZE_FAILED")


def _smtp_send_with_fallback(sender_email: str, app_password: str, msg: MIMEMultipart):
    """
    Try Gmail SMTP with automatic fallback:
    - 465: SMTP_SSL
    - 587: SMTP + STARTTLS
    """
    last_err = None
    context = ssl.create_default_context()

    # Try SSL first (465)
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context, timeout=15) as server:
            server.login(sender_email, app_password)
            server.send_message(msg)
            return
    except Exception as e:
        last_err = e

    # Fallback to STARTTLS (587)
    try:
        with smtplib.SMTP('smtp.gmail.com', 587, timeout=15) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(sender_email, app_password)
            server.send_message(msg)
            return
    except Exception as e:
        raise e from last_err

@app.route('/send-email', methods=['POST'])
@login_required
def send_email():
    data = request.get_json(silent=True) or {}

    user_sender_email = (data.get('sender_email') or "").strip()
    user_app_password = data.get('app_password') or ""
    dest_email = (data.get('email') or data.get('dest_email') or "").strip()
    subject = (data.get('subject') or "Rapport LogAnalyzer").strip()
    comment = data.get('message') or ""
    report_data = data.get('report_data') or {}

    if not user_sender_email or not user_app_password or not dest_email:
        return json_error("Missing email fields", 400, code="MISSING_EMAIL_FIELDS")

    msg = MIMEMultipart()
    msg['From'] = user_sender_email
    msg['To'] = dest_email
    msg['Subject'] = subject

    stats = (report_data.get('stats') or {}) if isinstance(report_data, dict) else {}
    body = f"""
    Bonjour,
    
    Voici le résumé du rapport LogAnalyzer :
    - Total des logs: {stats.get('total', 'N/A')}
    - Erreurs: {stats.get('errors', 'N/A')}
    - Warnings: {stats.get('warnings', 'N/A')}
    
    Commentaire : {comment}
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        _smtp_send_with_fallback(user_sender_email, user_app_password, msg)
        return jsonify({"status": "success", "message": "Email envoyé avec succès !"})
    except Exception as e:
        return json_error(f"Erreur: {str(e)}", 500, code="SMTP_SEND_FAILED")

if __name__ == '__main__':
    app.run(debug=True, port=5000)