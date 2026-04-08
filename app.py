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
import json
from openai import OpenAI
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication

from src.parser import parse_log_file
from config import Config
from models import db, User, Analysis

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


def _looks_like_cursor_key(value: str | None) -> bool:
    return bool(value and str(value).strip().startswith("crsr_"))


def _resolve_ai_config():
    """
    Resolve API keys with backward compatibility:
    - CURSOR_API_KEY is preferred for Cursor endpoint.
    - If GEMINI_API_KEY contains a Cursor key (crsr_*), treat it as Cursor key.
    """
    raw_gemini = (os.getenv("GEMINI_API_KEY") or "").strip()
    raw_cursor = (os.getenv("CURSOR_API_KEY") or "").strip()
    raw_openai = (os.getenv("OPENAI_API_KEY") or "").strip()

    cursor_key = raw_cursor or (raw_gemini if _looks_like_cursor_key(raw_gemini) else "")
    gemini_key = "" if _looks_like_cursor_key(raw_gemini) else raw_gemini
    openai_key = raw_openai

    cursor_base = (os.getenv("CURSOR_API_BASE_URL") or "https://api.cursor.sh/v1").strip()
    cursor_model = (os.getenv("CURSOR_MODEL") or "gpt-4o-mini").strip()
    return {
        "cursor_key": cursor_key,
        "cursor_base": cursor_base,
        "cursor_model": cursor_model,
        "openai_key": openai_key,
        "openai_base": (os.getenv("OPENAI_BASE_URL") or "").strip() or None,
        "openai_model": (os.getenv("OPENAI_MODEL") or "gpt-4o-mini").strip(),
        "gemini_key": gemini_key,
    }


def get_gemini_model():
    global _gemini_model
    if _gemini_model is not None:
        return _gemini_model

    api_key = _resolve_ai_config().get("gemini_key")
    if not api_key:
        raise RuntimeError("Missing GEMINI_API_KEY")

    import google.generativeai as genai
    genai.configure(api_key=api_key)
    # Use stable model name directly (no explicit API version string).
    _gemini_model = genai.GenerativeModel("gemini-1.5-flash")
    return _gemini_model


def _openai_style_completion(*, api_key: str, base_url: str | None, model_name: str, prompt: str) -> str:
    """
    OpenAI-compatible completion helper.
    Works with Cursor/OpenAI-compatible endpoints when base_url is provided.
    """
    client_kwargs = {"api_key": api_key}
    if base_url:
        client_kwargs["base_url"] = base_url
    client = OpenAI(**client_kwargs)

    resp = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": "You are a senior SOC analyst."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.2,
    )
    return (resp.choices[0].message.content or "").strip()


def generate_security_summary_text(log_text: str) -> str:
    """
    Try Cursor/OpenAI-compatible endpoint first (if CURSOR_API_KEY provided),
    then OpenAI API key, then Gemini stable model.
    Returns raw model text (JSON expected by caller).
    """
    prompt = (
        "Analyze the following logs (any type: Auth/Web/System/App/Network).\n"
        "Focus on security threats, repeated patterns, anomalies, and risk.\n"
        "Return ONLY valid JSON with keys:\n"
        "ai_insights (string, 2-5 sentences), security_level (LOW|MEDIUM|HIGH|CRITICAL).\n\n"
        f"LOGS:\n{log_text}\n"
    )

    cfg = _resolve_ai_config()

    # 1) Cursor/OpenAI-compatible endpoint (primary path)
    cursor_key = cfg["cursor_key"]
    if cursor_key:
        try:
            cursor_base = cfg["cursor_base"]
            preferred = cfg["cursor_model"]
            model_candidates = [preferred, "gpt-4o-mini", "gpt-4.1-mini", "claude-3-5-sonnet"]
            tried = set()
            for candidate in model_candidates:
                if not candidate or candidate in tried:
                    continue
                tried.add(candidate)
                try:
                    return _openai_style_completion(
                        api_key=cursor_key,
                        base_url=cursor_base,
                        model_name=candidate,
                        prompt=prompt,
                    )
                except Exception as model_err:
                    print(f"[Cursor AI Error][{candidate}] {str(model_err)}")
        except Exception as e:
            print(f"[Cursor AI Error] {str(e)}")

    # 2) Standard OpenAI-compatible key
    openai_key = cfg["openai_key"]
    if openai_key:
        try:
            openai_base = cfg["openai_base"]  # optional for proxy/openai-compatible services
            openai_model = cfg["openai_model"]
            return _openai_style_completion(
                api_key=openai_key,
                base_url=openai_base,
                model_name=openai_model,
                prompt=prompt,
            )
        except Exception as e:
            print(f"[OpenAI Fallback Error] {str(e)}")

    # 3) Gemini stable fallback
    try:
        model = get_gemini_model()
        return (model.generate_content(prompt).text or "").strip()
    except Exception as e:
        print(f"[Gemini Fallback Error] {str(e)}")
        raise


def _heuristic_security_summary(log_text: str) -> dict:
    text = str(log_text or "")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    low = text.lower()
    error_hits = sum(1 for t in (" error", "failed", "critical", "denied", "panic", "fatal") if t in low)
    warn_hits = sum(1 for t in (" warning", "warn", "timeout", "retry", "degraded") if t in low)
    auth_hits = sum(1 for t in ("auth", "sudo", "ssh", "login", "invalid user", "permission") if t in low)

    if error_hits >= 3:
        level = "HIGH"
    elif error_hits >= 1 or warn_hits >= 3:
        level = "MEDIUM"
    else:
        level = "LOW"

    summary = (
        f"Automated security analysis processed {len(lines)} log lines. "
        f"Detected {error_hits} critical/error indicators, {warn_hits} warning indicators, "
        f"and {auth_hits} authentication or access-related signals. "
        "Review repeated failures and access anomalies, then validate related services and credentials."
    )
    return {"ai_insights": summary, "security_level": level}


def generate_security_summary(*, model, log_text: str):
    """
    Produce a concise security-focused summary for any log type.
    Returns a dict: {ai_insights, security_level}
    """
    import json as _json

    # 'model' is kept for backward compatibility with existing calls.
    try:
        text = generate_security_summary_text(log_text)
    except Exception as e:
        print(str(e))
        # Never let AI failures break business flow (email/report).
        return _heuristic_security_summary(log_text)
    try:
        parsed = _json.loads(text)
        ai_insights = str(parsed.get("ai_insights", "")).strip() or text[:600]
        security_level = str(parsed.get("security_level", "")).strip().upper()
        if security_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            security_level = "MEDIUM"
        return {"ai_insights": ai_insights, "security_level": security_level}
    except Exception:
        if text:
            return {"ai_insights": text[:600], "security_level": "MEDIUM"}
        return _heuristic_security_summary(log_text)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

with app.app_context():
    db.create_all()
    ensure_default_admin()


def analyses_query_for_user():
    if getattr(current_user, "is_admin", False):
        return Analysis.query
    return Analysis.query.filter_by(user_id=current_user.id)


def save_analysis_for_current_user(*, source_type: str, source_path: str, server_ip: str | None, stats: dict, segments: dict, meta: dict):
    a = Analysis(
        user_id=current_user.id,
        source_type=source_type,
        source_path=source_path,
        server_ip=server_ip,
        stats=stats,
        segments=segments,
        meta=meta,
    )
    db.session.add(a)
    db.session.commit()
    return a

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


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form.get('current_password') or ""
        new_password = request.form.get('new_password') or ""
        confirm = request.form.get('confirm_password') or ""

        if not current_password or not new_password or not confirm:
            flash("Veuillez remplir tous les champs.", "danger")
            return redirect(url_for("profile"))
        if not current_user.check_password(current_password):
            flash("Mot de passe actuel incorrect.", "danger")
            return redirect(url_for("profile"))
        if new_password != confirm:
            flash("Les mots de passe ne correspondent pas.", "danger")
            return redirect(url_for("profile"))
        if len(new_password) < 8:
            flash("Le nouveau mot de passe doit contenir au moins 8 caractères.", "danger")
            return redirect(url_for("profile"))

        user = db.session.get(User, current_user.id)
        user.set_password(new_password)
        db.session.commit()
        flash("Password updated successfully.", "success")
        return redirect(url_for("profile"))

    return render_template('profile.html')


@app.route('/admin/users', methods=['GET'])
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/users/<int:user_id>/edit', methods=['POST'])
@admin_required
def admin_user_edit(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_users"))

    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    role = (request.form.get("role") or user.role).strip()

    if role not in ("Admin", "Analyst"):
        role = user.role

    if not username or not email:
        flash("Username et email sont obligatoires.", "danger")
        return redirect(url_for("admin_users"))

    existing = User.query.filter(
        ((User.username == username) | (User.email == email)) & (User.id != user.id)
    ).first()
    if existing:
        flash("Username ou email déjà utilisé.", "danger")
        return redirect(url_for("admin_users"))

    user.username = username
    user.email = email
    user.role = role
    db.session.commit()
    flash("User updated successfully.", "success")
    return redirect(url_for("admin_users"))


@app.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def admin_user_reset_password(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_users"))

    temp_password = request.form.get("temp_password") or "Temp@12345"
    if len(temp_password) < 8:
        flash("Temporary password must be at least 8 characters.", "danger")
        return redirect(url_for("admin_users"))

    user.set_password(temp_password)
    db.session.commit()
    flash(f"Password reset. Temporary password set for {user.username}.", "success")
    return redirect(url_for("admin_users"))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_user_delete(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_users"))
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin_users"))

    db.session.delete(user)
    db.session.commit()
    flash("User deleted.", "success")
    return redirect(url_for("admin_users"))


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
        payload = {
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
        }
        analysis = save_analysis_for_current_user(
            source_type="upload",
            source_path=payload["meta"]["source_path"],
            server_ip=None,
            stats=payload["stats"],
            segments=payload["segments"],
            meta=payload["meta"],
        )
        payload["analysis_id"] = analysis.id
        return jsonify(payload)
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
        payload = {
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
        }
        analysis = save_analysis_for_current_user(
            source_type="ssh",
            source_path=payload["meta"]["source_path"],
            server_ip=payload["meta"]["server_ip"],
            stats=payload["stats"],
            segments=payload["segments"],
            meta=payload["meta"],
        )
        payload["analysis_id"] = analysis.id
        return jsonify(payload)
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
        summary = generate_security_summary(model=None, log_text=str(log_line))
        return jsonify({"analysis": summary["ai_insights"], "security_level": summary["security_level"]})
    except Exception as e:
        return json_error(str(e), 500, code="AI_ANALYZE_FAILED")


@app.route('/api/analyses/<int:analysis_id>/report-pdf', methods=['POST'])
@login_required
def upload_report_pdf(analysis_id: int):
    a = analyses_query_for_user().filter_by(id=analysis_id).first()
    if not a:
        return json_error("Analysis not found.", 404, code="ANALYSIS_NOT_FOUND")

    if 'pdf' not in request.files:
        return json_error("No PDF provided.", 400, code="NO_PDF")
    f = request.files['pdf']
    if not f.filename:
        return json_error("Empty PDF filename.", 400, code="EMPTY_PDF_FILENAME")

    reports_dir = os.path.join(app.config['UPLOAD_FOLDER'], "reports")
    os.makedirs(reports_dir, exist_ok=True)

    filename = secure_filename(f"analysis_{a.id}.pdf")
    filepath = os.path.join(reports_dir, filename)
    f.save(filepath)

    a.meta = {**(a.meta or {}), "report_pdf_path": filepath}
    db.session.commit()

    return jsonify({"status": "success", "pdf_path": filepath})


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
    analysis_id = data.get('analysis_id')
    report_data = data.get('report_data') or {}
    if not analysis_id and isinstance(report_data, dict):
        analysis_id = report_data.get("analysis_id")

    if not user_sender_email or not user_app_password or not dest_email:
        return json_error("Missing email fields", 400, code="MISSING_EMAIL_FIELDS")

    msg = MIMEMultipart("mixed")
    msg['From'] = user_sender_email
    msg['To'] = dest_email
    msg['Subject'] = subject

    try:
        analysis_id_int = int(analysis_id)
    except Exception:
        return json_error("Invalid or missing analysis_id.", 400, code="INVALID_ANALYSIS_ID")

    analysis = analyses_query_for_user().filter_by(id=analysis_id_int).first()
    if not analysis:
        return json_error("Analysis not found.", 404, code="ANALYSIS_NOT_FOUND")

    stats = analysis.stats or {}
    meta = analysis.meta or {}
    pdf_path = meta.get("report_pdf_path")
    if not pdf_path or not os.path.exists(pdf_path):
        return json_error(
            "PDF report not found for this analysis. Please export the PDF first (Report → Export PDF).",
            400,
            code="PDF_NOT_FOUND",
        )

    # Generate security summary for email body
    seg = analysis.segments or {}
    sample_lines = []
    sample_lines += (seg.get("ERROR") or [])[:8]
    sample_lines += (seg.get("WARNING") or [])[:6]
    sample_lines += (seg.get("INFO") or [])[:3]
    sample_text = "\n".join(sample_lines[:15]) or "\n".join((seg.get("INFO") or [])[:15]) or str(analysis.source_path or "")

    sec = generate_security_summary(model=None, log_text=sample_text)
    verdict = sec.get("ai_insights") or "N/A"
    security_level = sec.get("security_level") or "MEDIUM"

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = os.path.basename(meta.get("source_path") or analysis.source_path or "logs")

    html_body = f"""
    <html>
      <body style="font-family: Inter, Arial, sans-serif; color:#111827;">
        <h2 style="margin:0 0 8px 0;">LogAnalyzer — Security Audit Report</h2>
        <p style="margin:0 0 16px 0; color:#4b5563;">Please find the PDF report attached.</p>

        <table cellpadding="10" cellspacing="0" style="border-collapse:collapse; width:100%; max-width:680px; border:1px solid #e5e7eb;">
          <tr style="background:#f8fafc;">
            <td style="font-weight:700;">Date du Rapport</td>
            <td>{now_str}</td>
          </tr>
          <tr>
            <td style="font-weight:700;">Fichier Analysé</td>
            <td>{filename}</td>
          </tr>
          <tr style="background:#f8fafc;">
            <td style="font-weight:700;">AI Insights</td>
            <td>{verdict or "N/A"}</td>
          </tr>
          <tr>
            <td style="font-weight:700;">Security Level</td>
            <td>{security_level}</td>
          </tr>
        </table>

        <p style="margin-top:16px; color:#6b7280; font-size:12px;">
          Stats: total={stats.get('total','N/A')} errors={stats.get('errors','N/A')} warnings={stats.get('warnings','N/A')} info={stats.get('info','N/A')}
        </p>

      </body>
    </html>
    """

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(html_body, "html", "utf-8"))
    msg.attach(alt)

    if comment:
        msg.attach(MIMEText(comment, "plain", "utf-8"))

    with open(pdf_path, "rb") as fp:
        part = MIMEApplication(fp.read(), _subtype="pdf")
    part.add_header("Content-Disposition", "attachment", filename=os.path.basename(pdf_path))
    msg.attach(part)

    try:
        _smtp_send_with_fallback(user_sender_email, user_app_password, msg)
        return jsonify({"status": "success", "message": "Email envoyé avec succès !"})
    except Exception as e:
        return json_error(f"Erreur: {str(e)}", 500, code="SMTP_SEND_FAILED")


# Backwards-compatible alias (if frontend uses a different route name)
@app.route('/send-report-email', methods=['POST'])
@login_required
def send_report_email():
    return send_email()


@app.route('/api/analyses', methods=['GET'])
@login_required
def api_analyses_list():
    q = analyses_query_for_user().order_by(Analysis.created_at.desc())
    items = q.limit(100).all()
    return jsonify({
        "status": "success",
        "analyses": [
            {
                "id": a.id,
                "user_id": a.user_id,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "source_type": a.source_type,
                "source_path": a.source_path,
                "server_ip": a.server_ip,
                "stats": a.stats,
            }
            for a in items
        ],
    })


@app.route('/api/analyses/<int:analysis_id>', methods=['GET'])
@login_required
def api_analysis_get(analysis_id: int):
    a = analyses_query_for_user().filter_by(id=analysis_id).first()
    if not a:
        return json_error("Analysis not found.", 404, code="ANALYSIS_NOT_FOUND")
    return jsonify({
        "status": "success",
        "analysis": {
            "id": a.id,
            "user_id": a.user_id,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "meta": a.meta,
            "stats": a.stats,
            "segments": a.segments,
        }
    })

if __name__ == '__main__':
    app.run(debug=True, port=5000)