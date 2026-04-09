import os
os.environ['NO_PROXY'] = 'generativelanguage.googleapis.com,smtp.gmail.com'

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
import paramiko
from dotenv import load_dotenv
from werkzeug.utils import secure_filename  # Ajout de l'utilitaire de nom de fichier sécurisé
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

# --- Authentification / Base de données ---
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
    Résout les clés API avec rétrocompatibilité :
    - CURSOR_API_KEY est prioritaire pour le endpoint Cursor.
    - Si GEMINI_API_KEY contient une clé Cursor (crsr_*), elle est traitée comme telle.
    """
    raw_gemini = (os.getenv("GEMINI_API_KEY") or "").strip()
    raw_cursor = (os.getenv("CURSOR_API_KEY") or "").strip()
    raw_openai = (os.getenv("OPENAI_API_KEY") or "").strip()

    cursor_key = raw_cursor or (raw_gemini if _looks_like_cursor_key(raw_gemini) else "")
    gemini_key = "" if _looks_like_cursor_key(raw_gemini) else raw_gemini
    openai_key = raw_openai

    # Base URL Cursor configurable (par défaut endpoint OpenAI-compatible Cursor).
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
    # Utilise directement un nom de modèle stable (sans version d'API explicite).
    _gemini_model = genai.GenerativeModel("gemini-1.5-flash")
    return _gemini_model


def _openai_style_completion(*, api_key: str, base_url: str | None, model_name: str, prompt: str) -> str:
    """
    Helper de complétion compatible OpenAI.
    Fonctionne avec les endpoints Cursor/OpenAI-compatibles si base_url est fourni.
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
    Essaie d'abord l'endpoint Cursor/OpenAI-compatible (si CURSOR_API_KEY est fourni),
    puis une clé OpenAI, puis le modèle Gemini stable.
    Retourne le texte brut du modèle (JSON attendu par l'appelant).
    """
    prompt = (
        "Analyze security-relevant logs and return ONLY valid JSON.\n"
        "Required keys: ai_insights (2-4 sentences), security_level (LOW|MEDIUM|HIGH|CRITICAL).\n"
        f"LOGS:\n{log_text}\n"
    )

    cfg = _resolve_ai_config()

    # 1) Endpoint Cursor/OpenAI-compatible (chemin principal)
    cursor_key = cfg["cursor_key"]
    if cursor_key:
        try:
            configured_base = cfg["cursor_base"]
            preferred = cfg["cursor_model"]
            # Prompt court + moins de combinaisons pour réduire les timeouts.
            model_candidates = [preferred, "gpt-4o-mini"]
            base_candidates = []
            for base in [configured_base, "https://api.cursor.sh/v1", "https://api.cursor.sh"]:
                if base and base not in base_candidates:
                    base_candidates.append(base)

            for base_url in base_candidates:
                for candidate in model_candidates:
                    if not candidate:
                        continue
                    try:
                        return _openai_style_completion(
                            api_key=cursor_key,
                            base_url=base_url,
                            model_name=candidate,
                            prompt=prompt,
                        )
                    except Exception as model_err:
                        print(f"[Cursor AI Error][base={base_url}][model={candidate}] {str(model_err)}")
        except Exception as e:
            print(f"[Cursor AI Error] {str(e)}")

    # 2) Clé OpenAI-compatible standard
    openai_key = cfg["openai_key"]
    if openai_key:
        try:
            openai_base = cfg["openai_base"]  # Optionnel pour proxy/services OpenAI-compatibles
            openai_model = cfg["openai_model"]
            return _openai_style_completion(
                api_key=openai_key,
                base_url=openai_base,
                model_name=openai_model,
                prompt=prompt,
            )
        except Exception as e:
            print(f"[OpenAI Fallback Error] {str(e)}")

    # 3) Repli Gemini stable
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
    Produit un résumé concis orienté sécurité pour tout type de log.
    Retourne un dict : {ai_insights, security_level}
    """
    import json as _json

    # 'model' est conservé pour la rétrocompatibilité avec les appels existants.
    try:
        text = generate_security_summary_text(log_text)
    except Exception as e:
        print(str(e))
        # Ne jamais laisser une erreur IA bloquer le flux métier (email/rapport).
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
    # Conserve une trace légère de la "session courante" pour la génération de rapport.
    try:
        recent = list(session.get("recent_analysis_ids") or [])
        recent.append(a.id)
        session["recent_analysis_ids"] = recent[-50:]
        session.modified = True
    except Exception:
        # Les erreurs de session ne doivent jamais bloquer la persistance des analyses.
        pass
    return a


def _session_analysis_ids() -> list[int]:
    raw = session.get("recent_analysis_ids") or []
    out: list[int] = []
    for item in raw:
        try:
            out.append(int(item))
        except Exception:
            continue
    return out


def _combine_analysis_segments(analyses: list[Analysis]) -> tuple[list[str], dict]:
    lines: list[str] = []
    errors = 0
    warnings = 0
    info = 0
    debug = 0
    total = 0

    for a in analyses:
        seg = a.segments or {}
        e = list(seg.get("ERROR") or [])
        w = list(seg.get("WARNING") or [])
        i = list(seg.get("INFO") or [])
        d = list(seg.get("DEBUG") or [])

        errors += len(e)
        warnings += len(w)
        info += len(i)
        debug += len(d)
        total += len(e) + len(w) + len(i) + len(d)
        lines.extend(e + w + i + d)

    return lines, {
        "errors": errors,
        "warnings": warnings,
        "info": info,
        "debug": debug,
        "total": total,
    }


def _global_health_score(stats: dict) -> int:
    """
    Score de Santé Global basé sur le ratio Erreurs vs Info :
    score = info / (info + errors) * 100
    """
    errors = int(stats.get("errors") or 0)
    info = int(stats.get("info") or 0)
    denom = max(1, errors + info)
    score = round((info / denom) * 100)
    return max(0, min(100, int(score)))


def _generate_executive_security_audit(log_lines: list[str], stats: dict, health_score: int) -> dict:
    # Garde une taille de prompt bornée et privilégie d'abord les lignes à fort signal.
    sample = "\n".join((log_lines or [])[:220])
    logs_to_analyze = sample
    print(f"Payload envoyé à l'IA: {logs_to_analyze}")
    prompt = (
        "Create a short executive security audit from these logs.\n"
        "Return ONLY valid JSON with this schema:\n"
        "{\n"
        '  "executive_summary": "string",\n'
        '  "summary_table": [\n'
        '    {"metric":"string","value":"string","notes":"string"}\n'
        "  ],\n"
        '  "immediate_actions": ["string"]\n'
        "}\n"
        "Constraints:\n"
        "- executive_summary: max 4 sentences.\n"
        "- summary_table: 5-7 rows only.\n"
        "- immediate_actions: 3-5 concrete actions.\n\n"
        f"STATS: {json.dumps(stats, ensure_ascii=True)}\n"
        f"GLOBAL_HEALTH_SCORE: {health_score}\n"
        "LOGS:\n"
        f"{logs_to_analyze}"
    )

    try:
        raw = generate_security_summary_text(prompt)
    except Exception as e:
        print(f"[Executive Audit AI Error] {str(e)}")
        raw = ""
    try:
        parsed = json.loads(raw)
    except Exception:
        return {
            "executive_summary": raw[:900] if raw else "Executive audit generated with limited formatting.",
            "summary_table": [
                {"metric": "Global Health Score", "value": f"{health_score}%", "notes": "Computed from Info vs Errors"},
                {"metric": "Errors", "value": str(stats.get("errors", 0)), "notes": "Critical/failed events detected"},
                {"metric": "Warnings", "value": str(stats.get("warnings", 0)), "notes": "Warning/degraded indicators"},
                {"metric": "Info", "value": str(stats.get("info", 0)), "notes": "Informational log volume"},
                {"metric": "Total Lines", "value": str(stats.get("total", 0)), "notes": "Total analyzed log lines"},
            ],
            "immediate_actions": [
                "Investigate recurring error patterns and isolate affected services.",
                "Validate authentication and access anomalies in critical hosts.",
                "Apply short-term containment and increase monitoring thresholds.",
            ],
        }

    summary = str(parsed.get("executive_summary") or "").strip()
    table = parsed.get("summary_table")
    actions = parsed.get("immediate_actions")

    if not isinstance(table, list):
        table = []
    norm_table = []
    for row in table:
        if not isinstance(row, dict):
            continue
        metric = str(row.get("metric") or "").strip()
        value = str(row.get("value") or "").strip()
        notes = str(row.get("notes") or "").strip()
        if metric:
            norm_table.append({"metric": metric, "value": value or "--", "notes": notes or "--"})

    if not isinstance(actions, list):
        actions = []
    norm_actions = [str(a).strip() for a in actions if str(a).strip()]

    if not norm_table:
        norm_table = [
            {"metric": "Global Health Score", "value": f"{health_score}%", "notes": "Computed from Info vs Errors"},
            {"metric": "Errors", "value": str(stats.get("errors", 0)), "notes": "Critical/failed events detected"},
            {"metric": "Warnings", "value": str(stats.get("warnings", 0)), "notes": "Warning/degraded indicators"},
            {"metric": "Info", "value": str(stats.get("info", 0)), "notes": "Informational log volume"},
            {"metric": "Total Lines", "value": str(stats.get("total", 0)), "notes": "Total analyzed log lines"},
        ]
    if not norm_actions:
        norm_actions = [
            "Investigate top recurring error signatures and impacted hosts.",
            "Harden authentication controls and review suspicious access attempts.",
            "Increase log retention and alerting coverage for critical services.",
        ]

    return {
        "executive_summary": summary or "Executive security audit generated successfully.",
        "summary_table": norm_table,
        "immediate_actions": norm_actions[:10],
    }

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
            flash("Identifiants invalides.", "danger")
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
        flash("Mot de passe mis à jour avec succès.", "success")
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
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("admin_users"))

    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    role = (request.form.get("role") or user.role).strip()

    if role not in ("Admin", "Analyst"):
        role = user.role

    if not username or not email:
        flash("Nom d'utilisateur et e-mail sont obligatoires.", "danger")
        return redirect(url_for("admin_users"))

    existing = User.query.filter(
        ((User.username == username) | (User.email == email)) & (User.id != user.id)
    ).first()
    if existing:
        flash("Nom d'utilisateur ou e-mail déjà utilisé.", "danger")
        return redirect(url_for("admin_users"))

    user.username = username
    user.email = email
    user.role = role
    db.session.commit()
    flash("Utilisateur mis à jour avec succès.", "success")
    return redirect(url_for("admin_users"))


@app.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def admin_user_reset_password(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("admin_users"))

    temp_password = request.form.get("temp_password") or "Temp@12345"
    if len(temp_password) < 8:
        flash("Le mot de passe temporaire doit contenir au moins 8 caractères.", "danger")
        return redirect(url_for("admin_users"))

    user.set_password(temp_password)
    db.session.commit()
    flash(f"Mot de passe réinitialisé. Mot de passe temporaire défini pour {user.username}.", "success")
    return redirect(url_for("admin_users"))


@app.route('/admin/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def admin_user_delete(user_id: int):
    user = db.session.get(User, user_id)
    if not user:
        flash("Utilisateur introuvable.", "danger")
        return redirect(url_for("admin_users"))
    if user.id == current_user.id:
        flash("Vous ne pouvez pas supprimer votre propre compte.", "danger")
        return redirect(url_for("admin_users"))

    db.session.delete(user)
    db.session.commit()
    flash("Utilisateur supprimé.", "success")
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


@app.route('/upload', methods=['POST'])  # Route d'upload local des logs
@login_required
def upload_file():
    """Gère l'upload local de fichiers de logs."""
    try:
        if 'file' not in request.files:
            return json_error("Aucun fichier fourni", 400, code="NO_FILE")

        file = request.files['file']
        if file.filename == '':
            return json_error("Nom de fichier vide", 400, code="EMPTY_FILENAME")

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
            return json_error("Limite invalide", 400, code="INVALID_LIMIT")

        if not ip or not user or not pwd:
            return json_error("Identifiants SSH manquants", 400, code="MISSING_SSH_FIELDS")

        # Durcissement basique anti-injection : caractères sûrs et limite bornée.
        limit = max(1, min(limit, 5000))
        if any(c in path for c in [';', '&', '|', '`', '$', '>', '<', '\n', '\r']):
            return json_error("Chemin invalide", 400, code="INVALID_PATH")

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
        return json_error("Échec d'authentification", 401, code="SSH_AUTH_FAILED")
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
            return json_error("Champ 'line' manquant", 400, code="MISSING_LINE")
        summary = generate_security_summary(model=None, log_text=str(log_line))
        return jsonify({"analysis": summary["ai_insights"], "security_level": summary["security_level"]})
    except Exception as e:
        return json_error(str(e), 500, code="AI_ANALYZE_FAILED")


@app.route('/generate-report', methods=['POST'])
@login_required
def generate_report():
    """
    Génère et persiste un audit de sécurité exécutif à partir de logs analysés.
    Périmètre :
    - "session" : analyses créées dans la session web courante.
    - "day" (par défaut) : analyses créées aujourd'hui (UTC) pour l'utilisateur courant.
    """
    try:
        data = request.get_json(silent=True) or {}
        scope = str(data.get("scope") or "day").strip().lower()

        analyses: list[Analysis] = []
        q = analyses_query_for_user()

        if scope == "session":
            ids = _session_analysis_ids()
            if ids:
                analyses = q.filter(Analysis.id.in_(ids)).order_by(Analysis.created_at.asc()).all()
            else:
                # Repli : approxime la session courante avec une fenêtre d'activité récente.
                since = datetime.now(timezone.utc) - timedelta(hours=8)
                analyses = q.filter(Analysis.created_at >= since).order_by(Analysis.created_at.asc()).all()
        else:
            now = datetime.now(timezone.utc)
            day_start = datetime(now.year, now.month, now.day, tzinfo=timezone.utc)
            analyses = q.filter(Analysis.created_at >= day_start).order_by(Analysis.created_at.asc()).all()

        if not analyses:
            return json_error("Aucun log analysé trouvé pour le périmètre sélectionné.", 404, code="NO_ANALYSES_FOR_REPORT")

        log_lines, combined_stats = _combine_analysis_segments(analyses)
        health_score = _global_health_score(combined_stats)
        ai_report = _generate_executive_security_audit(log_lines, combined_stats, health_score)

        latest = analyses[-1]
        meta = latest.meta or {}
        generated_report = {
            "generated_at": utc_now_iso(),
            "scope": scope,
            "analysis_ids": [a.id for a in analyses],
            "global_health_score": health_score,
            "stats": combined_stats,
            "executive_summary": ai_report.get("executive_summary"),
            "summary_table": ai_report.get("summary_table") or [],
            "immediate_actions": ai_report.get("immediate_actions") or [],
        }
        latest.meta = {**meta, "generated_report": generated_report}
        db.session.commit()

        return jsonify({
            "status": "success",
            "report": generated_report,
            "saved_on_analysis_id": latest.id,
        })
    except Exception as e:
        return json_error(str(e), 500, code="GENERATE_REPORT_FAILED")


@app.route('/api/reports/latest', methods=['GET'])
@login_required
def api_latest_report():
    """
    Récupère le dernier generated_report persisté selon le périmètre utilisateur/admin.
    """
    a = analyses_query_for_user().order_by(Analysis.created_at.desc()).all()
    for item in a:
        meta = item.meta or {}
        rep = meta.get("generated_report")
        if isinstance(rep, dict):
            return jsonify({"status": "success", "analysis_id": item.id, "report": rep})
    return json_error("Aucun rapport sauvegardé trouvé.", 404, code="REPORT_NOT_FOUND")


@app.route('/api/analyses/<int:analysis_id>/report-pdf', methods=['POST'])
@login_required
def upload_report_pdf(analysis_id: int):
    a = analyses_query_for_user().filter_by(id=analysis_id).first()
    if not a:
        return json_error("Analyse introuvable.", 404, code="ANALYSIS_NOT_FOUND")

    if 'pdf' not in request.files:
        return json_error("Aucun PDF fourni.", 400, code="NO_PDF")
    f = request.files['pdf']
    if not f.filename:
        return json_error("Nom de fichier PDF vide.", 400, code="EMPTY_PDF_FILENAME")

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
    Tente Gmail SMTP avec repli automatique :
    - 465: SMTP_SSL
    - 587: SMTP + STARTTLS
    """
    last_err = None
    context = ssl.create_default_context()

    # Tente d'abord SSL (465)
    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context, timeout=15) as server:
            server.login(sender_email, app_password)
            server.send_message(msg)
            return
    except Exception as e:
        last_err = e

    # Repli sur STARTTLS (587)
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
        return json_error("Champs e-mail manquants", 400, code="MISSING_EMAIL_FIELDS")

    msg = MIMEMultipart("mixed")
    msg['From'] = user_sender_email
    msg['To'] = dest_email
    msg['Subject'] = subject

    try:
        analysis_id_int = int(analysis_id)
    except Exception:
        return json_error("analysis_id invalide ou manquant.", 400, code="INVALID_ANALYSIS_ID")

    analysis = analyses_query_for_user().filter_by(id=analysis_id_int).first()
    if not analysis:
        return json_error("Analyse introuvable.", 404, code="ANALYSIS_NOT_FOUND")

    stats = analysis.stats or {}
    meta = analysis.meta or {}
    pdf_path = meta.get("report_pdf_path")
    if not pdf_path or not os.path.exists(pdf_path):
        return json_error(
            "Rapport PDF introuvable pour cette analyse. Veuillez d'abord exporter le PDF (Rapport → Exporter en PDF).",
            400,
            code="PDF_NOT_FOUND",
        )

    # Génère un résumé de sécurité pour le corps de l'email
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
        <h2 style="margin:0 0 8px 0;">LogAnalyzer — Rapport d'audit de sécurité</h2>
        <p style="margin:0 0 16px 0; color:#4b5563;">Veuillez trouver le rapport PDF en pièce jointe.</p>

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
            <td style="font-weight:700;">Aperçus IA</td>
            <td>{verdict or "N/A"}</td>
          </tr>
          <tr>
            <td style="font-weight:700;">Niveau de sécurité</td>
            <td>{security_level}</td>
          </tr>
        </table>

        <p style="margin-top:16px; color:#6b7280; font-size:12px;">
          Statistiques : total={stats.get('total','N/A')} erreurs={stats.get('errors','N/A')} avertissements={stats.get('warnings','N/A')} info={stats.get('info','N/A')}
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


# Alias rétrocompatible (si le frontend utilise un autre nom de route)
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
        return json_error("Analyse introuvable.", 404, code="ANALYSIS_NOT_FOUND")
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