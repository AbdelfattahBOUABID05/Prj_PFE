import os
os.environ['NO_PROXY'] = 'generativelanguage.googleapis.com,smtp.gmail.com'

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
import io
from flask_cors import CORS
from flask import request, jsonify
from datetime import datetime, timezone, timedelta
from sqlalchemy import func
import paramiko
from dotenv import load_dotenv
from werkzeug.utils import secure_filename  # Ajout de l'utilitaire de nom de fichier sécurisé
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from PIL import Image, ImageEnhance # Pour le traitement d'image de la signature
from cryptography.fernet import Fernet # Pour la sécurité des clés API
import requests # Pour l'API Remove.bg

import smtplib
import ssl
import json
import re
import dns.resolver # Pour la détection MX
from openai import OpenAI
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import time

from src.parser import parse_log_file
from config import Config
from extensions import db, scheduler                # ← source unique de db
from scheduler import run_planned_analysis
from models import User, Analysis, AnalysisJob
from flask import jsonify

load_dotenv()

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)
app.config.from_object(Config)
app.config['REMOVE_BG_API_KEY'] = os.getenv('REMOVE_BG_API_KEY') or get_decrypted_removebg_key()

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)        # ← lie l'unique instance db à app
scheduler.init_app(app)
scheduler.start()

login_manager = LoginManager() 
login_manager.init_app(app)
login_manager.login_view = 'login'

# S'assurer que le dossier des uploads statiques existe (pour les signatures)
UPLOAD_STATIC_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
if not os.path.exists(UPLOAD_STATIC_FOLDER):
    os.makedirs(UPLOAD_STATIC_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_STATIC_FOLDER

# --- Configuration Uploads & Sécurité ---
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_decrypted_removebg_key():
    """Déchiffre la clé API Remove.bg depuis les variables d'environnement."""
    try:
        fernet_key = os.getenv("FERNET_KEY")
        encrypted_key = os.getenv("ENCRYPTED_REMOVEBG_KEY")
        if not fernet_key or not encrypted_key:
            return None
        f = Fernet(fernet_key.encode())
        return f.decrypt(encrypted_key.encode()).decode()
    except Exception as e:
        print(f"Erreur de déchiffrement API Key: {str(e)}")
        return None

# --- Authentification / Base de données ---
if 'sqlalchemy' not in app.extensions:
    db.init_app(app)
    print("✓ SQLAlchemy initialisé.")
else:
    print("! SQLAlchemy déjà enregistré, passage à la suite.")
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)
if 'sqlalchemy' not in app.extensions:
    db.init_app(app)
    print("SQLAlchemy initialisé avec succès.")
else:
    print("SQLAlchemy était déjà enregistré, passage à la suite.")


@app.context_processor
def inject_global_stats():
    """Injecte des données globales pour les badges de notification."""
    data = {
        'pending_jobs_count': 0,
        'user_notifications': [],
        'unread_notif_count': 0
    }
    
    if current_user.is_authenticated:
        # Pour l'admin : nombre de jobs en attente d'approbation
        if current_user.is_admin:
            data['pending_jobs_count'] = AnalysisJob.query.filter_by(status='pending').count()
            
        # Pour l'analyste : jobs activés/refusés non lus
        unread_jobs = AnalysisJob.query.filter(
            AnalysisJob.user_id == current_user.id,
            AnalysisJob.user_notified == False,
            AnalysisJob.status.in_(['active', 'refused'])
        ).all()
        
        for job in unread_jobs:
            status_fr = "activée" if job.status == 'active' else "refusée"
            data['user_notifications'].append({
                'id': job.id,
                'message': f"Votre tâche pour {job.target_ip} a été {status_fr} par l'administrateur.",
                'status': job.status,
                'ip': job.target_ip
            })
        
        data['unread_notif_count'] = len(data['user_notifications'])
        
    return data

@app.route('/api/notifications/mark-read', methods=['POST'])
@login_required
def mark_notifications_read():
    """Marque toutes les notifications de jobs de l'utilisateur comme lues."""
    try:
        AnalysisJob.query.filter_by(user_id=current_user.id, user_notified=False).update({
            'user_notified': True
        })
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500

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


def send_user_notification(user, subject, content):
    """Envoie une notification à l'utilisateur si une adresse de destination est configurée."""
    dest = user.notification_email or user.email
    if dest:
        return send_notification(dest, subject, content)
    return False

def send_notification(email_dest, subject, content):
    """Envoie une notification par email en utilisant un compte Gmail SMTP fixe."""
    msg = MIMEMultipart()
    # Récupérer les identifiants SMTP fixes depuis les variables d'environnement
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    
    if not smtp_user or not smtp_pass:
        logger.error("SMTP_USER ou SMTP_PASS non configuré dans les variables d'environnement.")
        return False

    msg['From'] = smtp_user
    msg['To'] = email_dest
    msg['Subject'] = subject
    msg.attach(MIMEText(content, 'html'))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Erreur d'envoi d'email: {e}")
        return False

def generate_security_summary_text(log_text: str, top_patterns: list = None) -> str:
    """
    Essaie d'abord l'endpoint Cursor/OpenAI-compatible (si CURSOR_API_KEY est fourni),
    puis une clé OpenAI, puis le modèle Gemini stable.
    Retourne le texte brut du modèle (JSON attendu par l'appelant).
    """
    patterns_str = ""
    if top_patterns:
        patterns_str = "\nTop 10 Recurring Patterns (Message, Occurrences):\n" + \
                       "\n".join([f"- {p[0]}: {p[1]}" for p in top_patterns])

    prompt = (
        "Analyze security-relevant logs and return ONLY valid JSON.\n"
        "STRICT JSON FORMAT REQUIRED. No markdown, no extra text.\n\n"
        "Required JSON keys:\n"
        "  \"ai_status\": \"Critique|Attention|Normal\",\n"
        "  \"ai_score\": <int 0-100>,\n"
        "  \"ai_menaces\": <int>,\n"
        "  \"severity_counts\": {\"Critique\": X, \"Moyen\": Y, \"Faible\": Z},\n"
        "  \"activity_trend\": [f1, f2, f3, ...], (list of frequencies over time)\n"
        "  \"audit_points\": [\"Point 1\", \"Point 2\", ...], (key audit findings)\n"
        "  \"ai_insights\": \"Short summary paragraph\",\n"
        "  \"security_level\": \"LOW|MEDIUM|HIGH|CRITICAL\",\n"
        "  \"corrective_actions\": [\"Action 1\", \"Action 2\"],\n"
        "  \"prevention_steps\": [\"Prevention 1\", \"Prevention 2\"]\n\n"
        "Rules:\n"
        "- If 'Failed password' is found, reduce score by 20 points per attempt.\n"
        "- ai_status mapping: score > 80 -> Normal, 50-80 -> Attention, < 50 -> Critique.\n"
        f"{patterns_str}\n"
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
    failed_pass_hits = sum(1 for t in ("failed password",) if t in low)

    # Deduction for failed password attempts
    score = 100 - (error_hits * 5) - (warn_hits * 2) - (failed_pass_hits * 20)
    score = max(0, min(100, score))

    if score > 80:
        status = "Sain"
        level = "LOW"
    elif score >= 50:
        status = "Attention"
        level = "MEDIUM"
    else:
        status = "Critique"
        level = "HIGH"

    if error_hits >= 3 or failed_pass_hits >= 3:
        level = "CRITICAL"

    summary = (
        f"Automated security analysis processed {len(lines)} log lines. "
        f"Detected {error_hits} critical/error indicators, {warn_hits} warning indicators, "
        f"and {auth_hits} authentication signals including {failed_pass_hits} failed login attempts. "
        "Review repeated failures and access anomalies, then validate related services."
    )
    return {
        "ai_insights": summary, 
        "security_level": level,
        "score": score,
        "status": status,
        "menaces": error_hits + failed_pass_hits,
        "severity_counts": {"Critique": error_hits, "Moyen": warn_hits, "Faible": auth_hits},
        "activity_trend": [],
        "audit_points": [
            f"Détection de {error_hits} erreurs critiques.",
            f"Détection de {warn_hits} avertissements.",
            f"Détection de {failed_pass_hits} échecs d'authentification."
        ]
    }


def generate_security_summary(*, model, log_text: str, top_patterns: list = None):
    """
    Produit un résumé concis orienté sécurité pour tout type de log.
    Retourne un dict avec les métriques IA demandées.
    """
    import json as _json

    try:
        text = generate_security_summary_text(log_text, top_patterns)
        print("DEBUG - IA Response:", text) # Debugging requirement
    except Exception as e:
        print(f"Error calling AI: {str(e)}")
        res = _heuristic_security_summary(log_text)
        res.update({
            "ai_status": res.get("status", "Attention"),
            "ai_score": res.get("score", 70),
            "ai_menaces": res.get("menaces", 0),
            "corrective_actions": [],
            "prevention_steps": []
        })
        return res

    parsed = {}
    try:
        # 1. Essai de parsing JSON standard
        parsed = _json.loads(text)
    except Exception:
        # 2. Parsing robuste via Regex si JSON standard échoue
        try:
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                parsed = _json.loads(match.group(0))
        except Exception as re_err:
            print(f"Regex Parsing Error: {str(re_err)}")

    # Extraction sécurisée avec valeurs par défaut pour éviter les crashs frontend
    ai_insights = str(parsed.get("ai_insights", "")).strip() or text[:600]
    security_level = str(parsed.get("security_level", "MEDIUM")).strip().upper()
    if security_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        security_level = "MEDIUM"
    
    return {
        "ai_insights": ai_insights,
        "security_level": security_level,
        "score": int(parsed.get("ai_score", parsed.get("score", 70))),
        "status": str(parsed.get("ai_status", parsed.get("status", "Attention"))),
        "menaces": int(parsed.get("ai_menaces", parsed.get("menaces", 0))),
        "severity_counts": parsed.get("severity_counts", {"Critique": 0, "Moyen": 0, "Faible": 0}),
        "activity_trend": parsed.get("activity_trend", []),
        "audit_points": parsed.get("audit_points", []),
        "corrective_actions": parsed.get("corrective_actions", []),
        "prevention_steps": parsed.get("prevention_steps", [])
    }

if not os.path.exists(app.config.get('UPLOAD_FOLDER', 'uploads')):
    os.makedirs(app.config.get('UPLOAD_FOLDER', 'uploads'))

with app.app_context():
    db.create_all()
    ensure_default_admin()


def analyses_query_for_user():
    # On filtre systématiquement par l'ID de l'utilisateur connecté pour isolation totale
    return Analysis.query.filter_by(user_id=current_user.id)


def save_analysis_for_current_user(*, source_type: str, source_path: str, server_ip: str | None, stats: dict, segments: dict, meta: dict, log_content: str = ""):
    # Calcul des récurrences (Top 10) pour l'IA
    all_lines = (segments.get('ERROR', []) + segments.get('WARNING', []) + segments.get('INFO', []))
    counts = {}
    for line in all_lines:
        cleaned = str(line).split(' ', 3)[-1].strip() if ' ' in str(line) else str(line)
        counts[cleaned] = counts.get(cleaned, 0) + 1
    top_patterns = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # Génération des métriques IA avant sauvegarde
    ai_metrics = generate_security_summary(model=None, log_text=log_content, top_patterns=top_patterns) if log_content else None
    
    a = Analysis(
        user_id=current_user.id,
        source_type=source_type,
        source_path=source_path,
        server_ip=server_ip,
        stats=stats,
        segments=segments,
        meta=meta,
        ai_score=ai_metrics.get("score") if ai_metrics else None,
        ai_status=ai_metrics.get("status") if ai_metrics else None,
        ai_menaces=ai_metrics.get("menaces") if ai_metrics else None,
    )
    
    # Intégration des métriques IA complètes dans les meta pour le dashboard et rapport
    if ai_metrics:
        a.meta = {
            **(a.meta or {}), 
            "ai_insights": ai_metrics.get("ai_insights"),
            "severity_counts": ai_metrics.get("severity_counts"),
            "activity_trend": ai_metrics.get("activity_trend"),
            "audit_points": ai_metrics.get("audit_points"),
            "corrective_actions": ai_metrics.get("corrective_actions", []),
            "prevention_steps": ai_metrics.get("prevention_steps", []),
            "security_level": ai_metrics.get("security_level")
        }

    db.session.add(a)
    db.session.commit()
    
    # Stockage de l'ID uniquement dans la session Flask pour éviter la limite de 4KB
    session['last_analysis_id'] = a.id
    # On retire les données volumineuses de la session si elles y étaient
    session.pop('analysis_results', None)
    
    # Conserve une trace légère de la "session courante" pour la génération de rapport.
    try:
        recent = list(session.get("recent_analysis_ids") or [])
        recent.append(a.id)
        session["recent_analysis_ids"] = recent[-50:]
        session.modified = True
    except Exception:
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
    # Récupération de l'ID d'analyse depuis la session ou la dernière en base
    analysis_id = session.get('last_analysis_id')
    last_analysis = None
    
    if analysis_id:
        last_analysis = Analysis.query.filter_by(id=analysis_id, user_id=current_user.id).first()
    
    if not last_analysis:
        last_analysis = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created_at.desc()).first()

    # Statistiques globales pour le dashboard basées sur l'historique (7 derniers jours)
    seven_days_ago = datetime.now(timezone.utc) - timedelta(days=7)
    recent_analyses = Analysis.query.filter(
        Analysis.user_id == current_user.id,
        Analysis.created_at >= seven_days_ago
    ).order_by(Analysis.created_at.desc()).all()

    total_audits = Analysis.query.filter_by(user_id=current_user.id).count()
    active_servers = db.session.query(Analysis.server_ip).filter(Analysis.user_id == current_user.id, Analysis.server_ip != None).distinct().count()
    
    # Menaces critiques (Cumul des menaces sur les analyses récentes)
    critical_threats = sum((a.ai_menaces if a.ai_menaces is not None else int(a.stats.get('errors', 0))) for a in recent_analyses)
    
    # Score de santé système (Moyenne des scores récents)
    scores = [(a.ai_score if a.ai_score is not None else _global_health_score(a.stats)) for a in recent_analyses]
    system_health = round(sum(scores) / len(scores)) if scores else 100

    results = None
    if last_analysis:
        results = {
            "status": "success",
            "analysis_id": last_analysis.id,
            "meta": last_analysis.meta,
            "segments": last_analysis.segments,
            "stats": last_analysis.stats,
            "ai_score": last_analysis.ai_score,
            "ai_status": last_analysis.ai_status,
            "ai_menaces": last_analysis.ai_menaces,
            "generated_at": last_analysis.created_at.isoformat()
        }
        session['last_analysis_id'] = last_analysis.id
            
    return render_template('index.html', 
                           analysis_data=results, 
                           total_audits=total_audits,
                           active_servers=active_servers,
                           critical_threats=critical_threats,
                           system_health=system_health,
                           recent_activities=recent_analyses)

@app.route('/details')
@login_required
def details():
    analysis_id = session.get('last_analysis_id')
    last_analysis = None
    
    if analysis_id:
        last_analysis = Analysis.query.filter_by(id=analysis_id, user_id=current_user.id).first()
    
    if not last_analysis:
        last_analysis = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created_at.desc()).first()

    results = None
    if last_analysis:
        results = {
            "status": "success",
            "analysis_id": last_analysis.id,
            "meta": last_analysis.meta,
            "segments": last_analysis.segments,
            "stats": last_analysis.stats,
            "generated_at": last_analysis.created_at.isoformat()
        }
        session['last_analysis_id'] = last_analysis.id

    # Extraction du chemin du fichier pour l'affichage dans le template
    filename = "--"
    if results and 'meta' in results:
        filename = results['meta'].get('source_path') or results['meta'].get('filename') or "--"

    return render_template('details.html', analysis_data=results, filename=filename)

@app.route('/ssh')
@login_required
def ssh_page():
    return render_template('ssh_config.html')

@app.route('/analyse-local', methods=['GET', 'POST'])
@login_required
def analyse_local_page():
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash("Aucun fichier fourni", "danger")
                return redirect(request.url)

            file = request.files['file']
            if file.filename == '':
                flash("Nom de fichier vide", "danger")
                return redirect(request.url)

            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            results = parse_log_file(filepath)
            meta = file_metadata(filepath)
            
            payload = {
                "status": "success",
                "generated_at": utc_now_iso(),
                "meta": {
                    "source_type": "local_upload",
                    "source_path": filename,
                    "server_ip": "Local Machine",
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
            
            # Lecture du contenu pour l'analyse IA
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                log_content = f.read(50000)

            analysis = save_analysis_for_current_user(
                source_type="local_upload",
                source_path=filename,
                server_ip="Local Machine",
                stats=payload["stats"],
                segments=payload["segments"],
                meta=payload["meta"],
                log_content=log_content
            )
            
            flash("Analyse locale terminée avec succès.", "success")
            return redirect(url_for('report_page'))
            
        except Exception as e:
            flash(f"Erreur lors de l'analyse : {str(e)}", "danger")
            return redirect(request.url)
            
    return render_template('analyse_local.html')

@app.route('/report')
@login_required
def report_page():
    analysis_id = session.get('last_analysis_id')
    last_analysis = None
    
    if analysis_id:
        last_analysis = Analysis.query.filter_by(id=analysis_id, user_id=current_user.id).first()
    
    if not last_analysis:
        last_analysis = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created_at.desc()).first()

    results = None
    if last_analysis:
        results = {
            "status": "success",
            "analysis_id": last_analysis.id,
            "meta": last_analysis.meta,
            "segments": last_analysis.segments,
            "stats": last_analysis.stats,
            "generated_at": last_analysis.created_at.isoformat()
        }
        session['last_analysis_id'] = last_analysis.id

    return render_template('report.html', analysis_data=results)

@app.route('/help')
@login_required
def help_page():
    return render_template('help.html')

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
        action = request.form.get('action')
        
        if action == 'change_password':
            # ... (logique existante conservée) ...
            current_password = request.form.get('current_password') or ""
            new_password = request.form.get('new_password') or ""
            confirm = request.form.get('confirm_password') or ""

            if not current_password or not new_password or not confirm:
                flash("Veuillez remplir tous les champs du mot de passe.", "danger")
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
            
        elif action == 'update_email_config':
            email_sender = (request.form.get('email_sender') or "").strip()
            email_password = request.form.get('email_password') or ""
            smtp_server = (request.form.get('smtp_server') or "").strip()
            smtp_port = request.form.get('smtp_port')
            
            user = db.session.get(User, current_user.id)
            user.email_sender = email_sender
            if email_password:
                user.email_password_enc = email_password
            
            user.smtp_server = smtp_server if smtp_server else None
            try:
                user.smtp_port = int(smtp_port) if smtp_port else None
            except ValueError:
                user.smtp_port = None
                
            db.session.commit()
            flash("Configuration email mise à jour.", "success")
            
        elif action == 'update_signature':
            if 'signature' not in request.files:
                flash("Aucun fichier de signature fourni.", "danger")
                return redirect(url_for("profile"))
            
            file = request.files['signature']
            if file.filename == '':
                flash("Veuillez sélectionner une image pour la signature.", "danger")
                return redirect(url_for("profile"))
            
            if file and allowed_file(file.filename):
                try:
                    # Supprimer l'ancienne signature si elle existe
                    if current_user.signature_path:
                        old_path = os.path.join(app.config['UPLOAD_FOLDER'], current_user.signature_path)
                        if os.path.exists(old_path):
                            try:
                                os.remove(old_path)
                            except Exception:
                                pass
                    
                    # Générer un nom unique forcé en .png
                    filename = f"sig_{current_user.id}_{int(time.time())}.png"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    
                    # Force l'utilisation de la clé du .env
                    api_key = os.getenv('REMOVE_BG_API_KEY')
                    
                    if not api_key:
                        flash("Erreur : Clé API Remove.bg manquante dans le fichier .env.", "danger")
                        return redirect(url_for("profile"))

                    try:
                        file.seek(0)
                        # Appel API Remove.bg avec les paramètres optimisés
                        response = requests.post(
                            'https://api.remove.bg/v1.0/removebg',
                            files={'image_file': ('signature.png', file.read(), 'image/png')},
                            data={'size': 'auto'},
                            headers={'X-Api-Key': api_key},
                        )
                        
                        if response.status_code == requests.codes.ok:
                            with open(filepath, 'wb') as out:
                                out.write(response.content)
                            
                            # Vérifier que le fichier a bien été créé avant de mettre à jour la base
                            if os.path.exists(filepath):
                                user = db.session.get(User, current_user.id)
                                user.signature_path = filename
                                db.session.commit()
                                flash("Signature mise à jour avec succès via Remove.bg (Qualité Pro).", "success")
                            else:
                                flash("Erreur critique : le fichier de signature n'a pas pu être enregistré.", "danger")
                        else:
                            error_detail = response.json() if response.content else {"errors": [{"title": "Erreur inconnue"}]}
                            msg = error_detail.get('errors', [{}])[0].get('title', 'Erreur API')
                            flash(f"Échec de l'API Remove.bg : {msg} (Status: {response.status_code})", "danger")
                            print(f"Remove.bg Error: {response.status_code} - {response.text}")
                            
                    except Exception as api_err:
                        flash(f"Erreur de communication avec l'API Remove.bg : {str(api_err)}", "danger")
                        print(f"Remove.bg API Call Failed: {str(api_err)}")
                except Exception as e:
                    flash(f"Erreur lors du traitement de l'image : {str(e)}", "danger")
            else:
                flash("Format de fichier non autorisé (PNG, JPG, JPEG uniquement).", "danger")

        elif action == 'delete_signature':
            if current_user.signature_path:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], current_user.signature_path)
                if os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                    except Exception:
                        pass
                
                user = db.session.get(User, current_user.id)
                user.signature_path = None
                db.session.commit()
                flash("Signature supprimée.", "info")
            
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
    session.clear() # Vide complètement la session pour isolation utilisateur
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
        # Lecture du contenu pour l'analyse IA
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            log_content = f.read(50000) # Limite pour l'IA

        analysis = save_analysis_for_current_user(
            source_type="upload",
            source_path=payload["meta"]["source_path"],
            server_ip=None,
            stats=payload["stats"],
            segments=payload["segments"],
            meta=payload["meta"],
            log_content=log_content
        )
        payload["analysis_id"] = analysis.id
        
        # Le stockage en session est déjà géré par save_analysis_for_current_user
        return jsonify(payload)
    except Exception as e:
        return json_error(str(e), 500, code="UPLOAD_FAILED")

@app.route('/ssh-analyze', methods=['POST'])
@login_required
def ssh_analyze():
    import traceback
    ssh = None
    try:
        data = request.get_json(silent=True) or {}
        ip = (data.get('ip') or "").strip()
        user = (data.get('username') or "").strip()
        pwd = (data.get('password') or "").strip()
        path = (data.get('path') or "/var/log/messages").strip()
        target_date = data.get('target_date') # Format "YYYY-MM-DD"
        today_only = data.get('today_only', False)

        try:
            limit = int(data.get('limit', 100))
        except Exception:
            return json_error("Limite invalide", 400, code="INVALID_LIMIT")

        if not ip or not user or not pwd:
            return json_error("Identifiants SSH manquants", 400, code="MISSING_SSH_FIELDS")

        # Durcissement basique anti-injection
        limit = max(1, min(limit, 5000))
        if any(c in path for c in [';', '&', '|', '`', '$', '>', '<', '\n', '\r']):
            return json_error("Chemin invalide", 400, code="INVALID_PATH")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=user, password=pwd, timeout=10, banner_timeout=10, auth_timeout=10)

        # Construction de la commande SSH optimisée et multi-format
        if target_date:
            from datetime import datetime
            try:
                dt = datetime.fromisoformat(target_date)
            except ValueError:
                return json_error("Format de date invalide", 400)
            
            # Format Syslog : "Apr 10" ou "Apr  8"
            months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
            m_abbr = months[dt.month-1]
            day_str = f"{dt.day:2d}" 
            date_syslog = f"{m_abbr} {day_str}"
            
            # Autres formats (ISO: 2026-04-10, Slash: 10/04/2026)
            date_iso = dt.strftime("%Y-%m-%d")
            date_slash = dt.strftime("%d/%m/%Y")
            
            regex = "|".join([f"^{date_syslog}", date_iso, date_slash])
            
            # Commande STRICTE pour la date sélectionnée
            command = f"grep -aE '{regex}' {path}"
        elif today_only:
            from datetime import datetime
            dt = datetime.now()
            months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
            m_abbr = months[dt.month-1]
            day_str = f"{dt.day:2d}"
            date_syslog = f"{m_abbr} {day_str}"
            date_iso = dt.strftime("%Y-%m-%d")
            regex = "|".join([f"^{date_syslog}", date_iso])
            command = f"grep -aE '{regex}' {path}"
        else:
            command = f"tail -n {limit} {path}"

        stdin, stdout, stderr = ssh.exec_command(command)
        log_content = stdout.read().decode('utf-8', errors='replace')
        
        if not log_content or not log_content.strip():
            date_label = target_date if target_date else ("aujourd'hui" if today_only else "récents")
            return jsonify({"status": "error", "message": f"Aucun log trouvé pour {date_label}.", "code": "NO_LOGS_FOUND"}), 200

        # Parser les logs
        from src.parser import parse_log_file
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"ssh_{current_user.id}.log")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(log_content)
        
        try:
            results = parse_log_file(temp_path)
        except Exception as pe:
            logger.error(f"Erreur parsing logs: {pe}")
            return json_error("Erreur lors de l'analyse du format des logs.", 500)
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        # Calculer les stats
        stats = {
            "errors": len(results.get('ERROR', [])),
            "warnings": len(results.get('WARNING', [])),
            "info": len(results.get('INFO', [])),
            "total": sum(len(v) for v in results.values())
        }

        # Sauvegarder l'analyse
        analysis = save_analysis_for_current_user(
            source_type="ssh",
            source_path=path,
            server_ip=ip,
            stats=stats,
            segments=results,
            meta={"target_date": target_date, "today_only": today_only},
            log_content=log_content
        )

        # Enregistrer ou mettre à jour le profil serveur pour Quick Connect
        try:
            save_or_update_ssh_profile(
                user_id=current_user.id,
                ip=ip,
                username=user,
                password=pwd,
                log_path=path
            )
        except Exception as e:
            logger.error(f"Erreur profil SSH: {e}")

        return jsonify({
            "status": "success",
            "message": "Analyse SSH terminée",
            "stats": stats,
            "analysis_id": analysis.id
        })

    except paramiko.AuthenticationException:
        return json_error("Échec d'authentification SSH", 401, code="SSH_AUTH_FAILED")
    except Exception as e:
        traceback.print_exc()
        logger.error(f"[SSH ANALYZE ERROR] {str(e)}")
        return json_error(f"Erreur lors de l'analyse : {str(e)}", 500, code="SSH_ANALYZE_FAILED")
    finally:
        if ssh:
            try:
                ssh.close()
            except:
                pass

@app.route('/terminal/exec', methods=['POST'])
@admin_required
def terminal_exec():
    ssh = None
    try:
        data = request.get_json(silent=True) or {}
        command = (data.get('command') or "").strip()

        # Récupération des identifiants directement du payload JSON (Indépendance du formulaire d'analyse)
        ip = (data.get('host') or "").strip()
        user = (data.get('user') or "").strip()
        pwd = data.get('pass') or ""

        # Vérification des informations de connexion SSH fournies
        if not ip or not user or not pwd:
            return json_error("Veuillez renseigner le Host, User et Pass dans le terminal.", 400, code="MISSING_TERMINAL_CREDENTIALS")

        if not command:
            return json_error("Commande manquante", 400, code="MISSING_COMMAND")

        # Bloquer les commandes interactives
        interactive_cmds = ['vim', 'nano', 'top', 'htop', 'less', 'more']
        first_word = command.split()[0].lower() if command.split() else ""
        if first_word in interactive_cmds:
            return json_error("L'édition interactive n'est pas supportée dans ce terminal web. Utilisez 'echo' ou 'cat' pour visualiser.", 403, code="INTERACTIVE_COMMAND_NOT_SUPPORTED")

        # Durcissement basique : interdire certaines commandes dangereuses ou bloquantes
        forbidden = ['rm -rf /', 'mkfs', 'dd if=', ':(){ :|:& };:']
        if any(f in command for f in forbidden):
            return json_error("Commande interdite pour des raisons de sécurité", 403, code="FORBIDDEN_COMMAND")

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh.connect(ip, username=user, password=pwd, timeout=10, banner_timeout=10)
        except (paramiko.AuthenticationException, paramiko.SSHException, Exception) as conn_err:
            error_msg = str(conn_err)
            if "getaddrinfo failed" in error_msg:
                error_msg = f"Hôte introuvable ou invalide : {ip}"
            elif "Authentication failed" in error_msg:
                error_msg = "Échec d'authentification (User/Pass incorrect)"
            return json_error(f"Échec de connexion SSH : {error_msg}", 401, code="SSH_CONNECT_FAILED")

        # Configurer l'environnement terminal (TERM=xterm) pour éviter les erreurs de certaines commandes
        full_command = f"export TERM=xterm && {command}"
        stdin, stdout, stderr = ssh.exec_command(full_command, timeout=15)
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')

        return jsonify({
            "status": "success",
            "output": output,
            "error": error
        })
    except Exception as e:
        return json_error(str(e), 500, code="TERMINAL_EXEC_FAILED")
    finally:
        if ssh:
            ssh.close()

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

def get_smtp_config(email_addr: str):
    """
    Détecte automatiquement le serveur SMTP et le port en fonction de l'adresse email.
    Priorise les domaines connus, puis les préfixes standards, et enfin le MX Lookup.
    """
    domain = email_addr.split('@')[-1].lower()
    
    # 1. Mappage prioritaire pour les domaines spécifiques
    microsoft_domains = ['outlook.com', 'hotmail.com', 'outlook.fr', 'hotmail.fr', 'live.com', 'live.fr']
    if domain in microsoft_domains:
        return ('smtp.office365.com', 587)
        
    if domain == 'gmail.com':
        return ('smtp.gmail.com', 587)
        
    # 2. Test des préfixes standards (ex: smtp.domain.com)
    standard_prefixes = ['smtp.', 'mail.']
    for prefix in standard_prefixes:
        try:
            target = prefix + domain
            # Résolution DNS pour vérifier l'existence du serveur
            dns.resolver.resolve(target, 'A')
            return (target, 587) 
        except Exception:
            continue
            
    # 3. Fallback final : DNS Lookup MX
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        # On récupère le serveur MX avec la priorité la plus haute (le premier)
        mx_server = str(answers[0].exchange).rstrip('.')
        return (mx_server, 587)
    except Exception:
        pass
        
    return None, None

def clean_text_for_pdf(text: str) -> str:
    """Nettoie le texte pour la compatibilité avec les polices PDF standards (latin-1)."""
    if not text:
        return ""
    # Remplacement des caractères spéciaux courants non supportés par latin-1
    replacements = {
        '—': '-',   # Em dash
        '–': '-',   # En dash
        '’': "'",   # Smart quote
        '‘': "'",   # Smart quote
        '“': '"',   # Smart double quote
        '”': '"',   # Smart double quote
        '…': '...', # Ellipsis
        '€': 'EUR'  # Euro symbol (optionnel selon besoin)
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    
    # Encodage en latin-1 avec remplacement des caractères inconnus par '?'
    try:
        return text.encode('latin-1', 'replace').decode('latin-1')
    except Exception:
        return str(text)


def generate_pdf_report_bytes(analysis):
    """
    Génère un rapport PDF professionnel à partir d'une analyse.
    """
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # --- Header with Logos ---
        static_img_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "img")
        logo_est_path = os.path.join(static_img_dir, "logo_est.png")
        logo_awb_path = os.path.join(static_img_dir, "logo_awb.png")

        # EST Logo (Top Left) - Increased size to match 65px height
        if os.path.exists(logo_est_path):
            pdf.image(logo_est_path, x=10, y=8, h=17)
        
        # AWB Logo (Top Right) - Increased size to match 55px height
        if os.path.exists(logo_awb_path):
            # A4 is 210mm wide. We align to the right margin
            pdf.image(logo_awb_path, x=165, y=10, h=14)

        # Separate the header from the content
        pdf.set_draw_color(221, 221, 221) # #ddd
        pdf.set_line_width(0.3)
        pdf.line(10, 30, 200, 30)

        # Centered titles below logos
        pdf.set_y(35)
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(17, 24, 39) # Dark blue
        pdf.cell(190, 12, clean_text_for_pdf("RAPPORT D'AUDIT TECHNIQUE"), align="C", ln=True)
        
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(75, 85, 99)
        pdf.cell(190, 10, clean_text_for_pdf("Compte-rendu d'Analyse des Logs"), align="C", ln=True)
        
        pdf.ln(10)
        
        # --- Summary Table ---
        pdf.set_fill_color(249, 250, 251) # Light gray background
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(17, 24, 39)
        pdf.cell(190, 10, clean_text_for_pdf("1. Résumé de l'analyse"), fill=True, ln=True)
        pdf.ln(2)
        
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(55, 65, 81)
        
        # Grid layout for summary
        stats = analysis.stats or {}
        rows = [
            ("Date du rapport", datetime.now().strftime('%d/%m/%Y %H:%M')),
            ("Fichier Source", analysis.source_path or "/var/log/syslog"),
            ("Serveur Cible (IP)", analysis.server_ip or "Localhost"),
            ("Total lignes analysées", str(stats.get('total', 0)))
        ]
        
        for label, value in rows:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(60, 8, clean_text_for_pdf(label), border='B')
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(130, 8, clean_text_for_pdf(value), border='B', ln=True)
        pdf.ln(10)
        
        # --- Statistics Breakdown ---
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(17, 24, 39)
        pdf.cell(190, 10, clean_text_for_pdf("2. Statistiques Globales"), ln=True)
        
        # Stats table
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(243, 244, 246)
        pdf.cell(47.5, 8, clean_text_for_pdf("Total"), 1, 0, 'C', True)
        pdf.cell(47.5, 8, clean_text_for_pdf("Erreurs"), 1, 0, 'C', True)
        pdf.cell(47.5, 8, clean_text_for_pdf("Warnings"), 1, 0, 'C', True)
        pdf.cell(47.5, 8, clean_text_for_pdf("Infos"), 1, 1, 'C', True)
        
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(47.5, 8, str(stats.get('total', 0)), 1, 0, 'C')
        pdf.set_text_color(220, 38, 38) # Red for errors
        pdf.cell(47.5, 8, str(stats.get('errors', 0)), 1, 0, 'C')
        pdf.set_text_color(217, 119, 6) # Amber for warnings
        pdf.cell(47.5, 8, str(stats.get('warnings', 0)), 1, 0, 'C')
        pdf.set_text_color(37, 99, 235) # Blue for info
        pdf.cell(47.5, 8, str(stats.get('info', 0)), 1, 1, 'C')
        pdf.set_text_color(17, 24, 39)
        pdf.ln(10)
        
        # --- Top 10 Patterns ---
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(190, 10, clean_text_for_pdf("3. Analyse de Récurrence (Top 10 Patterns)"), ln=True)
        
        segments = analysis.segments or {}
        all_lines = (segments.get('ERROR', []) + segments.get('WARNING', []) + segments.get('INFO', []))
        
        counts = {}
        for line in all_lines:
            # Nettoyage du message (ignorer timestamp au début)
            # Format attendu: "Apr 11 12:34:56 host process[pid]: message"
            cleaned = str(line).split(' ', 3)[-1].strip() if ' ' in str(line) else str(line)
            counts[cleaned] = counts.get(cleaned, 0) + 1
            
        sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Header table patterns
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_fill_color(243, 244, 246)
        pdf.cell(150, 8, clean_text_for_pdf("Message de Log (Pattern)"), 1, 0, 'L', True)
        pdf.cell(40, 8, clean_text_for_pdf("Occurrences"), 1, 1, 'C', True)
        
        pdf.set_font("Courier", "", 8)
        for msg, count in sorted_counts:
            # Re-calculer x,y pour multi_cell
            curr_x, curr_y = pdf.get_x(), pdf.get_y()
            
            # multi_cell pour le message (largeur 150)
            cleaned_msg = clean_text_for_pdf(str(msg)[:300]) # Tronquer si trop long
            pdf.multi_cell(150, 5, cleaned_msg, border=1)
            new_y = pdf.get_y()
            
            # Revenir à droite pour les occurrences
            pdf.set_xy(curr_x + 150, curr_y)
            pdf.cell(40, new_y - curr_y, str(count), border=1, ln=True, align='C')
        pdf.ln(10)
        
        # --- Details Errors (Optional but nice) ---
        if stats.get('errors', 0) > 0:
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(190, 10, clean_text_for_pdf("4. Détails des premières erreurs"), ln=True)
            pdf.set_font("Courier", "", 8)
            
            errors = segments.get('ERROR', [])[:15]
            for err in errors:
                cleaned_err = clean_text_for_pdf(str(err))
                pdf.multi_cell(190, 5, cleaned_err, border=1, ln=True)
        
        # --- AI Actions & Prevention (New Section) ---
        meta = analysis.meta or {}
        actions = meta.get('corrective_actions', [])
        preventions = meta.get('prevention_steps', [])
        
        if actions or preventions:
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(17, 24, 39)
            pdf.cell(190, 10, clean_text_for_pdf("5. Recommandations de l'Intelligence Artificielle"), ln=True)
            pdf.ln(5)
            
            if actions:
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(220, 38, 38)
                pdf.cell(190, 8, clean_text_for_pdf("Actions Correctives Immédiates :"), ln=True)
                pdf.set_font("Helvetica", "", 10)
                pdf.set_text_color(55, 65, 81)
                for action in actions:
                    pdf.multi_cell(190, 6, clean_text_for_pdf(f"- {action}"), ln=True)
                pdf.ln(5)
                
            if preventions:
                pdf.set_font("Helvetica", "B", 11)
                pdf.set_text_color(37, 99, 235)
                pdf.cell(190, 8, clean_text_for_pdf("Préventions & Optimisations :"), ln=True)
                pdf.set_font("Helvetica", "", 10)
                pdf.set_text_color(55, 65, 81)
                for prev in preventions:
                    pdf.multi_cell(190, 6, clean_text_for_pdf(f"- {prev}"), ln=True)
                pdf.ln(10)

        # --- User Signature Section ---
        user = db.session.get(User, analysis.user_id)
        if user and user.signature_path:
            # S'assurer qu'on ne signe pas sur une page vide si on est trop bas
            if pdf.get_y() > 230:
                pdf.add_page()
            
            # Utiliser le chemin absolu direct vers le dossier uploads
            base_upload_path = os.path.abspath(app.config['UPLOAD_FOLDER'])
            sig_full_path = os.path.join(base_upload_path, user.signature_path)
            
            if os.path.exists(sig_full_path):
                # On mémorise la position Y actuelle
                y_before = pdf.get_y() + 10
                
                # Aligner la mention à droite
                pdf.set_y(y_before)
                pdf.set_x(130) # Se déplacer vers la droite
                pdf.set_font("Helvetica", "B", 10)
                pdf.set_text_color(17, 24, 39)
                pdf.cell(70, 10, clean_text_for_pdf("Signé électroniquement par l'expert :"), 0, 1, 'C')
                
                # Insertion de l'image PNG avec support de la transparence (type='PNG' forcé)
                # L'image juste en dessous (x=150 pour la droite)
                y_img = pdf.get_y()
                pdf.image(sig_full_path, x=150, y=y_img, w=40, type='PNG')
                
                # On repositionne le curseur pour que le texte (Nom/Email) s'écrive juste en dessous
                pdf.set_y(y_img + 20)
                
                pdf.set_font("Helvetica", "I", 9)
                pdf.set_text_color(107, 114, 128)
                # Informations de l'expert alignées à droite
                pdf.cell(190, 5, clean_text_for_pdf(f"Expert : {user.username} ({user.email})"), ln=True, align='R')
                pdf.cell(190, 5, clean_text_for_pdf(f"Date de signature : {datetime.now().strftime('%d/%m/%Y %H:%M')}"), ln=True, align='R')

        # --- Footer ---
        pdf.set_y(-15)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(156, 163, 175)
        pdf.cell(190, 10, clean_text_for_pdf("Document d'Audit Technique - LogAnalyzer PFE_ESTSB_AWB - Confidentiel"), align="C")

        return pdf.output()
    except Exception as e:
        print(f"PDF Generation Error: {str(e)}")
        raise e

@app.route('/download-pdf/<int:analysis_id>')
@login_required
def download_pdf_report(analysis_id):
    # Règle Métier : Vérifier si l'utilisateur a une signature avant de générer
    if not current_user.signature_path:
        flash("Action impossible : Vous devez d'abord ajouter votre signature dans votre profil pour valider les rapports.", "danger")
        return redirect(url_for("profile"))

    analysis = Analysis.query.filter_by(id=analysis_id, user_id=current_user.id).first()
    if not analysis:
        return "Analyse introuvable", 404

    try:
        pdf_bytes = generate_pdf_report_bytes(analysis)
        output = io.BytesIO(pdf_bytes)
        output.seek(0)
        
        return send_file(
            output,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f"Rapport_Audit_{analysis_id}.pdf"
        )
    except Exception as e:
        return f"Erreur lors de la génération du PDF : {str(e)}", 500


@app.route('/api/reports/latest')
@login_required
def get_latest_report():
    """Renvoie les données de la dernière analyse de l'utilisateur."""
    analysis_id = session.get('last_analysis_id')
    analysis = None
    if analysis_id:
        analysis = Analysis.query.filter_by(id=analysis_id, user_id=current_user.id).first()
    if not analysis:
        analysis = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created_at.desc()).first()
    
    if not analysis:
        return jsonify({"status": "error", "message": "Aucune analyse trouvée"}), 404
        
    return jsonify({
        "status": "success",
        "report": {
            "analysis_id": analysis.id,
            "stats": analysis.stats,
            "segments": analysis.segments,
            "meta": analysis.meta,
            "generated_at": analysis.created_at.isoformat()
        }
    })

@app.route('/api/send-report-email', methods=['POST'])
@login_required
def send_report_email():
    """
    Envoie le rapport PDF complet via le SMTP serveur.
    Supporte Gmail avec App Password (16 caractères).
    """
    import traceback
    try:
        data = request.get_json() or {}
        analysis_id = data.get('analysis_id')
        recipient = data.get('recipient') or data.get('email') or current_user.notification_email or current_user.email
        
        # Récupération des variables de configuration SMTP avec flexibilité (Optionnel)
        # On essaie d'abord les données envoyées par le frontend (email_source/app_password)
        # Sinon on se replie sur les variables d'environnement.
        smtp_user = data.get('sender_email') or data.get('email_source') or os.getenv("MAIL_USERNAME") or os.getenv("SMTP_USER") or current_user.email
        smtp_pass = data.get('app_password') or os.getenv("MAIL_PASSWORD") or os.getenv("SMTP_PASS")
        
        smtp_server = os.getenv("MAIL_SERVER", "smtp.gmail.com")
        smtp_port = int(os.getenv("MAIL_PORT", 587))
        use_tls = os.getenv("MAIL_USE_TLS", "True").lower() == "true"

        logger.info(f"[EMAIL] Tentative d'envoi à {recipient} depuis {smtp_user} via {smtp_server}:{smtp_port} (Auth: {'Oui' if smtp_pass else 'Non'})")

        if not recipient:
            return jsonify({"success": False, "message": "Email du destinataire manquant."}), 400
            
        if not analysis_id:
            return jsonify({"success": False, "message": "ID d'analyse manquant."}), 400
        
        analysis = Analysis.query.filter_by(id=analysis_id, user_id=current_user.id).first()
        if not analysis:
            return jsonify({"success": False, "message": f"Rapport {analysis_id} introuvable."}), 404

        # 1. Génération du PDF
        try:
            pdf_content = generate_pdf_report_bytes(analysis)
        except Exception as ge:
            logger.error(f"Erreur génération PDF: {ge}")
            return jsonify({"success": False, "message": "Erreur lors de la création du fichier PDF."}), 500
        
        # 2. Préparation du message
        subject = data.get('subject') or f"Rapport d'Audit Logs - {analysis.server_ip or 'Local'}"
        message_notes = data.get('message') or ""
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <h2>Rapport d'analyse LogAnalyzer</h2>
            <p>Bonjour,</p>
            <p>Voici le rapport d'analyse pour le serveur <strong>{analysis.server_ip or 'Local'}</strong>.</p>
            <ul>
                <li><strong>Score de sécurité :</strong> {analysis.ai_score}/100</li>
                <li><strong>Statut :</strong> {analysis.ai_status}</li>
                <li><strong>Date :</strong> {analysis.created_at.strftime('%d/%m/%Y %H:%M')}</li>
            </ul>
            {f'<p><strong>Note de l\'analyste :</strong> {message_notes}</p>' if message_notes else ''}
            <p>Le rapport détaillé est joint à cet email au format PDF.</p>
            <hr>
            <p style="font-size: 0.8em; color: #666;">Envoyé automatiquement par LogAnalyzer SOC.</p>
        </body>
        </html>
        """
        
        msg = MIMEMultipart("mixed")
        msg['Subject'] = subject
        msg['To'] = recipient
        msg['From'] = smtp_user
        msg.attach(MIMEText(html_body, 'html'))
        
        attachment = MIMEApplication(pdf_content)
        attachment.add_header('Content-Disposition', 'attachment', filename=f"Rapport_Audit_{analysis_id}.pdf")
        msg.attach(attachment)

        # 3. Envoi via SMTP avec capture d'erreur robuste
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP(smtp_server, smtp_port, timeout=20) as server:
                if use_tls:
                    server.starttls(context=context)
                
                # AUTHENTIFICATION CONDITIONNELLE
                if smtp_pass:
                    try:
                        server.login(smtp_user, smtp_pass)
                        logger.info(f"[EMAIL] Authentification réussie pour {smtp_user}")
                    except smtplib.SMTPAuthenticationError as auth_err:
                        logger.error(f"SMTP Auth Error: {auth_err}")
                        return jsonify({
                            "success": False, 
                            "message": "Authentification SMTP échouée. Vérifiez vos identifiants ou le 'App Password'."
                        }), 401
                else:
                    logger.info(f"[EMAIL] Envoi sans authentification (Relais SMTP)")
                
                server.send_message(msg)
            
            return jsonify({"success": True, "message": f"Email envoyé avec succès à {recipient} !"})
            
        except smtplib.SMTPException as se:
            logger.error(f"Erreur SMTP: {se}")
            return jsonify({"success": False, "message": f"Erreur lors de l'envoi de l'email : {str(se)}"}), 500
        except Exception as smtp_e:
            logger.error(f"Erreur SMTP Inconnue: {smtp_e}")
            return jsonify({"success": False, "message": f"Erreur de connexion SMTP : {str(smtp_e)}"}), 500
            
    except Exception as e:
        traceback.print_exc()
        logger.error(f"[EMAIL ERROR] {str(e)}")
        return jsonify({"success": False, "message": f"Erreur interne : {str(e)}"}), 500
        return jsonify({"success": False, "message": f"Erreur interne lors de l'envoi : {str(e)}"}), 500
        
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
    Envoie un email via SMTP Gmail avec les paramètres de l'application.
    """
    server_host = app.config.get('MAIL_SERVER', 'smtp.gmail.com')
    server_port = app.config.get('MAIL_PORT', 587)
    use_tls = app.config.get('MAIL_USE_TLS', True)
    
    context = ssl.create_default_context()
    
    try:
        # Initialisation de la connexion SMTP uniquement lors de l'envoi
        with smtplib.SMTP(server_host, server_port, timeout=20) as server:
            if use_tls:
                server.starttls(context=context)
            server.login(sender_email, app_password)
            server.send_message(msg)
    except Exception as e:
        print(f"[SMTP Error] {str(e)}")
        raise e

@app.route('/send-email', methods=['POST'])
@login_required
def send_email():
    """Version simplifiée de l'envoi d'email utilisant le SMTP serveur."""
    try:
        data = request.get_json(silent=True) or {}
        dest_email = data.get('email') or data.get('dest_email') or current_user.notification_email or current_user.email
        subject = data.get('subject') or "Rapport LogAnalyzer"
        message = data.get('message') or ""
        
        if not dest_email:
            return jsonify({"success": False, "message": "Email de destination manquant."}), 400

        success = send_user_notification(current_user, subject, f"<html><body>{message}</body></html>")
        
        if success:
            return jsonify({"success": True, "message": f"Email envoyé à {dest_email}"})
        else:
            return jsonify({"success": False, "message": "Échec de l'envoi."}), 500
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

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

@app.route('/profile/update_notifications', methods=['POST'])
@login_required
def update_profile_notifications():
    """Met à jour les préférences de notification de l'utilisateur."""
    try:
        enabled = request.form.get('email_notifications_enabled') == 'on'
        email = request.form.get('notification_email', '').strip()
        
        current_user.email_notifications_enabled = enabled
        current_user.notification_email = email
        
        db.session.commit()
        flash("Préférences de notification mises à jour.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erreur lors de la mise à jour : {e}", "danger")
    
    return redirect(url_for('profile'))

@app.route('/jobs/<int:job_id>/history', methods=['GET'])
@app.route('/api/jobs/<int:job_id>/history', methods=['GET'])
@login_required
def get_job_history(job_id: int):
    """Récupère l'historique des analyses pour un job spécifique."""
    job = AnalysisJob.query.get(job_id)
    if not job:
        return jsonify({"success": False, "message": "Job introuvable"}), 404
    
    if job.user_id != current_user.id and not current_user.is_admin:
        return jsonify({"success": False, "message": "Accès refusé"}), 403
    
    history = []
    for analysis in job.history.order_by(Analysis.created_at.desc()).all():
        history.append({
            "id": analysis.id,
            "created_at": analysis.created_at.isoformat(),
            "ai_status": analysis.ai_status,
            "ai_score": analysis.ai_score,
            "ai_menaces": analysis.ai_menaces
        })
    
    return jsonify({
        "success": True,
        "job_id": job.id,
        "target_ip": job.target_ip,
        "history": history
    })

# --- ROUTES DE PLANIFICATION D'ANALYSES ---

@app.route('/admin/scheduled-jobs', methods=['GET'])
@admin_required
def list_scheduled_jobs():
    """Liste toutes les tâches d'analyse planifiées"""
    jobs = AnalysisJob.query.order_by(AnalysisJob.created_at.desc()).all()
    return render_template('admin_scheduled_jobs.html', jobs=jobs)

# --- ROUTE DE CRÉATION DE TÂCHE PLANIFIÉE ---

@app.route('/admin/job/create', methods=['POST'])
@login_required
def create_scheduled_job():
    try:
        # 1. Récupération des données (Indentation correcte: 8 spaces)
        target_ip = (request.form.get('target_ip') or "").strip()
        log_path = (request.form.get('log_path') or "/var/log/syslog").strip()
        frequency = (request.form.get('frequency') or "daily").strip()
        custom_minutes = request.form.get('custom_minutes')
        ssh_username = (request.form.get('ssh_username') or "").strip()
        ssh_password = request.form.get('ssh_password') or ""
        notification_email = (request.form.get('notification_email') or "").strip()
        
        # 2. Validation des champs obligatoires
        if not target_ip or not ssh_username or not ssh_password:
            return jsonify({"success": False, "message": "Champs obligatoires manquants."}), 400
        
        # 3. Validation de la fréquence (C'était ici l'erreur de syntaxe)
        valid_frequencies = ('hourly', 'daily', 'weekly', 'monthly', 'custom')
        if frequency not in valid_frequencies:
            return jsonify({"success": False, "message": "Fréquence invalide."}), 400

        # 4. Gestion du cas "custom"
        interval_val = None
        if frequency == 'custom':
            if not custom_minutes or not str(custom_minutes).isdigit():
                return jsonify({"success": False, "message": "Minutes invalides."}), 400
            interval_val = int(custom_minutes)

        # 5. Validation de l'IP (Import local pour la propreté)
        import re
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target_ip):
            return jsonify({"success": False, "message": "Format IP invalide."}), 400
        
        # 6. Chiffrement du mot de passe
        try:
            fernet_key = os.getenv("FERNET_KEY")
            if not fernet_key:
                return jsonify({"success": False, "message": "Clé de sécurité manquante."}), 500
            
            f = Fernet(fernet_key.encode() if isinstance(fernet_key, str) else fernet_key)
            encrypted_password = f.encrypt(ssh_password.encode()).decode()
        except Exception as e:
            return jsonify({"success": False, "message": "Erreur chiffrement."}), 500
        
        # 7. Sauvegarde dans la DB
        try:
            job = AnalysisJob(
                user_id=current_user.id,
                target_ip=target_ip,
                log_path=log_path,
                frequency=frequency,
                custom_minutes=interval_val,
                ssh_username=ssh_username,
                ssh_password_enc=encrypted_password,
                notification_email=notification_email or None,
                status='pending',
                admin_notified=False
            )
            db.session.add(job)
            db.session.commit()
            
            # Notification à l'admin (optionnel, si configuré)
            admin_users = User.query.filter_by(role='Admin').all()
            for admin in admin_users:
                if admin.email:
                    subject = f"Nouvelle demande d'analyse planifiée - {target_ip}"
                    content = f"""
                    <h2>Nouvelle demande d'analyse planifiée</h2>
                    <p>L'utilisateur <strong>{current_user.username}</strong> a créé une nouvelle demande d'analyse pour le serveur <strong>{target_ip}</strong>.</p>
                    <p>Veuillez vous connecter à l'interface d'administration pour approuver ou refuser cette demande.</p>
                    """
                    send_notification(admin.email, subject, content)
            
            return jsonify({"success": True, "message": "Demande envoyée", "job_id": job.id}), 201
            
        except Exception as e:
            db.session.rollback()
            return jsonify({"success": False, "message": f"Erreur DB: {str(e)}"}), 500
    
    except Exception as e:
        return jsonify({"success": False, "message": f"Erreur serveur: {str(e)}"}), 500


@app.route('/admin/approve_job', methods=['POST'])
@app.route('/admin/job/<int:job_id>/approve', methods=['POST'])
@admin_required
def approve_analysis_job(job_id: int = None):
    # Gérer les deux routes (avec paramètre ou via form)
    if job_id is None:
        job_id = request.form.get('job_id') or request.json.get('job_id')
    
    if not job_id:
        return jsonify({"success": False, "message": "ID de tâche manquant."}), 400

    from datetime import datetime, timezone
    from models import AnalysisJob

    try:
        job = AnalysisJob.query.get(job_id)
        if not job:
            return jsonify({"success": False, "message": "Tâche introuvable."}), 404

        if job.status == 'active':
            return jsonify({"success": True, "message": "La tâche est déjà active."})

        job.status = 'active'
        job.approved_at = datetime.now(timezone.utc)
        job.next_run_at = datetime.now(timezone.utc)
        job.user_notified = False

        # Notification à l'utilisateur
        subject = "Votre tâche d'analyse a été approuvée"
        content = f"Votre demande d'analyse planifiée pour {job.target_ip} a été approuvée par un administrateur."
        send_user_notification(job.user, subject, content)

        # Si fréquence custom, utiliser interval, sinon cron
        from scheduler import scheduler
        if job.frequency == 'custom' and job.custom_minutes:
            scheduler.add_job(
                func=run_planned_analysis,
                trigger='interval',
                minutes=job.custom_minutes,
                args=[job_id],
                id=f'job_{job_id}',
                name=f'Analyse Planifiée {job_id}',
                replace_existing=True
            )
        else:
            trigger_map = {
                'hourly':  {'hour': '*'},
                'daily':   {'hour': 2,  'minute': 0},
                'weekly':  {'day_of_week': 'mon', 'hour': 2, 'minute': 0},
                'monthly': {'day': 1,   'hour': 2, 'minute': 0},
            }
            cron_params = trigger_map.get(job.frequency, {'hour': 2, 'minute': 0})

            scheduler.add_job(
                func=run_planned_analysis,
                trigger='cron',
                args=[job_id],
                id=f'job_{job_id}',
                name=f'Analyse Planifiée {job_id}',
                replace_existing=True,
                **cron_params
            )

        db.session.commit()
        return jsonify({"success": True, "message": "Tâche approuvée et programmée."})

    except Exception as e:
        db.session.rollback()
        print(f"[APPROVE ERROR] {e}")
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/admin/job/<int:job_id>/refuse', methods=['POST'])
@admin_required
def refuse_analysis_job(job_id: int):
    """Refuser une tâche d'analyse planifiée"""
    try:
        job = AnalysisJob.query.get(job_id)
        if not job:
            return jsonify({"success": False, "message": "Tâche introuvable"}), 404
        
        reason = (request.form.get('reason') or request.json.get('reason', "")).strip()
        
        job.status = 'refused'
        job.refusal_reason = reason
        job.user_notified = False
        
        # Notification à l'utilisateur
        subject = "Votre tâche d'analyse a été refusée"
        content = f"Votre demande d'analyse planifiée pour {job.target_ip} a été refusée par l'administrateur.<br>Raison : {reason}"
        send_user_notification(job.user, subject, content)
            
        db.session.commit()
        flash(f"Tâche {job_id} refusée.", "info")
        return jsonify({"success": True, "message": "Tâche refusée"})
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/jobs/<int:job_id>/stop', methods=['POST'])
@login_required
def stop_analysis_job(job_id: int):
    """Arrêter une tâche planifiée"""
    from scheduler import scheduler
    
    try:
        job = AnalysisJob.query.get(job_id)
        if not job:
            return jsonify({"success": False, "message": "Tâche introuvable"}), 404
        
        # Vérifier que l'utilisateur est le propriétaire ou admin
        if job.user_id != current_user.id and not current_user.is_admin:
            return jsonify({"success": False, "message": "Accès refusé"}), 403
        
        job.status = 'stopped'
        
        # Supprimer du scheduler
        try:
            scheduler.remove_job(f'job_{job_id}')
        except Exception:
            pass  # La tâche n'existait peut-être pas
        
        db.session.commit()
        flash(f"Tâche {job_id} arrêtée.", "success")
        return jsonify({"success": True, "message": "Tâche arrêtée avec succès"})
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# --- ROUTES DE PLANIFICATION D'ANALYSES ---

@app.route('/api/jobs', methods=['GET'])
@login_required
def api_get_jobs():
    """Récupérer les tâches de l'utilisateur actuel (approuvées uniquement pour la planification)"""
    # Filtrer par user_id et par statut 'active' (ou selon ta logique d'approbation)
    jobs = AnalysisJob.query.filter(
        AnalysisJob.user_id == current_user.id,
        AnalysisJob.status == 'active'
    ).order_by(AnalysisJob.created_at.desc()).all()
    
    return jsonify({
        "status": "success",
        "jobs": [
            {
                "id": j.id,
                "target_ip": j.target_ip,
                "log_path": j.log_path,
                "frequency": j.frequency,
                "status": j.status,
                "created_at": j.created_at.isoformat(),
                "next_run_at": j.next_run_at.isoformat() if j.next_run_at else None,
                "last_run_at": j.last_run_at.isoformat() if j.last_run_at else None
            }
            for j in jobs
        ]
    })

# --- ROUTE DASHBOARD AVEC SCHEDULED JOBS ---

@app.route('/dashboard')
@login_required
def dashboard():
    """
    Affiche le tableau de bord avec les jobs d'analyse planifiés de l'utilisateur.
    """
    # Récupération de l'ID d'analyse depuis la session ou la dernière en base
    analysis_id = session.get('last_analysis_id')
    last_analysis = None
    
    if analysis_id:
        last_analysis = Analysis.query.filter_by(id=analysis_id, user_id=current_user.id).first()
    
    if not last_analysis:
        last_analysis = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created_at.desc()).first()

    # Statistiques globales
    total_audits = Analysis.query.filter_by(user_id=current_user.id).count()
    active_servers = db.session.query(Analysis.server_ip).filter(
        Analysis.user_id == current_user.id,
        Analysis.server_ip != None
    ).distinct().count()
    
    # Récupération des 5 dernières analyses
    recent_analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created_at.desc()).limit(5).all()
    
    # Menaces critiques
    critical_threats = sum((a.ai_menaces if a.ai_menaces is not None else int(a.stats.get('errors', 0))) 
                          for a in recent_analyses)
    
    # Score de santé système
    scores = [(a.ai_score if a.ai_score is not None else _global_health_score(a.stats)) 
             for a in recent_analyses]
    system_health = round(sum(scores) / len(scores)) if scores else 100

    results = None
    if last_analysis:
        results = {
            "status": "success",
            "analysis_id": last_analysis.id,
            "meta": last_analysis.meta,
            "segments": last_analysis.segments,
            "stats": last_analysis.stats,
            "ai_score": last_analysis.ai_score,
            "ai_status": last_analysis.ai_status,
            "ai_menaces": last_analysis.ai_menaces,
            "generated_at": last_analysis.created_at.isoformat()
        }
        session['last_analysis_id'] = last_analysis.id
    
    # Récupérer TOUS les jobs planifiés de l'utilisateur (tous statuts)
    scheduled_jobs = AnalysisJob.query.filter(
        AnalysisJob.user_id == current_user.id
    ).order_by(AnalysisJob.created_at.desc()).all()
    
    return render_template(
        'index.html',
        analysis_data=results,
        total_audits=total_audits,
        active_servers=active_servers,
        critical_threats=critical_threats,
        system_health=system_health,
        recent_activities=recent_analyses,
        scheduled_jobs=scheduled_jobs  # ← Passer les jobs au template
    )

@app.route('/api/job/<int:job_id>', methods=['GET'])
@admin_required
def api_get_job(job_id: int):
    """Récupère les détails d'une tâche planifiée"""
    job = AnalysisJob.query.get(job_id)
    if not job:
        return jsonify({"success": False, "message": "Tâche introuvable"}), 404
    
    return jsonify({
        "success": True,
        "job": {
            "id": job.id,
            "target_ip": job.target_ip,
            "log_path": job.log_path,
            "frequency": job.frequency,
            "status": job.status,
            "refusal_reason": job.refusal_reason,
            "user_username": job.user.username,
            "created_at": job.created_at.isoformat()
        }
    })

@app.route('/api/stats', methods=['GET'])
@login_required
def api_stats():
    period = request.args.get('period', '7d')
    now = datetime.now(timezone.utc)
    until = now # Par défaut

    # ── Configuration de la plage et du formatage ──
    if period == '24h':
        since = now - timedelta(hours=24)
        group_fmt = '%H:00'
        step = timedelta(hours=2)
    elif period == '7d':
        since = now - timedelta(days=7)
        group_fmt = '%d %b'
        step = timedelta(days=1)
    elif period == 'weekend':
        days_since_sat = (now.weekday() - 5) % 7
        since = (now - timedelta(days=days_since_sat)).replace(hour=0, minute=0, second=0)
        group_fmt = '%a %Hh'
        step = timedelta(hours=6)
    elif period == 'custom':
        try:
            start_date_str = request.args.get('start_date')
            end_date_str = request.args.get('end_date')
            
            if not start_date_str or not end_date_str:
                return jsonify({"error": "Dates de début et de fin requises"}), 400
                
            since = datetime.fromisoformat(start_date_str.replace('T', ' ')).replace(tzinfo=timezone.utc)
            until = datetime.fromisoformat(end_date_str.replace('T', ' ')).replace(tzinfo=timezone.utc)
            
            # Définition flexible de group_fmt pour le mode custom
            diff = until - since
            if diff.days <= 1:
                group_fmt = '%H:00'
                step = timedelta(hours=1)
            elif diff.days <= 31:
                group_fmt = '%d %b'
                step = timedelta(days=1)
            else:
                group_fmt = '%b %Y'
                step = timedelta(days=30)
        except (ValueError, TypeError) as e:
            return jsonify({"error": f"Dates invalides: {str(e)}"}), 400
    else:
        return jsonify({"error": "Période invalide"}), 400

    # ── Requête Base de données ──
    analyses = Analysis.query.filter(
        Analysis.user_id == current_user.id,
        Analysis.created_at >= since,
        Analysis.created_at <= until
    ).all()

    # ── Initialisation des Buckets (Stats par catégorie) ──
    buckets = {}
    cursor = since
    while cursor <= until:
        label = cursor.strftime(group_fmt)
        if label not in buckets:
            buckets[label] = {"Critique": 0, "Avertissement": 0, "Info": 0, "total_logs": 0, "total_errors": 0, "total_warnings": 0}
        cursor += step

    # ── Remplissage des données ──
    for a in analyses:
        label = a.created_at.strftime(group_fmt)
        if label not in buckets:
            buckets[label] = {"Critique": 0, "Avertissement": 0, "Info": 0, "total_logs": 0, "total_errors": 0, "total_warnings": 0}
        
        # 1. Stats par Analyse (pour le graphique à barres existant)
        status = str(a.ai_status or "").lower()
        if 'critique' in status or 'danger' in status:
            buckets[label]['Critique'] += 1
        elif 'attention' in status or 'warning' in status:
            buckets[label]['Avertissement'] += 1
        else:
            buckets[label]['Info'] += 1
            
        # 2. Agrégation des volumes réels (pour les compteurs du dashboard)
        astats = a.stats or {}
        buckets[label]['total_logs'] += int(astats.get('total', 0))
        buckets[label]['total_errors'] += int(astats.get('errors', 0))
        buckets[label]['total_warnings'] += int(astats.get('warnings', 0))

    # Trier les buckets par date pour l'affichage
    sorted_labels = sorted(buckets.keys(), key=lambda x: datetime.strptime(x, group_fmt) if '%' in group_fmt else x)
    
    return jsonify({
        "labels": sorted_labels,
        "critique": [buckets[lb]['Critique'] for lb in sorted_labels],
        "avertissement": [buckets[lb]['Avertissement'] for lb in sorted_labels],
        "info": [buckets[lb]['Info'] for lb in sorted_labels],
        "total_logs": sum(buckets[lb]['total_logs'] for lb in sorted_labels),
        "total_errors": sum(buckets[lb]['total_errors'] for lb in sorted_labels),
        "total_warnings": sum(buckets[lb]['total_warnings'] for lb in sorted_labels)
    })

# --- GESTION DES PROFILS SERVEURS SSH ---

def _get_fernet():
    key = os.getenv("FERNET_KEY")
    if not key:
        # Fallback pour le développement, mais devrait être dans .env
        key = Fernet.generate_key().decode()
    return Fernet(key.encode())

@app.route('/api/ssh/profiles', methods=['GET'])
@login_required
def get_ssh_profiles():
    """Récupère les serveurs enregistrés de l'utilisateur."""
    from models import SavedServer
    profiles = SavedServer.query.filter_by(user_id=current_user.id).order_by(SavedServer.last_used_at.desc()).all()
    
    # Déchiffrement du nom d'utilisateur pour l'affichage (pas le mot de passe)
    f = _get_fernet()
    
    return jsonify({
        "success": True,
        "profiles": [
            {
                "id": p.id,
                "ip": p.ip,
                "username": f.decrypt(p.encrypted_username.encode()).decode(),
                "log_path": p.log_path,
                "last_used_at": p.last_used_at.isoformat() if p.last_used_at else None
            }
            for p in profiles
        ]
    })

@app.route('/api/ssh/profiles/<int:profile_id>/decrypt', methods=['POST'])
@login_required
def decrypt_ssh_profile(profile_id):
    """Déchiffre le nom d'utilisateur et le mot de passe d'un serveur pour remplissage auto."""
    from models import SavedServer
    profile = SavedServer.query.filter_by(id=profile_id, user_id=current_user.id).first()
    
    if not profile:
        return jsonify({"success": False, "message": "Serveur introuvable"}), 404
        
    try:
        f = _get_fernet()
        username = f.decrypt(profile.encrypted_username.encode()).decode()
        password = f.decrypt(profile.encrypted_password.encode()).decode()
        return jsonify({
            "success": True,
            "username": username,
            "password": password
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Erreur de déchiffrement : {str(e)}"}), 500

@app.route('/api/ssh/profiles/<int:profile_id>', methods=['DELETE'])
@login_required
def delete_ssh_profile(profile_id):
    """Supprime un serveur enregistré."""
    from models import SavedServer
    profile = SavedServer.query.filter_by(id=profile_id, user_id=current_user.id).first()
    
    if not profile:
        return jsonify({"success": False, "message": "Serveur introuvable"}), 404
        
    db.session.delete(profile)
    db.session.commit()
    return jsonify({"success": True, "message": "Serveur supprimé"})

def save_or_update_ssh_profile(user_id, ip, username, password, log_path):
    """Enregistre ou met à jour un serveur après une connexion réussie."""
    from models import SavedServer
    
    # Chiffrement AES-256
    f = _get_fernet()
    enc_user = f.encrypt(username.encode()).decode()
    enc_pass = f.encrypt(password.encode()).decode()
    
    profile = SavedServer.query.filter_by(user_id=user_id, ip=ip, log_path=log_path).first()
    
    if profile:
        profile.encrypted_username = enc_user
        profile.encrypted_password = enc_pass
        profile.last_used_at = datetime.now(timezone.utc)
    else:
        profile = SavedServer(
            user_id=user_id,
            ip=ip,
            encrypted_username=enc_user,
            encrypted_password=enc_pass,
            log_path=log_path,
            last_used_at=datetime.now(timezone.utc)
        )
        db.session.add(profile)
        
    db.session.commit()
    return profile

@app.route('/api/ssh/analyze-all-today', methods=['POST'])
@login_required
def analyze_all_today():
    """Analyse globale : scanne tous les serveurs enregistrés pour une date donnée."""
    from models import SavedServer
    from datetime import datetime
    
    data = request.get_json(silent=True) or {}
    target_date = data.get('target_date') # Format "YYYY-MM-DD"
    
    servers = SavedServer.query.filter_by(user_id=current_user.id).all()
    
    if not servers:
        return jsonify({"success": False, "message": "Aucun serveur enregistré trouvé."}), 404
        
    results = []
    f = _get_fernet()
    success_count = 0
    
    # Préparation des patterns de date
    dt = datetime.fromisoformat(target_date) if target_date else datetime.now()
    months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec']
    m_abbr = months[dt.month-1]
    day_str = f"{dt.day:2d}"
    date_syslog = f"{m_abbr} {day_str}"
    date_iso = dt.strftime("%Y-%m-%d")
    date_slash = dt.strftime("%d/%m/%Y")
    date_slash_short = dt.strftime("%d/%b/%Y")
    
    regex = "|".join([f"^{date_syslog}", date_iso, date_slash, date_slash_short])
    date_label = dt.strftime("%d %B %Y")
    
    for s in servers:
        ssh = None
        try:
            username = f.decrypt(s.encrypted_username.encode()).decode()
            password = f.decrypt(s.encrypted_password.encode()).decode()
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(s.ip, username=username, password=password, timeout=10)
            
            # Commande optimisée
            cmd = f"grep -aE '{regex}' {s.log_path} | tail -n 200"
            
            _, stdout, _ = ssh.exec_command(cmd)
            log_content = stdout.read().decode('utf-8', errors='replace')
            
            if log_content.strip():
                from src.parser import parse_log_file
                temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"global_{s.id}.log")
                with open(temp_path, "w", encoding="utf-8") as tmp:
                    tmp.write(log_content)
                
                parsed_results = parse_log_file(temp_path)
                os.remove(temp_path)
                
                stats = {
                    "errors": len(parsed_results.get('ERROR', [])),
                    "warnings": len(parsed_results.get('WARNING', [])),
                    "info": len(parsed_results.get('INFO', [])),
                    "total": sum(len(v) for v in parsed_results.values())
                }
                
                save_analysis_for_current_user(
                    source_type="ssh_global",
                    source_path=s.log_path,
                    server_ip=s.ip,
                    stats=stats,
                    segments=parsed_results,
                    meta={"mode": "global_scan", "date": date_label},
                    log_content=log_content
                )
                success_count += 1
                results.append({"ip": s.ip, "status": "success"})
            else:
                results.append({"ip": s.ip, "status": "no_logs"})
                
        except Exception as e:
            results.append({"ip": s.ip, "status": "error", "message": str(e)})
        finally:
            if ssh: ssh.close()
            
    return jsonify({
        "success": True,
        "message": f"{success_count} serveurs analysés pour le {date_label}.",
        "date_analyzed": date_label,
        "results": results
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        ensure_default_admin()
    app.run(debug=True, port=5000)