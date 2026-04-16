import os
os.environ['NO_PROXY'] = 'generativelanguage.googleapis.com,smtp.gmail.com'

from fpdf import FPDF
from fpdf.enums import XPos, YPos
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, send_file
import io
from flask_cors import CORS
from datetime import datetime, timezone, timedelta
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
import dns.resolver # Pour la détection MX
from openai import OpenAI
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import time

from src.parser import parse_log_file
from config import Config
from models import db, User, Analysis, AnalysisJob

load_dotenv()

app = Flask(__name__)
CORS(app)
app.config.from_object(Config)
app.config['REMOVE_BG_API_KEY'] = os.getenv('REMOVE_BG_API_KEY') or get_decrypted_removebg_key()

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
        "Rules:\n"
        "- If 'Failed password' is found, reduce score by 20 points per attempt.\n"
        "- Score: 0-100 (100 is perfectly safe).\n"
        "- Status: 'Sain' (score > 80), 'Attention' (score 50-80), 'Critique' (score < 50).\n"
        "- Menaces: total number of distinct security threats, alerts or critical errors found.\n"
        "Required JSON keys:\n"
        "  \"ai_insights\": \"Bullet points summarizing findings\",\n"
        "  \"security_level\": \"LOW|MEDIUM|HIGH|CRITICAL\",\n"
        "  \"score\": <int>,\n"
        "  \"status\": \"Sain|Attention|Critique\",\n"
        "  \"menaces\": <int>,\n"
        "  \"corrective_actions\": [\"Action 1\", \"Action 2\"],\n"
        "  \"prevention_steps\": [\"Prevention 1\", \"Prevention 2\"]\n"
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
        "menaces": error_hits + failed_pass_hits
    }


def generate_security_summary(*, model, log_text: str, top_patterns: list = None):
    """
    Produit un résumé concis orienté sécurité pour tout type de log.
    Retourne un dict : {ai_insights, security_level, score, status, menaces, corrective_actions, prevention_steps}
    """
    import json as _json

    # 'model' est conservé pour la rétrocompatibilité avec les appels existants.
    try:
        text = generate_security_summary_text(log_text, top_patterns)
    except Exception as e:
        print(str(e))
        # Ne jamais laisser une erreur IA bloquer le flux métier (email/rapport).
        res = _heuristic_security_summary(log_text)
        res.update({"corrective_actions": [], "prevention_steps": []})
        return res
    try:
        parsed = _json.loads(text)
        ai_insights = str(parsed.get("ai_insights", "")).strip() or text[:600]
        security_level = str(parsed.get("security_level", "")).strip().upper()
        if security_level not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            security_level = "MEDIUM"
        
        return {
            "ai_insights": ai_insights, 
            "security_level": security_level,
            "score": int(parsed.get("score", 70)),
            "status": str(parsed.get("status", "Attention")),
            "menaces": int(parsed.get("menaces", 0)),
            "corrective_actions": parsed.get("corrective_actions", []),
            "prevention_steps": parsed.get("prevention_steps", [])
        }
    except Exception:
        if text:
            return {
                "ai_insights": text[:600], 
                "security_level": "MEDIUM",
                "score": 70,
                "status": "Attention",
                "menaces": 0,
                "corrective_actions": [],
                "prevention_steps": []
            }
        res = _heuristic_security_summary(log_text)
        res.update({"corrective_actions": [], "prevention_steps": []})
        return res

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
    
    # Intégration des insights IA dans les meta pour le dashboard et rapport
    if ai_metrics:
        a.meta = {
            **(a.meta or {}), 
            "ai_insights": ai_metrics.get("ai_insights"),
            "corrective_actions": ai_metrics.get("corrective_actions", []),
            "prevention_steps": ai_metrics.get("prevention_steps", [])
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

    # Statistiques globales pour le dashboard basées sur les métriques IA
    total_audits = Analysis.query.filter_by(user_id=current_user.id).count()
    active_servers = db.session.query(Analysis.server_ip).filter(Analysis.user_id == current_user.id, Analysis.server_ip != None).distinct().count()
    
    # Récupération des 5 dernières analyses pour calculer les moyennes et totaux
    recent_analyses = Analysis.query.filter_by(user_id=current_user.id).order_by(Analysis.created_at.desc()).limit(5).all()
    
    # Menaces critiques (Basé sur ai_menaces si disponible, sinon sur stats.errors)
    critical_threats = sum((a.ai_menaces if a.ai_menaces is not None else int(a.stats.get('errors', 0))) for a in recent_analyses)
    
    # Score de santé système (Basé sur ai_score si disponible, sinon calcul heuristique)
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
    ssh = None
    try:
        data = request.get_json(silent=True) or {}
        ip = (data.get('ip') or "").strip()
        user = (data.get('username') or "").strip()
        pwd = data.get('password') or ""
        path = (data.get('path') or "/var/log/messages").strip()
        today_only = data.get('today_only', False)

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

        # Stockage des identifiants en session pour le terminal (Admins uniquement)
        if getattr(current_user, "is_admin", False):
            session['ssh_host'] = ip
            session['ssh_user'] = user
            session['ssh_pass'] = pwd

        # Construction de la commande SSH selon le mode (Tout ou Aujourd'hui uniquement)
        if today_only:
            # Récupération de la date actuelle aux formats standards
            now = datetime.now()
            # Format Syslog : "Apr 11" (Abbréviation mois en anglais + Jour avec espace)
            # Utilisation de mapping manuel pour garantir le format anglais attendu par syslog
            months_map = {
                1: 'Jan', 2: 'Feb', 3: 'Mar', 4: 'Apr', 5: 'May', 6: 'Jun',
                7: 'Jul', 8: 'Aug', 9: 'Sep', 10: 'Oct', 11: 'Nov', 12: 'Dec'
            }
            month_abbr = months_map[now.month]
            day = str(now.day).rjust(2) # " 1" ou "11"
            date_syslog = month_abbr + " " + day
            
            # Format ISO : "2026-04-11"
            date_iso = now.strftime("%Y-%m-%d")
            
            # Utilisation de grep pour filtrer les lignes commençant par l'un des formats
            # L'option -a (ou --text) force grep à traiter le fichier comme du texte
            command = f"grep -aE '^{date_syslog}|{date_iso}' {path}"
        else:
            command = f"tail -n {limit} {path}"

        stdin, stdout, stderr = ssh.exec_command(command)
        log_content = stdout.read().decode('utf-8', errors='replace')
        error_content = stderr.read().decode('utf-8', errors='replace')

        if error_content:
            return json_error(error_content.strip(), 400, code="SSH_COMMAND_ERROR")

        if today_only and not log_content.strip():
            return json_error("Aucun log trouvé pour aujourd'hui", status_code=200, code="NO_LOGS_TODAY")

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
            log_content=log_content
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
    Envoie le rapport PDF complet avec statistiques et Top 10 patterns.
    """
    # Règle Métier : Vérifier si l'utilisateur a une signature avant d'envoyer
    if not current_user.signature_path:
        return jsonify({"success": False, "message": "Action impossible : Vous devez d'abord ajouter votre signature dans votre profil pour valider les rapports."}), 403

    try:
        data = request.get_json() or {}
        analysis_id = data.get('analysis_id')
        recipient = data.get('recipient')
        
        if not analysis_id:
            return jsonify({"success": False, "message": "ID d'analyse manquant"}), 400
        
        user = db.session.get(User, current_user.id)
        analysis = Analysis.query.filter_by(id=analysis_id, user_id=current_user.id).first()
        
        if not analysis:
            return jsonify({"success": False, "message": "Analyse introuvable"}), 404

        target_email = (recipient or user.email).strip()
        
        # 1. Génération du PDF via le helper unifié
        pdf_content = generate_pdf_report_bytes(analysis)
        
        # 2. Préparation du corps de l'email (HTML pour le tableau)
        stats = analysis.stats or {}
        date_str = analysis.created_at.strftime('%d/%m/%Y')
        total_lines = stats.get('total', 0)
        alerts_count = int(stats.get('errors', 0)) + int(stats.get('warnings', 0))
        source_path = analysis.source_path or "/var/log/syslog"

        msg = MIMEMultipart("alternative")
        msg['From'] = user.email_sender
        msg['To'] = target_email
        msg['Subject'] = f"Rapport d'Audit Logs - {analysis.server_ip or 'Local'}"
        
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; color: #333;">
            <p>Bonjour,</p>
            <p>Voici le résumé de l'analyse effectuée le <strong>{date_str}</strong>.</p>
            
            <table style="border-collapse: collapse; width: 100%; max-width: 500px; margin: 20px 0; border: 1px solid #ddd;">
                <tr style="background-color: #f2f2f2;">
                    <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Champ</th>
                    <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Détails</th>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;">Fichier</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{source_path}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;">Lignes</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{total_lines}</td>
                </tr>
                <tr>
                    <td style="padding: 10px; border: 1px solid #ddd;">Alertes</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">{alerts_count}</td>
                </tr>
            </table>
            
            <p>Veuillez trouver en pièce jointe le rapport PDF complet contenant l'analyse détaillée et le Top 10 des récurrences.</p>
            
            <p>Cordialement,<br><strong>Système LogAnalyzer</strong></p>
        </body>
        </html>
        """
        msg.attach(MIMEText(html_body, 'html'))
        
        # 3. Pièce jointe PDF
        attachment = MIMEApplication(pdf_content)
        attachment.add_header('Content-Disposition', 'attachment', filename=f"Rapport_Audit_{analysis_id}.pdf")
        msg.attach(attachment)

        # 4. Envoi SMTP
        smtp_server = user.smtp_server
        smtp_port = user.smtp_port
        if not smtp_server or not smtp_port:
            smtp_server, smtp_port = get_smtp_config(user.email_sender)

        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, int(smtp_port), timeout=20) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(user.email_sender, user.email_password_enc)
            server.send_message(msg)
                
        return jsonify({"success": True, "message": f"Email envoyé avec succès à {target_email} !"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Erreur : {str(e)}"}), 500
        
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

# --- ROUTES DE PLANIFICATION D'ANALYSES ---

@app.route('/admin/scheduled-jobs', methods=['GET'])
@admin_required
def list_scheduled_jobs():
    """Liste toutes les tâches d'analyse planifiées"""
    jobs = AnalysisJob.query.order_by(AnalysisJob.created_at.desc()).all()
    return render_template('admin_scheduled_jobs.html', jobs=jobs)


@app.route('/admin/job/create', methods=['GET', 'POST'])
@admin_required
def create_scheduled_job():
    """Créer une nouvelle tâche d'analyse planifiée"""
    if request.method == 'POST':
        try:
            target_ip = (request.form.get('target_ip') or "").strip()
            log_path = (request.form.get('log_path') or "/var/log/syslog").strip()
            frequency = (request.form.get('frequency') or "daily").strip()
            ssh_username = (request.form.get('ssh_username') or "").strip()
            ssh_password = request.form.get('ssh_password') or ""
            notification_email = (request.form.get('notification_email') or "").strip()
            user_id = request.form.get('user_id')
            
            if not target_ip or not user_id:
                flash("IP cible et utilisateur sont obligatoires.", "danger")
                return redirect(url_for('create_scheduled_job'))
            
            if frequency not in ('hourly', 'daily', 'weekly', 'monthly'):
                flash("Fréquence invalide.", "danger")
                return redirect(url_for('create_scheduled_job'))
            
            user = User.query.get(int(user_id))
            if not user:
                flash("Utilisateur introuvable.", "danger")
                return redirect(url_for('create_scheduled_job'))
            
            # Créer la tâche
            job = AnalysisJob(
                user_id=user.id,
                target_ip=target_ip,
                log_path=log_path,
                frequency=frequency,
                ssh_username=ssh_username,
                ssh_password_enc=f"encrypted:{ssh_password}",  # À implémenter avec Fernet si nécessaire
                notification_email=notification_email,
                status='pending'  # En attente d'approbation
            )
            
            db.session.add(job)
            db.session.commit()
            
            flash(f"Tâche planifiée créée. En attente d'approbation de l'admin.", "info")
            return redirect(url_for('list_scheduled_jobs'))
            
        except Exception as e:
            flash(f"Erreur : {str(e)}", "danger")
            return redirect(url_for('create_scheduled_job'))
    
    users = User.query.filter_by(role='Analyst').all()
    return render_template('create_scheduled_job.html', users=users)


@app.route('/admin/job/<int:job_id>/approve', methods=['POST'])
@admin_required
def approve_analysis_job(job_id: int):
    """Approuver une tâche d'analyse planifiée et la lancer dans le scheduler"""
    from scheduler import scheduler
    from datetime import datetime, timezone
    
    try:
        job = AnalysisJob.query.get(job_id)
        if not job:
            return jsonify({"success": False, "message": "Tâche introuvable"}), 404
        
        job.status = 'active'
        job.approved_at = datetime.now(timezone.utc)
        job.next_run_at = datetime.now(timezone.utc)
        
        # Ajouter la tâche au scheduler
        frequency_map = {
            'hourly': 'cron',
            'daily': 'cron',
            'weekly': 'cron',
            'monthly': 'cron'
        }
        
        trigger_args = {
            'hourly': {'hour': '*'},
            'daily': {'hour': 2, 'minute': 0},
            'weekly': {'day_of_week': 'mon', 'hour': 2, 'minute': 0},
            'monthly': {'day': 1, 'hour': 2, 'minute': 0}
        }
        
        scheduler.add_job(
            func=run_planned_analysis,
            trigger='cron',
            args=[job_id, app],
            id=f'job_{job_id}',
            name=f'Analysis Job {job_id} - {job.target_ip}',
            replace_existing=True,
            **trigger_args.get(job.frequency, {'hour': '*'})
        )
        
        db.session.commit()
        flash(f"Tâche {job_id} approuvée et activée.", "success")
        return jsonify({"success": True, "message": "Tâche approuvée et lancée"})
        
    except Exception as e:
        flash(f"Erreur : {str(e)}", "danger")
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
    """Récupérer les tâches de l'utilisateur actuel"""
    jobs = AnalysisJob.query.filter_by(user_id=current_user.id).order_by(AnalysisJob.created_at.desc()).all()
    
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
    
    # Récupérer les jobs planifiés de l'utilisateur
    scheduled_jobs = AnalysisJob.query.filter_by(user_id=current_user.id).order_by(
        AnalysisJob.created_at.desc()
    ).all()
    
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)