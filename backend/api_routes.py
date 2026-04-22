from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required, current_user, login_user, logout_user
from datetime import datetime, timezone, timedelta
import os
import requests
import paramiko
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
from functools import wraps
from utils_security import encrypt_data, decrypt_data

from models import db, Analysis, User
from utils import (
    generate_security_summary,
    generate_pdf_report_bytes
)

api = Blueprint('api', __name__, url_prefix='/api')


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # Extraction du token depuis l'en-tête Authorization
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'status': 'error', 'message': 'Token manquant'}), 401
        
        try:
            # Utilisation de la SECRET_KEY de l'application et du sel fixe
            s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
            # Le sel doit être identique à celui utilisé lors du dumps()
            user_id = s.loads(token, salt='auth-token', max_age=86400) # Valide 24h
            
            user = db.session.get(User, user_id)
            if not user:
                return jsonify({'status': 'error', 'message': 'Utilisateur introuvable'}), 401
            
            # Injection de l'utilisateur dans l'objet request
            request.current_user = user
        except Exception as e:
            # Erreur explicite pour le frontend
            return jsonify({'status': 'error', 'message': 'Token invalide ou expiré'}), 401
        
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(*args, **kwargs):
        if request.current_user.role != "Admin":
            return jsonify({'status': 'error', 'message': 'Accès réservé aux administrateurs'}), 403
        return f(*args, **kwargs)
    return decorated


def _compute_severity_counts(analysis: Analysis | None) -> dict:
    if not analysis:
        return {"high": 0, "medium": 0, "low": 0}
    meta = analysis.meta or {}
    if isinstance(meta.get("severity_counts"), dict):
        counts = meta["severity_counts"]
        return {
            "high": int(counts.get("high", counts.get("Critique", 0))),
            "medium": int(counts.get("medium", counts.get("Moyen", 0))),
            "low": int(counts.get("low", counts.get("Faible", 0)))
        }
    stats = analysis.stats or {}
    return {
        "high": int(stats.get("errors", 0)),
        "medium": int(stats.get("warnings", 0)),
        "low": int(stats.get("info", 0))
    }

@api.route('/notifications', methods=['GET'])
@token_required
def get_notifications():
    user = request.current_user
    notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).limit(50).all()
    
    return jsonify({
        "status": "success",
        "notifications": [
            {
                "id": n.id,
                "title": n.title,
                "message": n.message,
                "type": n.type,
                "is_read": n.is_read,
                "created_at": n.created_at.isoformat(),
                "link": n.link
            }
            for n in notifications
        ]
    })

@api.route('/notifications/<int:notif_id>/read', methods=['POST'])
@token_required
def mark_notification_read(notif_id):
    user = request.current_user
    notification = Notification.query.filter_by(id=notif_id, user_id=user.id).first()
    
    if not notification:
        return jsonify({"status": "error", "message": "Notification introuvable"}), 404
        
    notification.is_read = True
    db.session.commit()
    return jsonify({"status": "success"})

@api.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data.get('username')).first()
    if user and user.check_password(data.get('password')):
        # login_user(user) # Flask-Login n'est plus nécessaire avec les tokens
        s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        token = s.dumps(user.id, salt='auth-token')
        return jsonify({
            "status": "success", 
            "message": "Connexion réussie",
            "token": token,
            "username": user.username,
            "role": user.role,
            "firstName": user.first_name,
            "lastName": user.last_name
        })
    return jsonify({"status": "error", "message": "Identifiants invalides"}), 401

@api.route('/logout', methods=['POST'])
@token_required
def logout():
    # logout_user() # Flask-Login n'est plus nécessaire
    return jsonify({"status": "success", "message": "Déconnexion réussie"})

@api.route('/analyses', methods=['GET'])
@token_required
def get_analyses():
    user = request.current_user
    period = request.args.get('period', '7d')
    now = datetime.now(timezone.utc)
    until = now

    if period == '24h':
        since = now - timedelta(hours=24)
    elif period == '7d':
        since = now - timedelta(days=7)
    elif period == '30d':
        since = now - timedelta(days=30)
    else:
        since = now - timedelta(days=7)

    analyses = Analysis.query.filter(
        Analysis.user_id == user.id,
        Analysis.created_at >= since,
        Analysis.created_at <= until
    ).order_by(Analysis.created_at.desc()).limit(100).all()

    return jsonify({
        "status": "success",
        "count": len(analyses),
        "analyses": [
            {
                "id": a.id,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "source_type": a.source_type,
                "source_path": a.source_path,
                "file_path": a.file_path,
                "server_ip": a.server_ip,
                "stats": a.stats,
                "ai_score": a.ai_score,
                "ai_status": a.ai_status,
                "ai_menaces": a.ai_menaces
            }
            for a in analyses
        ]
    })

@api.route('/analyses/<int:analysis_id>', methods=['GET'])
@token_required
def get_analysis(analysis_id):
    user = request.current_user
    a = Analysis.query.filter_by(id=analysis_id, user_id=user.id).first()
    if not a:
        return jsonify({"status": "error", "message": "Analyse introuvable"}), 404

    return jsonify({
        "status": "success",
        "analysis": {
            "id": a.id,
            "created_at": a.created_at.isoformat() if a.created_at else None,
            "source_type": a.source_type,
            "source_path": a.source_path,
            "file_path": a.file_path,
            "server_ip": a.server_ip,
            "stats": a.stats,
            "segments": a.segments,
            "meta": a.meta,
            "ai_score": a.ai_score,
            "ai_status": a.ai_status,
            "ai_menaces": a.ai_menaces
        }
    })

@api.route('/analyses/<int:analysis_id>/pdf', methods=['GET'])
@token_required
def get_analysis_pdf(analysis_id):
    user = request.current_user
    a = Analysis.query.filter_by(id=analysis_id, user_id=user.id).first()
    if not a:
        return jsonify({"status": "error", "message": "Analyse introuvable"}), 404
    
    from flask import make_response
    pdf_bytes = generate_pdf_report_bytes(a)
    if not pdf_bytes:
        return jsonify({"status": "error", "message": "Erreur lors de la génération du PDF"}), 500
        
    response = make_response(pdf_bytes)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=Rapport_Audit_{analysis_id}.pdf'
    return response

@api.route('/analyses/<int:analysis_id>', methods=['DELETE'])
@token_required
def delete_analysis(analysis_id):
    user = request.current_user
    a = Analysis.query.filter_by(id=analysis_id, user_id=user.id).first()
    if not a:
        return jsonify({"status": "error", "message": "Analyse introuvable"}), 404
    
    db.session.delete(a)
    db.session.commit()
    return jsonify({"status": "success", "message": "Analyse supprimée"})

@api.route('/stats', methods=['GET'])
@token_required
def get_stats():
    user = request.current_user
    period = request.args.get('period', '7d')
    now = datetime.now(timezone.utc)
    until = now

    if period == '24h':
        since = now - timedelta(hours=24)
        group_fmt = '%H:00'
        step = timedelta(hours=2)
    elif period == '7d':
        since = now - timedelta(days=7)
        group_fmt = '%d %b'
        step = timedelta(days=1)
    elif period == '30d':
        since = now - timedelta(days=30)
        group_fmt = '%d %b'
        step = timedelta(days=1)
    else:
        since = now - timedelta(days=7)
        group_fmt = '%d %b'
        step = timedelta(days=1)

    analyses = Analysis.query.filter(
        Analysis.user_id == user.id,
        Analysis.created_at >= since,
        Analysis.created_at <= until
    ).all()

    buckets = {}
    cursor = since
    while cursor <= until:
        label = cursor.strftime(group_fmt)
        buckets[label] = {"Critique": 0, "Avertissement": 0, "Info": 0, "total_logs": 0, "total_errors": 0, "total_warnings": 0}
        cursor += step

    for a in analyses:
        label = a.created_at.strftime(group_fmt)
        if label not in buckets:
            buckets[label] = {"Critique": 0, "Avertissement": 0, "Info": 0, "total_logs": 0, "total_errors": 0, "total_warnings": 0}

        status = str(a.ai_status or "").lower()
        if 'critique' in status or 'danger' in status:
            buckets[label]['Critique'] += 1
        elif 'attention' in status or 'warning' in status:
            buckets[label]['Avertissement'] += 1
        else:
            buckets[label]['Info'] += 1

        astats = a.stats or {}
        buckets[label]['total_logs'] += int(astats.get('total', 0))
        buckets[label]['total_errors'] += int(astats.get('errors', 0))
        buckets[label]['total_warnings'] += int(astats.get('warnings', 0))

    sorted_labels = sorted(buckets.keys())
    total_audits = Analysis.query.filter_by(user_id=user.id).count()
    active_servers = db.session.query(Analysis.server_ip).filter(
        Analysis.user_id == user.id,
        Analysis.server_ip != None
    ).distinct().count()

    seven_days_ago = now - timedelta(days=7)
    recent = Analysis.query.filter(
        Analysis.user_id == user.id,
        Analysis.created_at >= seven_days_ago
    ).all()

    critical_threats = sum((a.ai_menaces if a.ai_menaces is not None else int(a.stats.get('errors', 0))) for a in recent)
    scores = [(a.ai_score if a.ai_score is not None else 70) for a in recent]
    system_health = round(sum(scores) / len(scores)) if scores else 100

    last_analysis = Analysis.query.filter_by(
        user_id=user.id
    ).order_by(Analysis.created_at.desc()).first()

    analysis_data = None
    if last_analysis:
        severity_counts = _compute_severity_counts(last_analysis)
        meta = dict(last_analysis.meta or {})
        meta["severity_counts"] = severity_counts
        analysis_data = {
            "id": last_analysis.id,
            "meta": meta,
            "stats": last_analysis.stats,
            "ai_score": last_analysis.ai_score,
            "ai_status": last_analysis.ai_status,
            "severity_counts": severity_counts
        }

    return jsonify({
        "status": "success",
        "labels": sorted_labels,
        "critique": [buckets[lb]['Critique'] for lb in sorted_labels],
        "avertissement": [buckets[lb]['Avertissement'] for lb in sorted_labels],
        "info": [buckets[lb]['Info'] for lb in sorted_labels],
        "total_logs": sum(buckets[lb]['total_logs'] for lb in sorted_labels),
        "total_errors": sum(buckets[lb]['total_errors'] for lb in sorted_labels),
        "total_warnings": sum(buckets[lb]['total_warnings'] for lb in sorted_labels),
        "summary": {
            "total_audits": total_audits,
            "active_servers": active_servers,
            "critical_threats": critical_threats,
            "system_health": system_health
        },
        "analysis_data": analysis_data,
        "meta": analysis_data["meta"] if analysis_data else {},
        "severity_counts": analysis_data["severity_counts"] if analysis_data else {"high": 0, "medium": 0, "low": 0}
    })

@api.route('/dashboard', methods=['GET'])
@token_required
def get_dashboard():
    user = request.current_user
    now = datetime.now(timezone.utc)
    seven_days_ago = now - timedelta(days=7)

    last_analysis = Analysis.query.filter_by(
        user_id=user.id
    ).order_by(Analysis.created_at.desc()).first()

    recent_analyses = Analysis.query.filter(
        Analysis.user_id == user.id,
        Analysis.created_at >= seven_days_ago
    ).order_by(Analysis.created_at.desc()).limit(5).all()

    total_audits = Analysis.query.filter_by(user_id=user.id).count()
    active_servers = db.session.query(Analysis.server_ip).filter(
        Analysis.user_id == user.id,
        Analysis.server_ip != None
    ).distinct().count()

    critical_threats = sum((a.ai_menaces if a.ai_menaces is not None else 0) for a in recent_analyses)
    scores = [(a.ai_score if a.ai_score is not None else 70) for a in recent_analyses]
    system_health = round(sum(scores) / len(scores)) if scores else 100

    results = None
    if last_analysis:
        severity_counts = _compute_severity_counts(last_analysis)
        meta = dict(last_analysis.meta or {})
        meta["severity_counts"] = severity_counts
        results = {
            "analysis_id": last_analysis.id,
            "created_at": last_analysis.created_at.isoformat() if last_analysis.created_at else None,
            "server_ip": last_analysis.server_ip,
            "ai_score": last_analysis.ai_score,
            "ai_status": last_analysis.ai_status,
            "ai_menaces": last_analysis.ai_menaces,
            "meta": meta,
            "stats": last_analysis.stats,
            "severity_counts": severity_counts
        }

    return jsonify({
        "status": "success",
        "analysis_data": results,
        "meta": results["meta"] if results else {},
        "severity_counts": results["severity_counts"] if results else {"high": 0, "medium": 0, "low": 0},
        "summary": {
            "total_audits": total_audits,
            "active_servers": active_servers,
            "critical_threats": critical_threats,
            "system_health": system_health
        },
        "recent_activities": [
            {
                "id": a.id,
                "created_at": a.created_at.isoformat() if a.created_at else None,
                "server_ip": a.server_ip,
                "ai_status": a.ai_status,
                "ai_score": a.ai_score
            }
            for a in recent_analyses
        ]
    })

@api.route('/ssh/analyze', methods=['POST'])
@token_required
def ssh_analyze():
    user = request.current_user
    data = request.get_json()
    host = data.get('host')
    ssh_user = data.get('user')
    pwd = data.get('pass')
    num_lines = data.get('numLines', 100)
    cmd = f"tail -n {num_lines} /var/log/syslog"

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(host, username=ssh_user, password=pwd, timeout=10)
        except paramiko.AuthenticationException:
            return jsonify({"status": "error", "message": "Authentification SSH échouée"}), 401
        except paramiko.SSHException as se:
            return jsonify({"status": "error", "message": f"Erreur SSH: {str(se)}"}), 500
        except Exception as e:
            return jsonify({"status": "error", "message": f"Connexion impossible: {str(e)}"}), 500
        
        stdin, stdout, stderr = ssh.exec_command(cmd)
        log_content = stdout.read().decode('utf-8', errors='replace')
        ssh_err = stderr.read().decode('utf-8', errors='replace')
        ssh.close()

        if ssh_err and not log_content:
            return jsonify({"status": "error", "message": f"Erreur lors de l'exécution: {ssh_err}"}), 500

        if not log_content:
            return jsonify({"status": "error", "message": "Aucun log récupéré"}), 400

        from src.parser import parse_log_file
        temp_path = f"temp_ssh_{user.id}.log"
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(log_content)
        
        results = parse_log_file(temp_path)
        if os.path.exists(temp_path):
            os.remove(temp_path)

        stats = {
            "errors": len(results.get('ERROR', [])),
            "warnings": len(results.get('WARNING', [])),
            "info": len(results.get('INFO', [])),
            "total": sum(len(v) for v in results.values())
        }

        ai_metrics = generate_security_summary(model=None, log_text=log_content)
        
        analysis = Analysis(
            user_id=user.id,
            source_type="ssh",
            source_path=host, # Correction: host au lieu de cmd pour plus de clarté
            file_path=cmd.split()[-1], # On extrait le chemin du log (/var/log/syslog)
            server_ip=host,
            stats=stats,
            segments=results,
            meta=ai_metrics,
            ai_score=ai_metrics.get("score", 70),
            ai_status=ai_metrics.get("status", "Normal"),
            ai_menaces=ai_metrics.get("menaces", 0)
        )
        db.session.add(analysis)
        db.session.commit()

        return jsonify({"status": "success", "analysis_id": analysis.id})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@api.route('/settings', methods=['GET', 'POST'])
@token_required
def settings():
    user = request.current_user
    if request.method == 'GET':
        return jsonify({
            "status": "success",
            "settings": {
                "emailNotifications": bool(user.email_notifications_enabled),
                "notificationEmail": user.notification_email or user.email or "",
                "smtpServer": user.smtp_server or os.getenv("MAIL_SERVER", "smtp.gmail.com"),
                "smtpPort": user.smtp_port or int(os.getenv("MAIL_PORT", 587)),
                "smtpUser": user.email_sender or os.getenv("MAIL_USERNAME", ""),
                "smtpPassword": ""
            }
        })

    data = request.get_json() or {}
    user.email_notifications_enabled = bool(data.get("emailNotifications", False))
    user.notification_email = (data.get("notificationEmail") or "").strip() or None
    user.smtp_server = (data.get("smtpServer") or "").strip() or None
    user.smtp_port = int(data.get("smtpPort", 587)) if data.get("smtpPort") is not None else None
    user.email_sender = (data.get("smtpUser") or "").strip() or None

    # Keep current behavior simple: only update password if explicitly provided.
    smtp_password = (data.get("smtpPassword") or "").strip()
    if smtp_password:
        user.email_password_enc = encrypt_data(smtp_password)

    db.session.commit()
    return jsonify({"status": "success", "message": "Paramètres enregistrés avec succès"})

@api.route('/analyze-local', methods=['POST'])
@token_required
def analyze_local():
    """
    Route pour l'analyse de fichiers logs locaux (Upload).
    Accessible à tous les rôles authentifiés.
    """
    user = request.current_user
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "Aucun fichier fourni"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "Nom de fichier vide"}), 400

    filename = secure_filename(file.filename)
    upload_dir = "uploads"
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
    
    # Préfixer le nom du fichier avec l'ID utilisateur pour éviter les conflits
    file_path = os.path.join(upload_dir, f"{user.id}_{filename}")
    file.save(file_path)

    try:
        from src.parser import parse_log_file
        # Appel du parser existant
        results = parse_log_file(file_path)
        
        # Lecture du contenu pour l'analyse IA
        with open(file_path, "r", encoding="utf-8", errors='replace') as f:
            log_content = f.read()

        # Calcul des statistiques
        stats = {
            "errors": len(results.get('ERROR', [])),
            "warnings": len(results.get('WARNING', [])),
            "info": len(results.get('INFO', [])),
            "total": sum(len(v) for v in results.values())
        }

        # Analyse IA avec Gemini
        ai_metrics = generate_security_summary(model=None, log_text=log_content)
        
        # Sauvegarde dans le modèle Analysis
        analysis = Analysis(
            user_id=user.id,
            source_type="upload",
            source_path=filename,
            file_path=file_path,
            stats=stats,
            segments=results,
            meta=ai_metrics,
            ai_score=ai_metrics.get("score", 70),
            ai_status=ai_metrics.get("status", "Normal"),
            ai_menaces=ai_metrics.get("menaces", 0)
        )
        db.session.add(analysis)
        db.session.commit()

        return jsonify({
            "status": "success", 
            "message": "Analyse terminée avec succès",
            "analysis_id": analysis.id
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Erreur lors de l'analyse : {str(e)}"}), 500
    finally:
        # Nettoyage du fichier temporaire
        if os.path.exists(file_path):
            os.remove(file_path)

@api.route('/upload', methods=['POST'])
@token_required
def upload_file():
    user = request.current_user
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "Aucun fichier fourni"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "Nom de fichier vide"}), 400

    filename = secure_filename(file.filename)
    upload_dir = "uploads"
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir)
    
    file_path = os.path.join(upload_dir, f"{user.id}_{filename}")
    file.save(file_path)

    try:
        from src.parser import parse_log_file
        results = parse_log_file(file_path)
        
        with open(file_path, "r", encoding="utf-8", errors='replace') as f:
            log_content = f.read()

        stats = {
            "errors": len(results.get('ERROR', [])),
            "warnings": len(results.get('WARNING', [])),
            "info": len(results.get('INFO', [])),
            "total": sum(len(v) for v in results.values())
        }

        ai_metrics = generate_security_summary(model=None, log_text=log_content)
        
        analysis = Analysis(
            user_id=user.id,
            source_type="upload",
            source_path=filename,
            stats=stats,
            segments=results,
            meta=ai_metrics,
            ai_score=ai_metrics.get("score", 70),
            ai_status=ai_metrics.get("status", "Normal"),
            ai_menaces=ai_metrics.get("menaces", 0)
        )
        db.session.add(analysis)
        db.session.commit()

        return jsonify({"status": "success", "analysis_id": analysis.id})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)

# --- User: Jobs Management ---

@api.route('/jobs', methods=['GET'])
@token_required
def get_user_jobs():
    from models import AnalysisJob
    user = request.current_user
    jobs = AnalysisJob.query.filter_by(user_id=user.id).all()
    return jsonify({
        "status": "success",
        "jobs": [
            {
                "id": j.id,
                "target_ip": j.target_ip,
                "log_path": j.log_path,
                "frequency": j.frequency,
                "status": j.status,
                "created_at": j.created_at.isoformat() if j.created_at else None
            }
            for j in jobs
        ]
    })

@api.route('/jobs', methods=['POST'])
@token_required
def create_user_job():
    from models import AnalysisJob, Notification
    user = request.current_user
    data = request.get_json()
    
    new_job = AnalysisJob(
        user_id=user.id,
        target_ip=data.get('target_ip'),
        log_path=data.get('log_path', '/var/log/syslog'),
        frequency=data.get('frequency', 'daily'),
        ssh_username=data.get('ssh_user'),
        ssh_password_enc=encrypt_data(data.get('ssh_pass')),
        status='pending'
    )
    db.session.add(new_job)
    db.session.flush() # Pour avoir l'ID du job

    # Alerter les admins
    admins = User.query.filter_by(role='Admin').all()
    for admin in admins:
        notif = Notification(
            user_id=admin.id,
            title="Nouvelle demande de Job",
            message=f"L'analyste {user.username} a créé une demande pour {new_job.target_ip}.",
            type="info",
            link=f"/admin/jobs"
        )
        db.session.add(notif)

    db.session.commit()
    return jsonify({"status": "success", "message": "Demande de job créée et en attente de validation Admin"})

@api.route('/jobs/<int:job_id>', methods=['DELETE'])
@token_required
def delete_user_job(job_id):
    from models import AnalysisJob
    user = request.current_user
    job = AnalysisJob.query.filter_by(id=job_id, user_id=user.id).first()
    if not job:
        return jsonify({"status": "error", "message": "Job introuvable"}), 404
    
    db.session.delete(job)
    db.session.commit()
    return jsonify({"status": "success", "message": "Job supprimé"})


@api.route('/email/send-report', methods=['POST'])
@token_required
def send_report():
    user = request.current_user
    import smtplib
    import ssl
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from email.mime.application import MIMEApplication

    data = request.get_json() or {}
    analysis_id = data.get('analysis_id')
    recipient = data.get('recipient') or data.get('email') or user.notification_email or user.email
    
    if not analysis_id or not recipient:
        return jsonify({"status": "error", "message": "ID d'analyse ou destinataire manquant"}), 400
        
    analysis = db.session.get(Analysis, analysis_id)
    if not analysis or analysis.user_id != user.id:
        return jsonify({"status": "error", "message": "Analyse introuvable"}), 404
        
    # Configuration SMTP avec flexibilité (Priorité aux paramètres de l'utilisateur)
    smtp_server = user.smtp_server or os.getenv("MAIL_SERVER", "smtp.gmail.com")
    smtp_port = user.smtp_port or int(os.getenv("MAIL_PORT", 587))
    smtp_user = user.email_sender or os.getenv("MAIL_USERNAME") or os.getenv("SMTP_USER")
    smtp_pass = decrypt_data(user.email_password_enc) if user.email_password_enc else (os.getenv("MAIL_PASSWORD") or os.getenv("SMTP_PASS"))
    use_tls = os.getenv("MAIL_USE_TLS", "True").lower() == "true"

    if not smtp_user:
        return jsonify({"status": "error", "message": "Configuration SMTP incomplète (expéditeur manquant)."}), 400

    # 1. Génération du PDF
    pdf_bytes = generate_pdf_report_bytes(analysis)
    if not pdf_bytes:
        return jsonify({"status": "error", "message": "Erreur lors de la génération du PDF"}), 500
        
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
        </ul>
        {f'<p><strong>Note :</strong> {message_notes}</p>' if message_notes else ''}
        <p>Le rapport PDF est joint à cet email.</p>
    </body>
    </html>
    """
    
    msg = MIMEMultipart("mixed")
    msg['Subject'] = subject
    msg['To'] = recipient
    msg['From'] = smtp_user
    msg.attach(MIMEText(html_body, 'html'))
    
    attachment = MIMEApplication(pdf_bytes)
    attachment.add_header('Content-Disposition', 'attachment', filename=f"Rapport_Audit_{analysis_id}.pdf")
    msg.attach(attachment)

    # 3. Envoi SMTP
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, smtp_port, timeout=20) as server:
            if use_tls:
                server.starttls(context=context)
            
            if smtp_pass:
                try:
                    server.login(smtp_user, smtp_pass)
                except smtplib.SMTPAuthenticationError:
                    return jsonify({"status": "error", "message": "Authentification SMTP échouée. Vérifiez vos identifiants."}), 401
            
            server.send_message(msg)
        
        return jsonify({"status": "success", "message": f"Email envoyé avec succès à {recipient}"})
        
    except Exception as e:
        return jsonify({"status": "error", "message": f"Erreur de connexion SMTP : {str(e)}"}), 500


# --- Admin: User Management ---

@api.route('/admin/users', methods=['GET'])
@admin_required
def admin_get_users():
    users = User.query.all()
    return jsonify({
        "status": "success",
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "firstName": u.first_name,
                "lastName": u.last_name,
                "role": u.role,
                "created_at": u.created_at.isoformat() if u.created_at else None
            }
            for u in users
        ]
    })

@api.route('/admin/users', methods=['POST'])
@admin_required
def admin_create_user():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'Analyseur')
    first_name = data.get('firstName')
    last_name = data.get('lastName')

    if not username or not email or not password:
        return jsonify({"status": "error", "message": "Données manquantes"}), 400

    if User.query.filter((User.username == username) | (User.email == email)).first():
        return jsonify({"status": "error", "message": "Nom d'utilisateur ou email déjà utilisé"}), 400

    user = User(
        username=username,
        email=email,
        role=role,
        first_name=first_name,
        last_name=last_name
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"status": "success", "message": "Utilisateur créé avec succès"})

@api.route('/admin/users/<int:user_id>', methods=['PUT', 'DELETE'])
@admin_required
def admin_update_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"status": "error", "message": "Utilisateur introuvable"}), 404

    if request.method == 'DELETE':
        if user.id == request.current_user.id:
            return jsonify({"status": "error", "message": "Vous ne pouvez pas supprimer votre propre compte"}), 400
        db.session.delete(user)
        db.session.commit()
        return jsonify({"status": "success", "message": "Utilisateur supprimé"})

    data = request.get_json()
    user.username = data.get('username', user.username)
    user.email = data.get('email', user.email)
    user.role = data.get('role', user.role)
    user.first_name = data.get('firstName', user.first_name)
    user.last_name = data.get('lastName', user.last_name)

    new_password = data.get('password')
    if new_password:
        user.set_password(new_password)

    db.session.commit()
    return jsonify({"status": "success", "message": "Utilisateur mis à jour"})


# --- Admin: Job Management ---

@api.route('/admin/jobs', methods=['GET'])
@admin_required
def admin_get_jobs():
    from models import AnalysisJob
    jobs = AnalysisJob.query.all()
    return jsonify({
        "status": "success",
        "jobs": [
            {
                "id": j.id,
                "user_id": j.user_id,
                "username": j.user.username,
                "target_ip": j.target_ip,
                "log_path": j.log_path,
                "frequency": j.frequency,
                "status": j.status,
                "created_at": j.created_at.isoformat() if j.created_at else None
            }
            for j in jobs
        ]
    })

@api.route('/admin/jobs/<int:job_id>/approve', methods=['POST'])
@admin_required
def admin_approve_job(job_id):
    from models import AnalysisJob, Notification
    job = db.session.get(AnalysisJob, job_id)
    if not job:
        return jsonify({"status": "error", "message": "Job introuvable"}), 404

    data = request.get_json()
    action = data.get('action') # approve | refuse
    reason = data.get('reason', '')

    if action == 'approve':
        job.status = 'active'
        job.approved_at = datetime.now(timezone.utc)
        
        # Notification à l'utilisateur
        notif = Notification(
            user_id=job.user_id,
            title="Job Approuvé",
            message=f"Votre demande d'analyse pour {job.target_ip} a été approuvée.",
            type="success",
            link="/jobs"
        )
        db.session.add(notif)
        
    elif action == 'refuse':
        job.status = 'refused'
        job.refusal_reason = reason or 'Refusé par l\'administrateur'
        
        # Notification à l'utilisateur avec motif
        notif = Notification(
            user_id=job.user_id,
            title="Job Refusé",
            message=f"Votre demande pour {job.target_ip} a été refusée. Motif : {job.refusal_reason}",
            type="error",
            link="/jobs"
        )
        db.session.add(notif)
    else:
        return jsonify({"status": "error", "message": "Action invalide"}), 400

    db.session.commit()
    return jsonify({"status": "success", "message": f"Job {action}d avec succès"})


# --- Admin: Remote Console (SSH Terminal) ---

@api.route('/admin/console', methods=['POST'])
@admin_required
def admin_remote_console():
    data = request.get_json()
    host = data.get('host')
    user = data.get('user')
    pwd = data.get('pass')
    cmd = data.get('command')

    if not all([host, user, pwd, cmd]):
        return jsonify({"status": "error", "message": "Données SSH manquantes"}), 400

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=user, password=pwd, timeout=10)
        
        stdin, stdout, stderr = ssh.exec_command(cmd)
        output = stdout.read().decode('utf-8', errors='replace')
        error = stderr.read().decode('utf-8', errors='replace')
        ssh.close()

        return jsonify({
            "status": "success",
            "output": output,
            "error": error
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Erreur Console: {str(e)}"}), 500


# --- User: Profile & Signature ---

@api.route('/profile', methods=['GET'])
@token_required
def get_profile():
    user = request.current_user
    return jsonify({
        "status": "success",
        "username": user.username,
        "email": user.email,
        "firstName": user.first_name,
        "lastName": user.last_name,
        "role": user.role,
        "signature_path": user.signature_path
    })

@api.route('/profile/change-password', methods=['POST'])
@token_required
def change_password():
    user = request.current_user
    data = request.get_json()
    old_pass = data.get('old')
    new_pass = data.get('new')

    if not user.check_password(old_pass):
        return jsonify({"status": "error", "message": "Ancien mot de passe incorrect"}), 400

    user.set_password(new_pass)
    db.session.commit()
    return jsonify({"status": "success", "message": "Mot de passe mis à jour"})

@api.route('/profile/upload-signature', methods=['POST'])
@token_required
def upload_signature():
    user = request.current_user
    if 'signature' not in request.files:
        return jsonify({"status": "error", "message": "Aucun fichier fourni"}), 400
    
    file = request.files['signature']
    if file.filename == '':
        return jsonify({"status": "error", "message": "Nom de fichier vide"}), 400

    # Process with Remove.bg
    # Traitement avec Remove.bg
    api_key = os.getenv("REMOVE_BG_API_KEY")
    if not api_key:
        return jsonify({"status": "error", "message": "Clé API Remove.bg manquante"}), 500

    try:
        response = requests.post(
            'https://api.remove.bg/v1.0/removebg',
            files={'image_file': file},
            data={'size': 'auto'},
            headers={'X-Api-Key': api_key},
        )
        if response.status_code == requests.codes.ok:
            # Save processed image
            # Sauvegarder l'image traitée
            filename = f"sig_{user.id}.png"
            static_dir = os.path.join(current_app.root_path, 'static', 'signatures')
            if not os.path.exists(static_dir):
                os.makedirs(static_dir)
            
            file_path = os.path.join(static_dir, filename)
            with open(file_path, 'wb') as out:
                out.write(response.content)
            
            user.signature_path = f"signatures/{filename}"
            db.session.commit()
            
            return jsonify({
                "status": "success", 
                "message": "Signature mise à jour",
                "signature_path": user.signature_path
            })
        else:
            return jsonify({"status": "error", "message": f"Erreur Remove.bg: {response.text}"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500




