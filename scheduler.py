from flask_apscheduler import APScheduler
from flask import Flask
import logging
import os
import paramiko
from datetime import datetime, timezone, timedelta
import smtplib
import ssl
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import io

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

scheduler = APScheduler()

def init_scheduler(app: Flask):
    """Initialiser APScheduler avec l'application Flask"""
    app.config['SCHEDULER_API_ENABLED'] = True
    scheduler.init_app(app)
    scheduler.start()
    logger.info("APScheduler initialized successfully")


def run_planned_analysis(job_id: int):
    """
    Reçoit UNIQUEMENT un int sérialisable.
    Reconstruit le contexte Flask en interne.
    """
    # Imports locaux pour éviter tout circular import au démarrage
    from extensions import db
    from models import AnalysisJob, Analysis
    from datetime import datetime, timezone
    import paramiko, os

    # Import de l'app en dernier, après que tout le reste est chargé
    from app import app as flask_app, send_notification

    with flask_app.app_context():
        try:
            job = db.session.get(AnalysisJob, job_id)
            if not job or job.status != 'active':
                print(f"[SCHEDULER] Job {job_id} introuvable ou inactif.")
                return

            print(f"[SCHEDULER] Démarrage analyse #{job_id} → {job.target_ip}")

            # Déchiffrement du mot de passe SSH
            fernet_key = os.getenv("FERNET_KEY")
            from cryptography.fernet import Fernet
            f = Fernet(fernet_key.encode())
            ssh_password = f.decrypt(job.ssh_password_enc.encode()).decode()

            # Connexion SSH et récupération des logs
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                job.target_ip,
                username=job.ssh_username,
                password=ssh_password,
                timeout=15
            )
            _, stdout, _ = ssh.exec_command(f"tail -n 500 {job.log_path}")
            log_content = stdout.read().decode('utf-8', errors='replace')
            ssh.close()

            # Parser les logs (Import local)
            from src.parser import parse_log_file
            # Sauvegarder temporairement
            temp_path = os.path.join(os.getenv('UPLOAD_FOLDER', 'uploads'), f"job_{job.id}_temp.log")
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write(log_content)
            
            results = parse_log_file(temp_path)
            os.remove(temp_path)

            # Calcul des stats
            stats = {
                "errors": len(results.get('ERROR', [])),
                "warnings": len(results.get('WARNING', [])),
                "info": len(results.get('INFO', [])),
                "total": sum(len(v) for v in results.values())
            }

            # Génération métriques IA (Import local)
            from app import generate_security_summary
            ai_metrics = generate_security_summary(model=None, log_text=log_content)

            # Créer l'analyse
            analysis = Analysis(
                user_id=job.user_id,
                job_id=job.id,
                source_type="scheduled_ssh",
                source_path=job.log_path,
                server_ip=job.target_ip,
                stats=stats,
                segments=results,
                meta={
                    "scheduled_job_id": job.id,
                    "ai_insights": ai_metrics.get("ai_insights"),
                    "severity_counts": ai_metrics.get("severity_counts"),
                    "activity_trend": ai_metrics.get("activity_trend"),
                    "audit_points": ai_metrics.get("audit_points"),
                    "corrective_actions": ai_metrics.get("corrective_actions", []),
                    "prevention_steps": ai_metrics.get("prevention_steps", []),
                    "security_level": ai_metrics.get("security_level")
                },
                ai_score=ai_metrics.get("score"),
                ai_status=ai_metrics.get("status"),
                ai_menaces=ai_metrics.get("menaces")
            )
            db.session.add(analysis)

            # Mise à jour du job
            job.last_run_at = datetime.now(timezone.utc)
            
            # Notification par email si activée
            from app import send_user_notification
            if job.user.email_notifications_enabled:
                if ai_metrics.get('status') == 'Critique' or ai_metrics.get('menaces', 0) > 0:
                    subject = f"🚨 ALERTE SÉCURITÉ : {job.target_ip}"
                    content = f"""
                    <h2>Alerte de sécurité LogAnalyzer</h2>
                    <p>Une anomalie a été détectée sur le serveur <strong>{job.target_ip}</strong>.</p>
                    <ul>
                        <li><strong>Statut :</strong> {ai_metrics.get('status')}</li>
                        <li><strong>Score :</strong> {ai_metrics.get('score')}/100</li>
                        <li><strong>Menaces :</strong> {ai_metrics.get('menaces')}</li>
                    </ul>
                    <h3>Insights IA :</h3>
                    <p>{ai_metrics.get('ai_insights')}</p>
                    <p>Consultez votre tableau de bord pour plus de détails.</p>
                    """
                    send_user_notification(job.user, subject, content)

            db.session.commit()
            print(f"[SCHEDULER] Job {job_id} terminé avec succès.")

        except Exception as e:
            db.session.rollback()
            error_msg = str(e)
            print(f"[SCHEDULER] Erreur job {job_id} : {error_msg}")
            
            # Enregistrer l'échec dans l'historique pour visibilité utilisateur
            try:
                failed_analysis = Analysis(
                    user_id=job.user_id,
                    job_id=job.id,
                    source_type="scheduled_ssh",
                    source_path=job.log_path,
                    server_ip=job.target_ip,
                    stats={"total": 0, "errors": 0, "warnings": 0, "info": 0},
                    segments={},
                    meta={"error": error_msg, "status": "failed"},
                    ai_status="Erreur",
                    ai_score=0,
                    ai_menaces=0
                )
                db.session.add(failed_analysis)
                db.session.commit()
            except Exception as db_e:
                print(f"[SCHEDULER] Impossible d'enregistrer l'erreur en DB : {db_e}")


def ssh_analyze_for_job(job) -> Analysis:
    """
    Exécute une analyse SSH pour une tâche planifiée.
    
    Args:
        job: Instance AnalysisJob
        
    Returns:
        Instance Analysis ou None
    """
    from models import Analysis, db
    from src.parser import parse_log_file
    from app import save_analysis_for_current_user, file_metadata
    from cryptography.fernet import Fernet
    
    ssh = None
    try:
        # Déchiffrer le mot de passe SSH
        ssh_password = job.ssh_password_enc
        if job.ssh_password_enc.startswith("encrypted:"):
            try:
                fernet_key = os.getenv("FERNET_KEY")
                f = Fernet(fernet_key.encode())
                ssh_password = f.decrypt(job.ssh_password_enc[10:].encode()).decode()
            except Exception as e:
                logger.error(f"Failed to decrypt SSH password: {str(e)}")
                raise
        
        # Établir la connexion SSH
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            job.target_ip,
            username=job.ssh_username,
            password=ssh_password,
            timeout=10
        )
        
        logger.info(f"SSH connected to {job.target_ip}")
        
        # Exécuter la commande pour récupérer les logs
        command = f"tail -n 500 {job.log_path}"
        stdin, stdout, stderr = ssh.exec_command(command)
        log_content = stdout.read().decode('utf-8', errors='replace')
        error_content = stderr.read().decode('utf-8', errors='replace')
        
        if error_content:
            logger.error(f"SSH command error: {error_content}")
            return None
        
        # Sauvegarder temporairement les logs
        temp_path = os.path.join(os.getenv('UPLOAD_FOLDER', 'uploads'), f"job_{job.id}_temp.log")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(log_content)
        
        # Parser les logs
        results = parse_log_file(temp_path)
        meta = file_metadata(temp_path)
        
        stats = {
            "errors": len(results.get('ERROR', [])),
            "warnings": len(results.get('WARNING', [])),
            "info": len(results.get('INFO', [])),
            "total": sum(len(v) for v in results.values())
        }
        
        # Créer l'enregistrement Analysis avec la clé utilisateur du job
        user = job.user
        
        # Créer temporairement une session utilisateur pour save_analysis_for_current_user
        from flask_login import current_user
        from unittest.mock import Mock
        
        mock_user = Mock()
        mock_user.id = user.id
        
        # Sauvegarder directement via la base de données
        analysis = Analysis(
            user_id=user.id,
            source_type="scheduled_ssh",
            source_path=job.log_path,
            server_ip=job.target_ip,
            stats=stats,
            segments=results,
            meta={
                "scheduled_job_id": job.id,
                "analysis_type": "scheduled",
                **meta
            }
        )
        
        db.session.add(analysis)
        db.session.commit()
        
        logger.info(f"Analysis saved for job {job.id}")
        
        # Nettoyer le fichier temporaire
        try:
            os.remove(temp_path)
        except Exception as e:
            logger.warning(f"Failed to delete temp file: {str(e)}")
        
        return analysis
        
    except Exception as e:
        logger.error(f"SSH analysis error for job {job.id}: {str(e)}")
        return None
    finally:
        if ssh:
            try:
                ssh.close()
            except Exception:
                pass


def check_anomalies(analysis) -> bool:
    """
    Vérifie s'il y a des anomalies dans l'analyse.
    
    Args:
        analysis: Instance Analysis
        
    Returns:
        bool: True si des anomalies sont détectées
    """
    if not analysis:
        return False
    
    stats = analysis.stats or {}
    
    # Critères d'anomalie
    has_critical_errors = stats.get('errors', 0) > 10
    has_many_warnings = stats.get('warnings', 0) > 20
    ai_status = analysis.ai_status
    has_high_threat = analysis.ai_menaces and analysis.ai_menaces > 5
    
    return has_critical_errors or has_many_warnings or ai_status == "Critique" or has_high_threat


def calculate_next_run_time(frequency: str, last_run: datetime) -> datetime:
    """
    Calcule le prochain moment d'exécution selon la fréquence.
    
    Args:
        frequency: 'hourly', 'daily', 'weekly', 'monthly'
        last_run: Dernière date d'exécution
        
    Returns:
        datetime: Prochain moment d'exécution
    """
    if frequency == "hourly":
        return last_run + timedelta(hours=1)
    elif frequency == "daily":
        return last_run + timedelta(days=1)
    elif frequency == "weekly":
        return last_run + timedelta(weeks=1)
    elif frequency == "monthly":
        return last_run + timedelta(days=30)
    else:
        return last_run + timedelta(days=1)


def send_email_notification(job, analysis: Analysis, pdf_content: bytes):
    """
    Envoie une notification email en cas d'anomalie.
    
    Args:
        job: Instance AnalysisJob
        analysis: Instance Analysis
        pdf_content: Contenu PDF (bytes) ou None
    """
    user = job.user
    recipient = job.notification_email or user.email
    
    msg = MIMEMultipart("alternative")
    msg['From'] = user.email_sender
    msg['To'] = recipient
    msg['Subject'] = f"[ALERTE] Anomalie détectée - {job.target_ip}"
    
    # Préparer le corps HTML
    stats = analysis.stats or {}
    ai_insights = analysis.meta.get('ai_insights', 'N/A') if analysis.meta else 'N/A'
    
    html_body = f"""
    <html>
    <body style="font-family: Arial, sans-serif; color: #333;">
        <h2 style="color: #dc2626;">🚨 Alerte Anomalie - Analyse Planifiée</h2>
        <p>Une anomalie a été détectée lors de l'analyse planifiée.</p>
        
        <table style="border-collapse: collapse; width: 100%; max-width: 600px; margin: 20px 0; border: 1px solid #ddd;">
            <tr style="background-color: #f2f2f2;">
                <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Paramètre</th>
                <th style="padding: 10px; border: 1px solid #ddd; text-align: left;">Valeur</th>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Serveur</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{job.target_ip}</td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Fichier Log</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{job.log_path}</td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Erreurs</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd; color: #dc2626;"><strong>{stats.get('errors', 0)}</strong></td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Warnings</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd; color: #f59e0b;"><strong>{stats.get('warnings', 0)}</strong></td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>État de sécurité</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>{analysis.ai_status or 'N/A'}</strong></td>
            </tr>
            <tr>
                <td style="padding: 10px; border: 1px solid #ddd;"><strong>Menaces détectées</strong></td>
                <td style="padding: 10px; border: 1px solid #ddd;">{analysis.ai_menaces or 0}</td>
            </tr>
        </table>
        
        <h3>Insights IA :</h3>
        <p style="background-color: #f9fafb; padding: 10px; border-left: 4px solid #3b82f6;">{ai_insights}</p>
        
        <p>Veuillez consulter le rapport PDF joint pour plus de détails.</p>
        
        <hr>
        <p style="color: #6b7280; font-size: 12px;">
            Rapport généré automatiquement par LogAnalyzer le {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}
        </p>
    </body>
    </html>
    """
    
    msg.attach(MIMEText(html_body, 'html'))
    
    # Ajouter le PDF s'il existe
    if pdf_content:
        attachment = MIMEApplication(pdf_content)
        attachment.add_header('Content-Disposition', 'attachment', filename=f"Rapport_Audit_{analysis.id}.pdf")
        msg.attach(attachment)
    
    # Envoyer l'email
    try:
        smtp_server = user.smtp_server or 'smtp.gmail.com'
        smtp_port = user.smtp_port or 587
        
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, int(smtp_port), timeout=20) as server:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(user.email_sender, user.email_password_enc)
            server.send_message(msg)
        
        logger.info(f"Email notification sent to {recipient}")
    except Exception as e:
        logger.error(f"Failed to send email notification: {str(e)}")
        raise