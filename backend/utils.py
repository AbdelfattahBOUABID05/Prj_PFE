import os
import smtplib
import ssl
import json
import re
import dns.resolver
from datetime import datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from cryptography.fernet import Fernet
from openai import OpenAI
import logging
from fpdf import FPDF
from flask import current_app
from utils_security import decrypt_data
import qrcode
import io
import base64
import threading

logger = logging.getLogger(__name__)

def send_report_email_async(app, smtp_config, recipient, subject, html_body, pdf_bytes, filename):
    """Envoie un rapport par email de manière asynchrone."""
    def send_thread(app_context):
        with app_context:
            try:
                import smtplib
                import ssl
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart
                from email.mime.application import MIMEApplication

                msg = MIMEMultipart("mixed")
                msg['Subject'] = subject
                msg['To'] = recipient
                msg['From'] = smtp_config['user']
                msg.attach(MIMEText(html_body, 'html'))
                
                attachment = MIMEApplication(pdf_bytes)
                attachment.add_header('Content-Disposition', 'attachment', filename=filename)
                msg.attach(attachment)

                context = ssl.create_default_context()
                with smtplib.SMTP(smtp_config['server'], smtp_config['port'], timeout=30) as server:
                    if smtp_config.get('use_tls'):
                        server.starttls(context=context)
                    if smtp_config.get('password'):
                        server.login(smtp_config['user'], smtp_config['password'])
                    server.send_message(msg)
                logger.info(f"Email envoyé avec succès à {recipient}")
            except Exception as e:
                logger.error(f"Erreur envoi email asynchrone: {str(e)}")

    threading.Thread(
        target=send_thread,
        args=(app.app_context(),)
    ).start()

def generate_user_qr(user):
    """Génère un QR Code pour l'utilisateur Expert SOC."""
    try:
        # Données sécurisées : Nom, Prénom, Email uniquement
        qr_data = f"Expert SOC: {user.first_name} {user.last_name}\nEmail: {user.email}"
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        return buffered.getvalue()
    except Exception as e:
        logger.error(f"Erreur génération QR: {e}")
        return None

def encrypt_ssh_password(password: str) -> str:
    """Chiffre un mot de passe SSH."""
    if not password:
        return ""
    try:
        fernet_key = os.getenv("FERNET_KEY") or os.getenv("SECRET_KEY")
        if not fernet_key:
            return password
        
        import base64
        import hashlib
        key = base64.urlsafe_b64encode(hashlib.sha256(fernet_key.encode()).digest())
        f = Fernet(key)
        return f.encrypt(password.encode()).decode()
    except Exception as e:
        logger.error(f"Encryption error: {str(e)}")
        return password

def decrypt_ssh_password(token: str) -> str:
    """Déchiffre un mot de passe SSH."""
    if not token:
        return ""
    try:
        fernet_key = os.getenv("FERNET_KEY") or os.getenv("SECRET_KEY")
        if not fernet_key:
            return token
            
        import base64
        import hashlib
        key = base64.urlsafe_b64encode(hashlib.sha256(fernet_key.encode()).digest())
        f = Fernet(key)
        return f.decrypt(token.encode()).decode()
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        return token

def encrypt_admin_password(password: str) -> str:
    """Chiffre un mot de passe pour la console Admin."""
    if not password:
        return ""
    try:
        # Utilisation de MASTER_CONSOLE_KEY spécifiquement pour l'admin
        fernet_key = os.getenv("MASTER_CONSOLE_KEY") or os.getenv("SECRET_KEY")
        if not fernet_key:
            return password
        
        import base64
        import hashlib
        key = base64.urlsafe_b64encode(hashlib.sha256(fernet_key.encode()).digest())
        f = Fernet(key)
        return f.encrypt(password.encode()).decode()
    except Exception as e:
        logger.error(f"Admin Encryption error: {str(e)}")
        return password

def decrypt_admin_password(token: str) -> str:
    """Déchiffre un mot de passe pour la console Admin."""
    if not token:
        return ""
    try:
        fernet_key = os.getenv("MASTER_CONSOLE_KEY") or os.getenv("SECRET_KEY")
        if not fernet_key:
            return token
            
        import base64
        import hashlib
        key = base64.urlsafe_b64encode(hashlib.sha256(fernet_key.encode()).digest())
        f = Fernet(key)
        return f.decrypt(token.encode()).decode()
    except Exception as e:
        logger.error(f"Admin Decryption error: {str(e)}")
        return token

def file_metadata(filepath: str) -> dict:
    return {
        "filename": os.path.basename(filepath),
        "filesize": os.path.getsize(filepath),
        "last_modified": datetime.fromtimestamp(os.path.getmtime(filepath), tz=timezone.utc).isoformat()
    }

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _looks_like_cursor_key(value: str | None) -> bool:
    return bool(value and str(value).strip().startswith("crsr_"))

def _resolve_ai_config():
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

def _openai_style_completion(*, api_key: str, base_url: str | None, model_name: str, prompt: str) -> str:
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

def _heuristic_security_summary(log_text: str) -> dict:
    text = str(log_text or "")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    low = text.lower()
    error_hits = sum(1 for t in (" error", "failed", "critical", "denied", "panic", "fatal") if t in low)
    warn_hits = sum(1 for t in (" warning", "warn", "timeout", "retry", "degraded") if t in low)
    auth_hits = sum(1 for t in ("auth", "sudo", "ssh", "login", "invalid user", "permission") if t in low)
    failed_pass_hits = sum(1 for t in ("failed password",) if t in low)

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

def get_gemini_model():
    """Helper to get Gemini model globally."""
    import google.generativeai as genai
    
    cfg = _resolve_ai_config()
    api_key = cfg.get("gemini_key")
    if not api_key:
        raise RuntimeError("Missing GEMINI_API_KEY")
        
    genai.configure(api_key=api_key)
    return genai.GenerativeModel("gemini-1.5-flash")

def generate_security_summary_text(log_text: str, top_patterns: list = None) -> str:
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

    cursor_key = cfg["cursor_key"]
    if cursor_key:
        try:
            configured_base = cfg["cursor_base"]
            preferred = cfg["cursor_model"]
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

    openai_key = cfg["openai_key"]
    if openai_key:
        try:
            openai_base = cfg["openai_base"]
            openai_model = cfg["openai_model"]
            return _openai_style_completion(
                api_key=openai_key,
                base_url=openai_base,
                model_name=openai_model,
                prompt=prompt,
            )
        except Exception as e:
            print(f"[OpenAI Fallback Error] {str(e)}")

    try:
        model = get_gemini_model()
        return (model.generate_content(prompt).text or "").strip()
    except Exception as e:
        print(f"[Gemini Fallback Error] {str(e)}")
        raise

def generate_security_summary(*, model, log_text: str, top_patterns: list = None):
    try:
        text = generate_security_summary_text(log_text, top_patterns)
        print("DEBUG - IA Response:", text)
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
        parsed = json.loads(text)
    except Exception:
        try:
            match = re.search(r'\{.*\}', text, re.DOTALL)
            if match:
                parsed = json.loads(match.group(0))
        except Exception as re_err:
            print(f"Regex Parsing Error: {str(re_err)}")

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

def clean_text_for_pdf(text: str) -> str:
    """Nettoie le texte pour éviter les erreurs d'encodage FPDF (Latin-1)."""
    if not text: return ""
    return str(text).encode('latin-1', 'replace').decode('latin-1')

class SOC_Report(FPDF):
    def __init__(self, qr_bytes=None, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.qr_bytes = qr_bytes

    def header(self):
        # Watermark (QR Code avec Opacité 0.05) au centre de chaque page
        if self.qr_bytes:
            with self.local_context(fill_opacity=0.05):
                qr_stream = io.BytesIO(self.qr_bytes)
                # Positionner au centre de la page (A4: 210x297)
                self.image(qr_stream, x=55, y=100, w=100)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        
        # Numéro de page à gauche
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="L")
        
        # Note d'authentification à droite
        self.set_x(-100)
        self.cell(90, 10, clean_text_for_pdf("Document Authentifié par le SOC - Rapport Officiel"), align="R")

def generate_pdf_report_bytes(analysis):
    """
    Génère un rapport PDF professionnel à partir d'une analyse.
    """
    try:
        from models import User
        user = User.query.get(analysis.user_id)
        qr_bytes = generate_user_qr(user) if user else None

        pdf = SOC_Report(qr_bytes=qr_bytes)
        pdf.alias_nb_pages()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=20)
        
        # --- Header with Logos ---
        static_img_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "img")
        logo_est_path = os.path.join(static_img_dir, "logo_est.png")
        logo_awb_path = os.path.join(static_img_dir, "logo_awb.png")

        if os.path.exists(logo_est_path):
            pdf.image(logo_est_path, x=10, y=8, h=17)
        
        if os.path.exists(logo_awb_path):
            pdf.image(logo_awb_path, x=165, y=10, h=14)

        pdf.set_draw_color(221, 221, 221)
        pdf.set_line_width(0.3)
        pdf.line(10, 30, 200, 30)

        pdf.set_y(35)
        pdf.set_font("Helvetica", "B", 20)
        pdf.set_text_color(17, 24, 39)
        pdf.cell(190, 12, clean_text_for_pdf("RAPPORT D'AUDIT TECHNIQUE"), align="C", ln=True)
        
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(75, 85, 99)
        pdf.cell(190, 10, clean_text_for_pdf("Compte-rendu d'Analyse des Logs"), align="C", ln=True)
        
        pdf.ln(10)
        
        pdf.set_fill_color(249, 250, 251)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(17, 24, 39)
        pdf.cell(190, 10, clean_text_for_pdf("1. Résumé de l'analyse"), fill=True, ln=True)
        pdf.ln(2)
        
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(55, 65, 81)
        
        stats = analysis.stats or {}
        
        # Date formatée
        analysis_date = analysis.created_at
        if isinstance(analysis_date, datetime):
            date_str = analysis_date.strftime('%d/%m/%Y %H:%M')
        else:
            date_str = str(analysis_date)

        rows = [
            ("ID du Rapport", f"#{analysis.id}"),
            ("Date de l'Analyse", date_str),
            ("Source des Logs", analysis.server_ip if analysis.source_type == 'SSH' else "Hôte Local"),
            ("Fichier Source", analysis.source_path or "N/A"),
            ("Total lignes analysées", str(stats.get('total', 0)))
        ]
        
        for label, value in rows:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(50, 8, clean_text_for_pdf(label + " :"), border=0)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(140, 8, clean_text_for_pdf(value), border=0, ln=True)

        pdf.ln(10)

        # --- Contenu additionnel (ex: Patterns, AI Insights) si nécessaire ---
        # (Logique existante pour les sections peut être ajoutée ici)

        # --- Signature Finale (QR Code Opacité 1.0) ---
        if qr_bytes:
            # S'assurer qu'il y a assez d'espace pour la signature, sinon nouvelle page
            if pdf.get_y() > 220:
                pdf.add_page()
            
            pdf.ln(20)
            pdf.set_y(-70) # Positionner vers le bas
            
            # Label au dessus du QR Code
            pdf.set_x(130)
            pdf.set_font("Helvetica", "B", 10)
            pdf.set_text_color(17, 24, 39)
            pdf.cell(60, 10, clean_text_for_pdf("Authentifié par l'Expert SOC :"), ln=True, align="C")
            
            # QR Code à droite (Full Opacity)
            pdf.set_x(145)
            qr_stream = io.BytesIO(qr_bytes)
            pdf.image(qr_stream, h=30)
            
            # Nom de l'expert
            pdf.set_x(130)
            pdf.set_font("Helvetica", "I", 9)
            pdf.set_text_color(75, 85, 99)
            pdf.cell(60, 10, clean_text_for_pdf(f"{user.first_name} {user.last_name}"), align="C")

        return bytes(pdf.output(dest='S'))
    except Exception as e:
        logger.error(f"Erreur génération PDF: {e}")
        return None

def save_analysis(*, db, user_id: int, source_type: str, source_path: str, server_ip: str | None, stats: dict, segments: dict, meta: dict, log_content: str = ""):
    from models import Analysis
    all_lines = (segments.get('ERROR', []) + segments.get('WARNING', []) + segments.get('INFO', []))
    counts = {}
    for line in all_lines:
        cleaned = str(line).split(' ', 3)[-1].strip() if ' ' in str(line) else str(line)
        counts[cleaned] = counts.get(cleaned, 0) + 1
    top_patterns = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]

    ai_metrics = generate_security_summary(model=None, log_text=log_content, top_patterns=top_patterns) if log_content else {}
    
    a = Analysis(
        user_id=user_id,
        source_type=source_type,
        source_path=source_path,
        server_ip=server_ip,
        stats=stats,
        segments=segments,
        meta=meta,
        ai_score=ai_metrics.get("score"),
        ai_status=ai_metrics.get("status"),
        ai_menaces=ai_metrics.get("menaces"),
    )
    
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
    return a

def send_user_notification(user, subject, content):
    """Envoie une notification à l'utilisateur si une adresse de destination est configurée."""
    dest = user.notification_email or user.email
    if dest:
        # On génère l'expéditeur dynamique : {username}@awb.pfe.ma
        sender = f"{user.username}@awb.pfe.ma"
        return send_notification(dest, subject, content, sender=sender, user=user)
    return False

def send_notification(email_dest, subject, content, sender=None, user=None):
    """Envoie une notification par email ou simule l'envoi si SMTP non configuré."""
    # Priorité aux paramètres personnalisés de l'utilisateur
    if user:
        smtp_server = user.smtp_server or os.getenv("MAIL_SERVER")
        smtp_user = user.email_sender or os.getenv("MAIL_USERNAME") or os.getenv("SMTP_USER")
        smtp_pass = decrypt_data(user.email_password_enc) if user.email_password_enc else (os.getenv("MAIL_PASSWORD") or os.getenv("SMTP_PASS"))
        smtp_port = user.smtp_port or int(os.getenv("MAIL_PORT", 587))
    else:
        smtp_server = os.getenv("MAIL_SERVER")
        smtp_user = os.getenv("MAIL_USERNAME") or os.getenv("SMTP_USER")
        smtp_pass = os.getenv("MAIL_PASSWORD") or os.getenv("SMTP_PASS")
        smtp_port = int(os.getenv("MAIL_PORT", 587))
    
    # Si les paramètres SMTP sont absents, on passe en mode simulation
    is_simulated = not (smtp_server and smtp_user and smtp_pass)
    
    # Expéditeur dynamique par défaut si aucun expéditeur SMTP n'est fourni
    dynamic_sender = f"{user.username}@awb.pfe.ma" if user else "system@awb.pfe.ma"
    final_sender = sender or smtp_user or dynamic_sender
    
    if is_simulated:
        logger.info(f"[SIMULATION EMAIL] De: {final_sender} À: {email_dest} | Sujet: {subject}")
        return True

    msg = MIMEMultipart()
    use_tls = os.getenv("MAIL_USE_TLS", "True").lower() == "true"

    msg['Subject'] = subject
    msg['From'] = final_sender
    msg['To'] = email_dest
    msg.attach(MIMEText(content, 'html'))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
            if use_tls:
                server.starttls(context=context)
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        return True
    except Exception as e:
        logger.error(f"Erreur d'envoi d'email : {str(e)}")
        return False
