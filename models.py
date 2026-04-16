from __future__ import annotations

from datetime import datetime, timezone

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="Analyst")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    
    # Configuration email simplifiée
    email_sender = db.Column(db.String(255), nullable=True)
    email_password_enc = db.Column(db.String(255), nullable=True)
    smtp_server = db.Column(db.String(255), nullable=True)
    smtp_port = db.Column(db.Integer, nullable=True)
    signature_path = db.Column(db.String(255), nullable=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return (self.role or "").lower() == "admin"


class Analysis(db.Model):
    __tablename__ = "analyses"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)

    source_type = db.Column(db.String(20), nullable=False)  # ssh | upload
    source_path = db.Column(db.Text, nullable=False)
    server_ip = db.Column(db.String(64), nullable=True)

    # Conserve les payloads bruts pour la traçabilité
    stats = db.Column(db.JSON, nullable=False)
    segments = db.Column(db.JSON, nullable=False)
    meta = db.Column(db.JSON, nullable=False)

    # Métriques IA pour le dashboard
    ai_score = db.Column(db.Integer, nullable=True)
    ai_status = db.Column(db.String(20), nullable=True)
    ai_menaces = db.Column(db.Integer, nullable=True)

    user = db.relationship("User", backref=db.backref("analyses", lazy="dynamic"))


class AnalysisJob(db.Model):
    """Modèle pour les tâches d'analyse planifiées"""
    __tablename__ = "analysis_jobs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Paramètres de la tâche
    target_ip = db.Column(db.String(64), nullable=False)  # Adresse IP cible
    log_path = db.Column(db.String(255), nullable=False, default="/var/log/syslog")  # Chemin du fichier log
    frequency = db.Column(db.String(20), nullable=False)  # hourly, daily, weekly, monthly
    
    # Statut de la tâche
    status = db.Column(db.String(20), nullable=False, default="pending")  # pending, active, refused, stopped
    
    # Métadonnées SSH
    ssh_username = db.Column(db.String(128), nullable=True)
    ssh_password_enc = db.Column(db.String(255), nullable=True)  # Encrypted password
    
    # Dates
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    approved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_run_at = db.Column(db.DateTime(timezone=True), nullable=True)
    next_run_at = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # Raison du refus (si applicable)
    refusal_reason = db.Column(db.Text, nullable=True)
    
    # Notifications
    notify_on_anomaly = db.Column(db.Boolean, default=True)
    notification_email = db.Column(db.String(255), nullable=True)
    
    # Relation avec l'utilisateur
    user = db.relationship("User", backref=db.backref("scheduled_jobs", lazy="dynamic"))

    def __repr__(self):
        return f"<AnalysisJob {self.id} - {self.target_ip} - {self.status}>"