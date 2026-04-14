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
    signature_path = db.Column(db.String(255), nullable=True) # Chemin vers le fichier image de la signature

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

