import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", os.urandom(24))
    
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    
    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # Taille maximale 16 Mo

    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///log_analyzer.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    DEFAULT_ADMIN_USERNAME = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
    DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@local")
    DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin@12345")

    # Configuration Email (Flask-Mail style)
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False