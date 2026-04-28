import os
from flask import Flask, jsonify
from flask_cors import CORS
from flask_login import LoginManager
from dotenv import load_dotenv
import logging

from config import Config
from extensions import db, scheduler
from scheduler import init_scheduler
from models import User
from api_routes import api as api_blueprint

load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
init_scheduler(app)

# Initialisation des extensions
# Mise à jour de CORS pour être plus robuste
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:4200", "http://127.0.0.1:4200"]
    }
}, 
    supports_credentials=True, 
    expose_headers=["Authorization"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With", "Accept", "Origin"])

# Flask-Login configuration
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"status": "error", "message": "Non autorisé. Veuillez vous connecter."}), 401

@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except Exception:
        return None

# Register Blueprints
app.register_blueprint(api_blueprint)

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            
            admin_user = User.query.filter_by(username='admin').first()
            
            if not admin_user:
                admin_user = User(
                    username='admin',
                    email='admin@soc.local',
                    first_name='Admin',
                    last_name='SOC',
                    role='Admin',
                    is_first_login=False
                )
                admin_user.set_password('Admin@12345')
                db.session.add(admin_user)
                db.session.commit()
                print("✅ [OK] Default Admin created with role 'Admin'")
            else:
                if admin_user.role != 'Admin':
                    admin_user.role = 'Admin'
                    db.session.commit()
                    print("🔄 [Update] Admin role updated to 'Admin' for compatibility")
                else:
                    print("ℹ️ [Info] Admin account is already configured correctly")
            
            print("[*] Default Admin account verified/created.")
            print("Database initialized successfully!")

        except Exception as e:
            db.session.rollback()
            print(f"[!] Error during database seeding: {e}")

    app.run(host='localhost', port=5000, debug=True)