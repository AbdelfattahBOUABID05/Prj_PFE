🛡️ LogAnalyzer - Système d'Analyse de Logs

LogAnalyzer est une solution complète de monitoring et de sécurité. Elle permet de surveiller et d'analyser les logs des serveurs à distance via SSH, en exploitant l'IA pour transformer des logs techniques bruts en rapports d'audit exploitables.
🚀 Nouvelles FonctionnalitéS

    🔐 Auth & Multi-Roles : Système de connexion sécurisé (Super Admin / IT Analyst).

    🤖 AI Security Audit : Intégration de Google Gemini pour l'analyse des vulnérabilités.

    📑 Advanced Reporting : Génération de PDF professionnels incluant les logos institutionnels (Attijariwafa Bank & EST Sidi Bennour).

    📧 Email Dispatch : Envoi automatisé des rapports d'audit par e-mail via SMTP sécurisé.

    ❓ Centre d'Aide Interactif : Une page de documentation intégrée (FAQ) avec système d'accordéon pour guider l'utilisateur.

    📊 Executive Dashboard : Interface moderne avec graphiques en temps réel (Chart.js).

🏛️ Contexte Institutionnel

Ce projet a été développé dans le cadre d'un Projet de Fin d'Études (PFE), fruit d'une collaboration entre :

    Attijariwafa Bank : Partenaire stratégique et cadre d'application professionnel.

    EST Sidi Bennour : Encadrement académique et technique.

🛠️ Configuration & Prérequis
1. Serveur Cible (Fedora/Ubuntu)

Pour permettre l'extraction des logs, SSH doit être actif :
Bash

sudo dnf install openssh-server -y
sudo systemctl enable --now sshd
sudo firewall-cmd --add-service=ssh --permanent && sudo firewall-cmd --reload

Note : Assurez-vous que l'utilisateur SSH a les droits de lecture sur /var/log/.
2. Configuration du Reporting (Email)

Pour activer l'envoi des rapports par mail :

    Accédez à votre Profil.

    Configurez votre adresse Gmail et votre Mot de passe d'application (App Password).

    Vérifiez les paramètres SMTP (Port 587).

🏗️ Architecture Technique

    Backend : Flask, Python 3.x, Flask-Login.

    Base de Données : SQLite & SQLAlchemy.

    Analyse AI : Google Generative AI (Gemini Pro).

    Frontend : Bootstrap 5, FontAwesome, JavaScript (ES6).

    Libraries PDF : fpdf2 pour la génération dynamique.

📦 Installation
Bash

git clone https://github.com/AbdelfattahBOUABID05/Prj_PFE.git
cd Prj_PFE
pip install -r requirements.txt

Fichier .env :
Extrait de code

GEMINI_API_KEY=votre_cle_api
SECRET_KEY=votre_cle_secrete_flask
MAIL_USERNAME=votre_email@gmail.com
MAIL_PASSWORD=votre_app_password

👤 Accès par Défaut

    Username : admin

    Password : Admin@12345

👨‍💻 Développeur

Abdelfattah Bouabid
Étudiant en Ingénierie des Systèmes d'Informatique et Technologies Web (ISITW) - EST Sidi Bennour.
Stage de fin d'études effectué au sein d'Attijariwafa Bank.