LogAnalyzer SOC - Architecture Séparée (V2.0)
🌟 Vue d'ensemble

LogAnalyzer SOC est une solution complète de surveillance et d'analyse de journaux système, conçue pour les analystes SOC. L'application combine la puissance de l'IA pour la détection de menaces et une interface moderne pour une gestion efficace des incidents.

    Backend : API Flask sécurisée avec intégration de Google Gemini AI.

    Frontend : Interface Single Page Application (SPA) développée avec Angular 17 et Tailwind CSS.

🔑 Accès par Défaut

Pour votre première connexion après l'initialisation de la base de données :

    Email : admin@soc.com

    Mot de passe : Admin@123

    Note : Le système vous demandera obligatoirement de changer ce mot de passe lors de votre première session pour des raisons de sécurité.

🖥️ Configuration de la Machine Virtuelle (Cible SSH)

Pour que l'analyse SSH fonctionne correctement, la machine virtuelle que vous souhaitez scanner (ex: Ubuntu, Kali) doit être configurée comme suit :

    Installer le serveur SSH :
    Bash

    sudo apt update && sudo apt install openssh-server -y

    Activer le service :
    Bash

    sudo systemctl enable ssh && sudo systemctl start ssh

    Droits de lecture sur les logs :
    L'utilisateur utilisé pour la connexion SSH doit avoir le droit de lire /var/log/syslog ou /var/log/auth.log.
    Bash

    # Ajouter l'utilisateur au groupe 'adm' (recommandé)
    sudo usermod -aG adm [votre_utilisateur]

    Pare-feu :
    Assurez-vous que le port 22 est ouvert :
    Bash

    sudo ufw allow ssh

🚀 Installation & Lancement
Backend (Flask)

    Accéder au dossier : cd backend

    Installer les dépendances : pip install -r requirements.txt

    Variables d'environnement (.env) :
    Extrait de code

    SECRET_KEY=votre_cle_flask
    FERNET_KEY=votre_cle_de_chiffrement_aes
    GEMINI_API_KEY=votre_cle_google_ai
    DATABASE_URL=sqlite:///loganalyzer.db

    Lancer le serveur : flask run --port=5000

Frontend (Angular)

    Accéder au dossier : cd frontend

    Installer : npm install

    Lancer : npm start (Accès : http://localhost:4200)

🛠️ Endpoints API Principaux
Méthode	Endpoint	Description
POST	/api/auth/login	Authentification utilisateur
POST	/api/ssh/analyze	Analyse en temps réel via SSH
POST	/api/auth/change-password	Sécurité : Changement de mot de passe obligatoire
GET	/api/dashboard	Statistiques et graphiques IA
GET	/api/analyses/:id/pdf	Exportation du rapport d'audit
🛡️ Sécurité des Données

    Chiffrement au repos : Les identifiants SSH sont stockés en base de données via un chiffrement symétrique AES-256.

    Hachage : Les mots de passe utilisateurs utilisent l'algorithme bcrypt.

    CORS : Restrictions d'accès limitées au domaine du frontend.