# 🛡️ LogAnalyzer - Système d'Analyse de Logs Fedora (Version Pro)

**LogAnalyzer** est une solution complète de monitoring et de sécurité. Elle permet de surveiller et d'analyser les logs des serveurs **Fedora** à distance via SSH, en exploitant l'IA (Google Gemini) pour transformer des logs techniques bruts en rapports d'audit exploitables.

---

## 🚀 Nouvelles Fonctionnalités (V2.0)
* **🔐 Auth & Multi-Roles** : Système de connexion sécurisé avec deux niveaux d'accès :
    * **Super Admin** : Gestion des utilisateurs et accès complet.
    * **IT Analyst** : Consultation et analyse des serveurs.
* **🤖 AI Security Audit** : Intégration avancée de Google Gemini pour l'analyse prédictive des erreurs.
* **📡 SSH Log Streaming** : Extraction en temps réel depuis des environnements Linux distants.
* **📊 Executive Dashboard** : Interface moderne (Glassmorphism) avec graphiques d'activité.
* **📑 Audit Reports** : Génération de rapports PDF professionnels prêts à l'impression.

---

## 🛠️ Configuration du Serveur Cible (Fedora)

Pour que LogAnalyzer puisse communiquer avec votre serveur, vous devez configurer le service **SSH** correctement :

### 1. Installation du service SSH
Si SSH n'est pas encore installé sur votre serveur Fedora :
sudo dnf install openssh-server -y

2. Activation et démarrage
sudo systemctl enable sshd
sudo systemctl start sshd

3. Configuration du Firewall

Il est impératif d'autoriser le port 22 (SSH) pour permettre la connexion entrante :
sudo firewall-cmd --add-service=ssh --permanent
sudo firewall-cmd --reload

4. Vérification de l'IP

Notez l'adresse IP de votre serveur pour la configurer dans LogAnalyzer :
ip addr show

🏗️ Architecture Technique

    Backend : Flask (Python 3.x)

    Base de Données : SQLite avec SQLAlchemy (Gestion des utilisateurs & sessions).

    Sécurité : Flask-Login & Werkzeug (Hashing des mots de passe).

    Frontend : JavaScript ES6+, Bootstrap 5, Chart.js.

    AI Integration : Google Generative AI SDK.

📦 Installation & Déploiement

    Cloner le projet :
    git clone [https://github.com/AbdelfattahBOUABID05/Prj_PFE.git](https://github.com/AbdelfattahBOUABID05/Prj_PFE.git)
    cd Prj_PFE

    Installer les dépendances :
    pip install -r requirements.txt

    Variables d'environnement (.env) :
    Extrait de code

    GEMINI_API_KEY=votre_cle_api
    SECRET_KEY=votre_cle_secrete_flask

    Lancement de l'application :
    python app.py

    Note : La base de données log_analyzer.db sera créée automatiquement au premier lancement.

👤 Accès par Défaut

    Username : admin

    Password : Admin@12345

Développé par : Abdelfattah Bouabid Étudiant en Ingénierie des Systèmes d'Information et Technologies Web (ISITW) - EST Sidi Bennour
