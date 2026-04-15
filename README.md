# 🛡️ LogAnalyzer - AI-Powered Log Monitoring System

## 📌 Description

**LogAnalyzer** est une plateforme intelligente de monitoring et d’analyse de logs basée sur l’intelligence artificielle.
Elle permet d’automatiser la collecte, l’analyse et l’interprétation des journaux systèmes afin de détecter rapidement les anomalies et renforcer la sécurité des infrastructures.

---

## 🚀 Fonctionnalités Clés

* 🔐 **Authentification Multi-Rôles**
  Gestion sécurisée des accès (Super Admin / IT Analyst)

* 🤖 **Analyse IA des Logs**
  Détection d’anomalies et vulnérabilités via Google Gemini Pro

* 📑 **Génération de Rapports PDF**
  Rapports professionnels avec identité visuelle

* 📧 **Envoi Automatique par Email**
  Dispatch des rapports via SMTP sécurisé

* 📊 **Dashboard Interactif**
  Visualisation en temps réel avec graphiques (Chart.js)

* ❓ **Centre d’Aide Intégré**
  FAQ interactive pour faciliter l’utilisation

---

## 🏛️ Contexte du Projet

Ce projet s’inscrit dans une collaboration entre :

* 🏦 **Attijariwafa Bank** — Contexte professionnel et besoins métiers
* 🎓 **EST Sidi Bennour** — Encadrement académique (ISITW)

---

## 🔄 Workflow de l’Application

1. Authentification utilisateur
2. Saisie des informations SSH
3. Connexion au serveur distant
4. Extraction des logs (/var/log)
5. Analyse via IA (Gemini)
6. Génération d’un rapport PDF
7. Envoi automatique par email

---

## 🏗️ Architecture Technique

| Composant       | Technologie                               |
| --------------- | ----------------------------------------- |
| Backend         | Flask (Python 3), Flask-Login, Flask-Mail |
| Base de données | SQLite + SQLAlchemy                       |
| IA              | Google Generative AI (Gemini Pro)         |
| Frontend        | Bootstrap 5, JavaScript (ES6), Chart.js   |
| PDF             | FPDF2                                     |

---

## 🔐 Sécurité

* Authentification sécurisée (sessions Flask)
* Accès SSH contrôlé
* Validation des entrées utilisateur
* Protection des variables sensibles via `.env`
* Utilisation de mots de passe d’application (SMTP)

---

## 📸 Aperçu de l’Application

👉 *(Ajoute هنا screenshots ديالك)*

* Dashboard
* Login
* Analyse des logs
* Rapport PDF

---

## 🎥 Démo

👉 *(حط هنا lien ديال vidéo ولا GitHub demo)*

---

## 🛠️ Installation

```bash
# Cloner le projet
git clone https://github.com/AbdelfattahBOUABID05/Prj_PFE.git
cd Prj_PFE

# Installer les dépendances
pip install -r requirements.txt
```

---

## ⚙️ Configuration

### 🔑 Variables d’environnement (.env)

```env
GEMINI_API_KEY=your_api_key
SECRET_KEY=your_secret_key
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
REMOVE_BG_API_KEY=your_key
```

---

## 🖥️ Configuration Serveur (SSH)

```bash
sudo dnf install openssh-server -y
sudo systemctl enable --now sshd
sudo firewall-cmd --add-service=ssh --permanent
sudo firewall-cmd --reload
```

⚠️ L’utilisateur SSH doit avoir accès à `/var/log/`

---

## 👤 Accès par Défaut

* **Username:** admin
* **Password:** Admin@12345

---

## 👨‍💻 Auteur

**Abdelfattah Bouabid**
🎓 Étudiant ISITW - EST Sidi Bennour
🏦 Stage PFE chez Attijariwafa Bank