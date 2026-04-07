import os
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import paramiko
from dotenv import load_dotenv
import google.generativeai as genai

# Importation du parseur personnalisé et de la configuration du projet
from src.parser import parse_log_file 
from config import Config 

# Chargement des variables d'environnement (ex: API KEY) depuis le fichier .env
load_dotenv()

# Initialisation de l'application Flask et configuration des CORS (Cross-Origin Resource Sharing)
app = Flask(__name__)
CORS(app)
app.config.from_object(Config)

# Configuration de l'IA Google Gemini avec la clé API sécurisée
api_key = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=api_key)
model = genai.GenerativeModel('gemini-1.5-flash')

# Création automatique du dossier de téléchargement s'il n'existe pas
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- ROUTES DE NAVIGATION (AFFICHAGE DES PAGES HTML) ---

@app.route('/')
def index():
    """ Affiche la page d'accueil (Dashboard) """
    return render_template('index.html')

@app.route('/details')
def details():
    """ Affiche les détails des logs """
    return render_template('details.html')

@app.route('/ssh')
def ssh_page():
    """ Affiche la page de configuration de la connexion SSH """
    return render_template('ssh_config.html')

@app.route('/report')
def report_page():
    """ Affiche la page du rapport d'analyse final """
    return render_template('report.html')

# --- ROUTES API (TRAITEMENT DES DONNÉES) ---

@app.route('/ssh-analyze', methods=['POST'])
def ssh_analyze():
    """
    Établit une connexion SSH, récupère les logs d'un serveur distant 
    et les analyse localement.
    """
    data = request.json
    ip = data.get('ip')
    user = data.get('username')
    pwd = data.get('password')
    path = data.get('path', '/var/log/messages') 
    limit = int(data.get('limit', 100))

    try:
        # Initialisation du client SSH avec Paramiko
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy()) # Accepter automatiquement les clés d'hôte
        ssh.connect(ip, username=user, password=pwd, timeout=10)

        # Exécution de la commande Linux 'tail' pour lire les dernières lignes du fichier log
        stdin, stdout, stderr = ssh.exec_command(f"tail -n {limit} {path}")
        log_content = stdout.read().decode('utf-8')
        error_content = stderr.read().decode('utf-8')
        ssh.close()

        # Gestion des erreurs de commande SSH (ex: fichier introuvable)
        if error_content:
            return jsonify({"status": "error", "message": error_content}), 400

        # Sauvegarde temporaire du contenu récupéré pour le traitement par le parseur
        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], "ssh_temp.log")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(log_content)

        # Analyse du fichier temporaire et calcul des statistiques
        results = parse_log_file(temp_path)
        return jsonify({
            "status": "success",
            "segments": results,
            "stats": {
                "errors": len(results['ERROR']),
                "warnings": len(results['WARNING']),
                "info": len(results['INFO']),
                "total": sum(len(v) for v in results.values())
            }
        })
    except Exception as e:
        # Retourne l'erreur en cas d'échec de la connexion ou de l'analyse
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/ai-analyze-line', methods=['POST'])
def ai_analyze_line():
    """
    Envoie une ligne de log spécifique à l'IA Gemini pour obtenir 
    une explication et une solution.
    """
    try:
        data = request.json
        log_line = data.get('line')
        
        # Définition du prompt envoyé au modèle génératif
        prompt = f"En tant qu'expert Linux, analyse ce log de Fedora et donne une solution : {log_line}"
        
        # Génération du contenu par l'IA
        response = model.generate_content(prompt)
        return jsonify({"analysis": response.text})
    except Exception as e:
        print(f"AI Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

# Lancement de l'application sur le port 5000 avec le mode Debug activé
if __name__ == '__main__':
    app.run(debug=True, port=5000)