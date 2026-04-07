import os
os.environ['NO_PROXY'] = 'google.generativeai,smtp.gmail.com'
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import paramiko
from dotenv import load_dotenv
import google.generativeai as genai

# Importation des protocoles email pour l'envoi de rapports
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Importation du parseur personnalisé et de la configuration du projet
from src.parser import parse_log_file 
from config import Config 

# Chargement des variables d'environnement depuis le fichier .env (API Key, Email, etc.)
load_dotenv()

# Initialisation de l'application Flask
app = Flask(__name__)
CORS(app)
app.config.from_object(Config)

# Configuration de l'IA Google Gemini
api_key = os.getenv("GEMINI_API_KEY")
genai.configure(api_key=api_key)
model = genai.GenerativeModel('gemini-pro')

# Création du dossier d'upload si nécessaire
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# --- ROUTES DE NAVIGATION ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/details')
def details():
    return render_template('details.html')

@app.route('/ssh')
def ssh_page():
    return render_template('ssh_config.html')

@app.route('/report')
def report_page():
    return render_template('report.html')

@app.route('/send-report-page')
def send_report_page():
    """ Affiche la page de configuration et d'envoi d'email """
    return render_template('send_report.html')

# --- ROUTES API DE TRAITEMENT ---

@app.route('/ssh-analyze', methods=['POST'])
def ssh_analyze():
    """ Gère la connexion SSH et l'analyse des logs distants """
    data = request.json
    ip = data.get('ip')
    user = data.get('username')
    pwd = data.get('password')
    path = data.get('path', '/var/log/messages') 
    limit = int(data.get('limit', 100))

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=user, password=pwd, timeout=10)

        stdin, stdout, stderr = ssh.exec_command(f"tail -n {limit} {path}")
        log_content = stdout.read().decode('utf-8')
        error_content = stderr.read().decode('utf-8')
        ssh.close()

        if error_content:
            return jsonify({"status": "error", "message": error_content}), 400

        temp_path = os.path.join(app.config['UPLOAD_FOLDER'], "ssh_temp.log")
        with open(temp_path, "w", encoding="utf-8") as f:
            f.write(log_content)

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
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/ai-analyze-line', methods=['POST'])
def ai_analyze_line():
    """ Analyse une ligne de log spécifique via Gemini AI """
    try:
        data = request.json
        log_line = data.get('line')
        prompt = f"En tant qu'expert Linux, analyse ce log de Fedora et donne une solution : {log_line}"
        response = model.generate_content(prompt)
        return jsonify({"analysis": response.text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/send-email', methods=['POST'])
def send_email():
    data = request.json
    
    user_sender_email = data.get('sender_email')
    user_app_password = data.get('app_password')
    dest_email = data.get('email')
    subject = data.get('subject')
    comment = data.get('message')
    report_data = data.get('report_data') 

    # Construction du message MIME
    msg = MIMEMultipart()
    msg['From'] = user_sender_email
    msg['To'] = dest_email
    msg['Subject'] = subject

    body = f"""
    Bonjour,
    
    Voici le résumé du rapport LogAnalyzer :
    - Total des logs: {report_data['stats']['total']}
    - Erreurs: {report_data['stats']['errors']}
    - Warnings: {report_data['stats']['warnings']}
    
    Commentaire : {comment}
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Connexion sécurisée au serveur SMTP de Gmail
        server = smtplib.SMTP_SSL('smtp.gmail.com', 587)
        server.login(user_sender_email, user_app_password)
        server.send_message(msg)
        server.quit()
        return jsonify({"status": "success", "message": "Email envoyé avec succès !"})
    except Exception as e:
        return jsonify({"status": "error", "message": "Échec d'authentification ou erreur réseau."}), 500

# Démarrage du serveur Flask
if __name__ == '__main__':
    app.run(debug=True, port=5000)