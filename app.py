from flask import Flask, render_template, request, jsonify
from flask_cors import CORS  # تأكد من تثبيتها بـ pip install flask-cors
import os
import paramiko
from config import Config
from src.parser import parse_log_file

app = Flask(__name__)
CORS(app)
app.config.from_object(Config)

# تأكد أن مجلد الـ uploads موجود
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/details')
def details():
    return render_template('details.html')

# --- هاد الجزء هو اللي كايحل صفحة SSH وكايمنع خطأ 404 ---
@app.route('/ssh')
def ssh_page():
    return render_template('ssh_config.html')

@app.route('/report')
def report_page():
    return render_template('report.html')

# --- هادا الـ API اللي كايخدم فـ الخلفية (POST) ---
@app.route('/ssh-analyze', methods=['POST'])
def ssh_analyze():
    data = request.json
    ip = data.get('ip')
    user = data.get('username')
    pwd = data.get('password')
    path = data.get('path', '/var/log/messages') # الافتراضي لـ Fedora
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)