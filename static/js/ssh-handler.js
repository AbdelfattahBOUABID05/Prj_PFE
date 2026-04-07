document.getElementById('sshForm')?.addEventListener('submit', async function(e) {
    e.preventDefault();
    const btn = document.getElementById('submitBtn');
    const status = document.getElementById('statusMessage');
    
    // شد المسار اللي كتب المستخدم
    const logPathInput = document.getElementById('path').value; 

    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Connexion...';

    const payload = {
        ip: document.getElementById('ip').value,
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
        path: logPathInput,
        limit: document.getElementById('limit').value
    };

    try {
        const response = await fetch('/ssh-analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const result = await response.json();

        if (result.status === "success") {
            // كنزيدو المسار يدويًا للبيانات قبل ما نسيفيوها
            result.path = logPathInput; 
            
            // كنخزنو كولشي في localStorage
            localStorage.setItem('lastAnalysis', JSON.stringify(result));
            
            status.innerHTML = '<div class="alert alert-success">Succès! Analyse terminée.</div>';
            
            // التوجيه لصفحة التقرير
            setTimeout(() => window.location.href = '/report', 1000);
        } else {
            throw new Error(result.message);
        }
    } catch (error) {
        status.innerHTML = `<div class="alert alert-danger">Erreur: ${error.message}</div>`;
        btn.disabled = false;
        btn.innerHTML = 'Réessayer';
    }
});