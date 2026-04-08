document.getElementById('emailForm')?.addEventListener('submit', async function(e) {
    e.preventDefault();
    const btn = document.getElementById('sendBtn');
    const status = document.getElementById('statusMail');
    
    const lastAnalysis = JSON.parse(localStorage.getItem('lastAnalysis'));
    const analysisId = lastAnalysis?.analysis_id;

    const payload = {
    sender_email: document.getElementById('sender_email').value,
    app_password: document.getElementById('app_password').value,
    email: document.getElementById('dest_email').value,
    subject: document.getElementById('subject').value,
    message: document.getElementById('message').value,
    analysis_id: analysisId,
    report_data: lastAnalysis
    };

    btn.disabled = true;
    btn.innerText = "Envoi en cours...";

    try {
        const response = await fetch('/send-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const res = await response.json();
        if(res.status === "success") {
            status.innerHTML = `<div class="alert alert-success">${res.message}</div>`;
        } else {
            throw new Error(res.message);
        }
    } catch (error) {
        status.innerHTML = `<div class="alert alert-danger">Erreur: ${error.message}</div>`;
        btn.disabled = false;
        btn.innerText = "Réessayer";
    }
});