/**
 * Gestion de la connexion SSH et de l'envoi des paramètres d'analyse au serveur.
 */
async function runSshAnalysis(isTodayOnly = false) {
    const btn = isTodayOnly ? document.getElementById('todayBtn') : document.getElementById('submitBtn');
    const otherBtn = isTodayOnly ? document.getElementById('submitBtn') : document.getElementById('todayBtn');
    const status = document.getElementById('statusMessage');
    
    // Récupération du chemin du fichier log saisi par l'utilisateur
    const logPathInput = document.getElementById('path').value; 

    // Interface : Désactiver les boutons et afficher un indicateur de chargement
    btn.disabled = true;
    if (otherBtn) otherBtn.disabled = true;

    const originalHtml = btn.innerHTML;
    if (isTodayOnly) {
        const today = new Date().toLocaleDateString('fr-FR', { day: 'numeric', month: 'short' });
        btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span> Filtrage des logs du ${today}...`;
    } else {
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Connexion...';
    }

    // Préparation de l'objet JSON contenant les identifiants et paramètres SSH
    const payload = {
        ip: document.getElementById('ip').value,
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
        path: logPathInput,
        limit: document.getElementById('limit').value, // Nombre de lignes à récupérer
        today_only: isTodayOnly
    };

    try {
        // Envoi de la requête POST vers la route Flask '/ssh-analyze'
        const response = await fetch('/ssh-analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        // Lecture de la réponse JSON renvoyée par le serveur Python
        const result = await response.json();

        if (result.status === "success") {
            // Ajout du chemin du fichier aux résultats pour l'affichage ultérieur
            result.path = logPathInput; 
            result.generated_at = new Date().toISOString();
            
            // Stockage persistant des résultats dans le navigateur (LocalStorage)
            localStorage.setItem('lastAnalysis', JSON.stringify(result));
            
            // Affichage d'un message de succès avec SweetAlert2
            Swal.fire({
                icon: 'success',
                title: 'Analyse terminée',
                text: 'La connexion SSH et l\'analyse des logs ont réussi.',
                customClass: {
                    popup: 'swal-custom-popup',
                    title: 'swal-custom-title',
                    confirmButton: 'swal-custom-confirm'
                },
                buttonsStyling: false,
                timer: 1500,
                showConfirmButton: false
            });
            
            // Redirection automatique vers la page des lignes de logs
            setTimeout(() => window.location.href = '/details', 1600);
        } else if (result.code === "NO_LOGS_TODAY") {
            // Cas spécifique : Aucun log trouvé pour aujourd'hui
            Swal.fire({
                icon: 'info',
                title: 'Aucun log',
                text: result.message,
                customClass: {
                    popup: 'swal-custom-popup',
                    title: 'swal-custom-title',
                    confirmButton: 'swal-custom-confirm'
                },
                buttonsStyling: false
            });
            btn.disabled = false;
            if (otherBtn) otherBtn.disabled = false;
            btn.innerHTML = originalHtml;
        } else {
            // Lever une erreur si le serveur renvoie un statut d'échec
            throw new Error(result.message);
        }
    } catch (error) {
        // Gestion des erreurs avec SweetAlert2
        Swal.fire({
            icon: 'error',
            title: 'Échec de l\'analyse',
            text: error.message,
            customClass: {
                popup: 'swal-custom-popup',
                title: 'swal-custom-title',
                confirmButton: 'swal-custom-confirm'
            },
            buttonsStyling: false
        });
        btn.disabled = false;
        if (otherBtn) otherBtn.disabled = false;
        btn.innerHTML = originalHtml;
    }
}

document.getElementById('sshForm')?.addEventListener('submit', function(e) {
    e.preventDefault();
    runSshAnalysis(false);
});

document.getElementById('todayBtn')?.addEventListener('click', function() {
    // Vérifier si le formulaire est valide avant de lancer l'analyse "Today"
    const form = document.getElementById('sshForm');
    if (form.checkValidity()) {
        runSshAnalysis(true);
    } else {
        form.reportValidity();
    }
});