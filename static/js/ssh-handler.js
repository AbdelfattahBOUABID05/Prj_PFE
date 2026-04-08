/**
 * Gestion de la connexion SSH et de l'envoi des paramètres d'analyse au serveur.
 */
document.getElementById('sshForm')?.addEventListener('submit', async function(e) {
    // Empêcher le rechargement de la page par défaut lors de la soumission du formulaire
    e.preventDefault();
    
    const btn = document.getElementById('submitBtn');
    const status = document.getElementById('statusMessage');
    
    // Récupération du chemin du fichier log saisi par l'utilisateur
    const logPathInput = document.getElementById('path').value; 

    // Interface : Désactiver le bouton et afficher un indicateur de chargement (Spinner)
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span> Connexion...';

    // Préparation de l'objet JSON contenant les identifiants et paramètres SSH
    const payload = {
        ip: document.getElementById('ip').value,
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
        path: logPathInput,
        limit: document.getElementById('limit').value // Nombre de lignes à récupérer
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
            
            // Affichage d'un message de succès à l'utilisateur
            status.innerHTML = '<div class="alert alert-success">Succès! Analyse terminée.</div>';
            
            // Redirection automatique vers la page du rapport après 1 seconde
            setTimeout(() => window.location.href = '/report', 1000);
        } else {
            // Lever une erreur si le serveur renvoie un statut d'échec (ex: mauvaise IP ou mot de passe)
            throw new Error(result.message);
        }
    } catch (error) {
        // Gestion des erreurs : Affichage du message d'erreur et réinitialisation du bouton
        status.innerHTML = `<div class="alert alert-danger">Erreur: ${error.message}</div>`;
        btn.disabled = false;
        btn.innerHTML = 'Réessayer';
    }
});