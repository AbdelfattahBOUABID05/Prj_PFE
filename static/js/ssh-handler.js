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

/**
 * Gestion du Terminal Interactif
 */
const terminalBody = document.getElementById('terminalBody');
const terminalInput = document.getElementById('terminalInput');
const clearBtn = document.getElementById('clearTerminal');
const terminalStatusDot = document.getElementById('terminalStatusDot');

// Champs d'identification du terminal (Indépendants du formulaire principal)
const termHost = document.getElementById('termHost');
const termUser = document.getElementById('termUser');
const termPass = document.getElementById('termPass');

function updateTerminalStatus(status) {
    if (!terminalStatusDot) return;
    terminalStatusDot.className = 'status-dot';
    if (status === 'success') {
        terminalStatusDot.classList.add('bg-success');
        terminalStatusDot.title = 'Connecté (Dernière commande réussie)';
    } else if (status === 'error') {
        terminalStatusDot.classList.add('bg-danger');
        terminalStatusDot.title = 'Erreur de connexion / exécution';
    } else {
        terminalStatusDot.classList.add('bg-secondary');
        terminalStatusDot.title = 'Déconnecté';
    }
}

function appendToTerminal(text, type = 'output') {
    if (!terminalBody) return;
    const line = document.createElement('div');
    line.className = `terminal-output-line ${type === 'error' ? 'terminal-error' : (type === 'cmd' ? 'terminal-cmd-echo' : '')}`;
    line.textContent = text;
    terminalBody.appendChild(line);
    terminalBody.scrollTop = terminalBody.scrollHeight;
}

async function executeTerminalCommand() {
    const commandValue = terminalInput.value.trim();
    if (!commandValue) return;

    // Gestion locale de la commande 'clear'
    if (commandValue.toLowerCase() === 'clear') {
        if (terminalBody) {
            terminalBody.innerHTML = '<div class="text-success small mb-2"># Terminal effacé. Prêt.</div>';
        }
        terminalInput.value = '';
        return;
    }

    // Récupération des identifiants depuis la barre supérieure du terminal
    const host = termHost?.value.trim();
    const user = termUser?.value.trim();
    const pass = termPass?.value;

    // Validation des champs avant l'envoi
    if (!host || !user || !pass) {
        appendToTerminal(`$ ${commandValue}`, "cmd"); // Echo the command first
        appendToTerminal("Erreur : Veuillez remplir le Host, User et Pass.", "error");
        updateTerminalStatus('error');
        terminalInput.value = ''; // Clear input even on error
        return;
    }

    appendToTerminal(`$ ${commandValue}`, "cmd");
    terminalInput.value = '';
    terminalInput.disabled = true;

    try {
        const response = await fetch('/terminal/exec', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                host: host,
                user: user,
                pass: pass,
                command: commandValue 
            })
        });

        const result = await response.json();

        if (result.status === "success") {
            updateTerminalStatus('success');
            if (result.output) appendToTerminal(result.output);
            if (result.error) appendToTerminal(result.error, "error");
            if (!result.output && !result.error) appendToTerminal("(Aucune sortie)");
        } else {
            updateTerminalStatus('error');
            appendToTerminal(`Erreur : ${result.message}`, "error");
        }
    } catch (error) {
        updateTerminalStatus('error');
        appendToTerminal(`Erreur de communication : ${error.message}`, "error");
    } finally {
        terminalInput.disabled = false;
        terminalInput.focus();
    }
}

terminalInput?.addEventListener('keypress', function(e) {
    if (e.key === 'Enter') {
        executeTerminalCommand();
    }
});

clearBtn?.addEventListener('click', function() {
    if (terminalBody) {
        terminalBody.innerHTML = '<div class="text-success small mb-2"># Terminal effacé. Prêt.</div>';
    }
});

// Focus automatique sur l'input quand le modal s'ouvre
document.getElementById('terminalModal')?.addEventListener('shown.bs.modal', function () {
    terminalInput?.focus();
});