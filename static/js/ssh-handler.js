/**
 * Gestion des profils serveurs (Quick Connect)
 */
async function loadServerProfiles() {
    const container = document.getElementById('serverProfilesContainer');
    const section = document.getElementById('quickConnectSection');
    const header = document.getElementById('quickConnectHeader');
    if (!container || !section) return;

    try {
        const response = await fetch('/api/ssh/profiles');
        const data = await response.json();

        if (data.success && data.profiles.length > 0) {
            section.classList.remove('d-none');
            header?.classList.remove('d-none');
            container.innerHTML = data.profiles.map(p => `
                <div class="col-md-4">
                    <div class="glass-card p-3 h-100 quick-connect-card" onclick="useProfile(${p.id})">
                        <div class="d-flex justify-content-between align-items-start mb-2">
                            <div class="quick-icon bg-soft-primary text-primary">
                                <i class="fas fa-server"></i>
                            </div>
                            <button class="btn btn-link btn-sm text-danger p-0" onclick="event.stopPropagation(); deleteProfile(${p.id})">
                                <i class="fas fa-trash-alt"></i>
                            </button>
                        </div>
                        <h6 class="fw-bold mb-1 text-truncate">${p.ip}</h6>
                        <p class="text-muted small mb-0"><i class="fas fa-user me-1"></i>${p.username}</p>
                        <p class="text-muted small mb-2 text-truncate"><i class="fas fa-file-code me-1"></i>${p.log_path}</p>
                        <div class="d-grid mt-2">
                            <button class="btn btn-sm btn-soft-primary py-1">Lancer l'analyse</button>
                        </div>
                    </div>
                </div>
            `).join('');
        } else {
            section.classList.add('d-none');
            header?.classList.add('d-none');
        }
    } catch (error) {
        console.error("Erreur lors du chargement des profils :", error);
    }
}

async function useProfile(profileId) {
    const submitBtn = document.getElementById('submitBtn');
    const originalHtml = submitBtn.innerHTML;

    try {
        const response = await fetch(`/api/ssh/profiles/${profileId}/decrypt`, { method: 'POST' });
        const data = await response.json();

        if (data.success) {
            // Récupérer les infos du profil depuis l'API
            const profilesResponse = await fetch('/api/ssh/profiles');
            const profilesData = await profilesResponse.json();
            const profile = profilesData.profiles.find(p => p.id === profileId);

            if (profile) {
                document.getElementById('ip').value = profile.ip;
                document.getElementById('username').value = data.username;
                document.getElementById('password').value = data.password;
                document.getElementById('path').value = profile.log_path;

                // Animation visuelle
                const form = document.getElementById('sshForm');
                form.classList.add('pulse-highlight');
                setTimeout(() => form.classList.remove('pulse-highlight'), 1000);

                // Lancement immédiat de l'analyse
                runSshAnalysis(false);
            }
        }
    } catch (error) {
        Swal.fire('Erreur', 'Impossible de charger le serveur : ' + error.message, 'error');
    }
}

const formDatePickerBtn = document.getElementById('formDatePickerBtn');
const formDateInputContainer = document.getElementById('formDateInputContainer');
const analyzeFormTodayBtn = document.getElementById('analyzeFormTodayBtn');
const runFormDateAnalysisBtn = document.getElementById('runFormDateAnalysis');

formDatePickerBtn?.addEventListener('click', () => {
    formDateInputContainer?.classList.toggle('d-none');
});

// Mise à jour dynamique du label du bouton au changement de date
document.getElementById('formTargetDate')?.addEventListener('change', (e) => {
    const dateVal = e.target.value;
    const btn = document.getElementById('analyzeFormTodayBtn');
    if (dateVal && btn) {
        const formattedDate = new Date(dateVal).toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' });
        btn.innerHTML = `<i class="fas fa-calendar-alt me-2"></i> Analyser les logs du ${formattedDate}`;
    } else if (btn) {
        btn.innerHTML = `<i class="fas fa-calendar-check me-2"></i> Analyser les logs d'aujourd'hui`;
    }
});

/**
 * Analyse les logs du formulaire actuel.
 */
async function runFormAnalysis() {
    const btn = document.getElementById('analyzeFormTodayBtn');
    const originalHtml = btn.innerHTML;
    
    // Récupération des données du formulaire EXCLUSIVEMENT
    const ip = document.getElementById('ip').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const path = document.getElementById('path').value;
    const limit = document.getElementById('limit').value;
    const targetDate = document.getElementById('formTargetDate').value;

    if (!ip || !username || !password) {
        return Swal.fire('Champs manquants', 'Veuillez remplir les informations de connexion dans le formulaire.', 'warning');
    }

    btn.disabled = true;
    const dateLabel = targetDate ? new Date(targetDate).toLocaleDateString('fr-FR') : "aujourd'hui";
    btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span> Extraction des logs du ${dateLabel}...`;

    try {
        const response = await fetch('/ssh-analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                ip, username, password, path, limit,
                target_date: targetDate || null,
                today_only: !targetDate
            })
        });

        const data = await response.json();

        if (data.status === 'success') {
            Swal.fire({
                icon: 'success',
                title: 'Analyse terminée',
                text: `Les logs du ${dateLabel} ont été analysés avec succès.`,
                timer: 3000,
                showConfirmButton: false
            }).then(() => {
                loadServerProfiles(); 
                window.location.href = '/dashboard';
            });
        } else if (data.code === 'NO_LOGS_FOUND') {
            Swal.fire({
                icon: 'info',
                title: 'Aucun log trouvé',
                text: data.message,
                confirmButtonColor: '#4158D0'
            });
        } else {
            throw new Error(data.message || 'Erreur lors de l\'analyse');
        }
    } catch (error) {
        Swal.fire('Erreur d\'analyse', error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalHtml;
    }
}

analyzeFormTodayBtn?.addEventListener('click', () => runFormAnalysis());

// --- ANCIENNE LOGIQUE GLOBALE (Scan de tous les serveurs enregistrés) ---
const chooseDateBtn = document.getElementById('chooseDateBtn');
const customDateContainer = document.getElementById('customDateContainer');
const analyzeAllTodayBtn = document.getElementById('analyzeAllTodayBtn');
const runCustomDateBtn = document.getElementById('runCustomDateAnalysis');

async function runGlobalAnalysis(date = null) {
    const btn = date ? runCustomDateBtn : analyzeAllTodayBtn;
    const originalHtml = btn.innerHTML;
    
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span> Scan en cours...`;

    try {
        const response = await fetch('/api/ssh/analyze-all-today', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target_date: date })
        });
        
        const data = await response.json();

        if (data.success) {
            Swal.fire({
                icon: 'success',
                title: 'Analyse terminée',
                text: data.message,
                footer: `<span class="text-info">Période: ${data.date_analyzed}</span>`,
                confirmButtonColor: '#0dcaf0'
            });
        } else {
            throw new Error(data.message);
        }
    } catch (error) {
        Swal.fire('Échec du Scan', error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalHtml;
    }
}

analyzeAllTodayBtn?.addEventListener('click', () => runGlobalAnalysis());

runCustomDateBtn?.addEventListener('click', () => {
    const dateVal = document.getElementById('targetDateInput').value;
    if (!dateVal) {
        return Swal.fire('Attention', 'Veuillez sélectionner une date.', 'warning');
    }
    runGlobalAnalysis(dateVal);
});

async function deleteProfile(profileId) {
    const result = await Swal.fire({
        title: 'Supprimer ce profil ?',
        text: "Cette action est irréversible.",
        icon: 'warning',
        showCancelButton: true,
        confirmButtonColor: '#dc3545',
        confirmButtonText: 'Supprimer',
        cancelButtonText: 'Annuler'
    });

    if (result.isConfirmed) {
        try {
            const response = await fetch(`/api/ssh/profiles/${profileId}`, { method: 'DELETE' });
            const data = await response.json();
            if (data.success) {
                loadServerProfiles();
            }
        } catch (error) {
            Swal.fire('Erreur', error.message, 'error');
        }
    }
}

// Charger les profils au démarrage
document.addEventListener('DOMContentLoaded', loadServerProfiles);

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