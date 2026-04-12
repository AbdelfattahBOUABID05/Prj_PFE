/**
 * Gestion de l'affichage du rapport d'analyse et intégration de l'IA.
 */
document.addEventListener('DOMContentLoaded', function() {
    if (!document.getElementById('reportContent')) return; // Pas sur la page rapport
    initReportPage();
});

async function initReportPage() {
    // Priorité à l'analyse injectée par le serveur (Session Flask)
    // Sinon, repli sur le localStorage
    const localData = window.SERVER_ANALYSIS_DATA || JSON.parse(localStorage.getItem('lastAnalysis') || 'null');

    if (localData) {
        renderFromLocalAnalysis(localData);
    } else {
        setHtml('findingsImmediate', emptyFinding('Aucune donnée disponible.'));
        setHtml('findingsLongterm', emptyFinding('Veuillez lancer une analyse.'));
    }

    // Le chargement des rapports persistés peut être optionnel ou adapté
    const serverReport = await fetchLatestReport();
    if (serverReport && !localData) {
        renderPersistedReport(serverReport);
    }

    const btn = document.getElementById('generateInsightsBtn');
    if (btn) {
        btn.addEventListener('click', async () => {
            if (!localData) {
                Swal.fire({
                    icon: 'warning',
                    title: 'Données manquantes',
                    text: 'Aucune analyse locale disponible pour générer les aperçus.',
                    customClass: {
                        popup: 'swal-custom-popup',
                        title: 'swal-custom-title',
                        confirmButton: 'swal-custom-confirm'
                    },
                    buttonsStyling: false
                });
                return;
            }
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Génération…';
            try {
                await generateCategorizedInsights(localData);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-wand-magic-sparkles me-2"></i>Générer les aperçus d\'audit';
            }
        });
    }
}

function renderFromLocalAnalysis(data) {
    const stats = data.stats || { errors: 0, warnings: 0, info: 0, total: 0 };
    const meta = data.meta || {};

    const targetIp = meta.server_ip || '--';
    const targetPath = meta.source_path || data.path || data.filename || '/var/log/messages';
    const ts = data.generated_at ? new Date(data.generated_at) : new Date();

    setText('auditTimestamp', ts.toLocaleString('fr-FR'));
    setText('auditTargetIp', targetIp);
    setText('auditTargetPath', targetPath);

    // Mise à jour des compteurs (Tableau récapitulatif simple)
    setText('statTotalLines', String(stats.total ?? 0));
    setText('statCritical', String(stats.errors ?? 0));
    setText('statWarnings', String(stats.warnings ?? 0));
    setText('statInfo', String(stats.info ?? 0));

    // Analyse de récurrence et Top 20 erreurs
    renderRecurrenceAnalysis(data);
    renderTopErrors(data);
    
    // Rendu des traces et résumés IA si disponibles
    renderTraceSamples(data);
}

/**
 * Calcule et affiche les patterns de logs les plus fréquents.
 */
function renderRecurrenceAnalysis(data) {
    const body = document.getElementById('recurrenceTableBody');
    if (!body) return;

    body.innerHTML = ''; // Vider avant d'ajouter
    
    const segments = data.segments || {};
    const allLines = [
        ...(segments.ERROR || []),
        ...(segments.WARNING || []),
        ...(segments.INFO || [])
    ];

    if (!allLines.length) {
        body.innerHTML = '<tr><td colspan="2" class="text-center text-muted">Aucune donnée disponible.</td></tr>';
        return;
    }

    // Compter les occurrences de chaque message (en ignorant les timestamps au début)
    const counts = {};
    allLines.forEach(line => {
        // Nettoyage basique du timestamp pour regrouper les messages identiques
        const cleaned = line.replace(/^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+\s+/, '').trim();
        counts[cleaned] = (counts[cleaned] || 0) + 1;
    });

    // Trier par nombre d'occurrences décroissant
    const sorted = Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);

    body.innerHTML = sorted.map(([msg, count]) => `
        <tr>
            <td style="word-break: break-all; font-family: monospace; font-size: 0.8rem;">${escapeHtml(msg)}</td>
            <td style="text-align: center; font-weight: bold;">${count}</td>
        </tr>
    `).join('');
}

/**
 * Affiche les 20 premières erreurs avec leur horodatage.
 */
function renderTopErrors(data) {
    const body = document.getElementById('topErrorsTableBody');
    if (!body) return;

    body.innerHTML = ''; // Vider avant d'ajouter

    const errors = (data.segments?.ERROR || []).slice(0, 20);

    if (!errors.length) {
        body.innerHTML = '<tr><td colspan="2" class="text-center text-muted">Aucune erreur détectée.</td></tr>';
        return;
    }

    body.innerHTML = errors.map(err => {
        const tsMatch = err.match(/^[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+/);
        const timestamp = tsMatch ? tsMatch[0] : '--';
        const message = tsMatch ? err.replace(tsMatch[0], '').trim() : err;

        return `
            <tr>
                <td class="text-muted" style="font-family: monospace;">${escapeHtml(timestamp)}</td>
                <td style="font-weight: 500;">${escapeHtml(message)}</td>
            </tr>
        `;
    }).join('');
}

async function fetchLatestReport() {
    try {
        const res = await fetch('/api/reports/latest');
        const payload = await res.json();
        if (!res.ok || payload?.status !== 'success' || !payload?.report) return null;
        return payload.report;
    } catch (e) {
        return null;
    }
}

function renderPersistedReport(report) {
    const stats = report?.stats || { errors: 0, warnings: 0, info: 0, total: 0 };
    
    if (report?.generated_at) {
        setText('auditTimestamp', new Date(report.generated_at).toLocaleString('fr-FR'));
    }

    setText('statTotalLines', String(stats.total ?? 0));
    setText('statCritical', String(stats.errors ?? 0));
    setText('statWarnings', String(stats.warnings ?? 0));
    setText('statInfo', String(stats.info ?? 0));

    // Si on a des données de segments, on peut relancer l'analyse de récurrence
    if (report.segments) {
        renderRecurrenceAnalysis(report);
        renderTopErrors(report);
    }
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value ?? '--';
}

function setHtml(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
}

function renderTraceSamples(data) {
    const container = document.getElementById('traceSamples');
    if (!container) return;

    const segments = data.segments || {};
    const sample = [
        ...(segments.ERROR || []).slice(0, 2).map(t => ({ sev: 'ERROR', text: t })),
        ...(segments.WARNING || []).slice(0, 2).map(t => ({ sev: 'WARNING', text: t })),
        ...(segments.INFO || []).slice(0, 2).map(t => ({ sev: 'INFO', text: t })),
    ].slice(0, 6);

    if (!sample.length) {
        container.innerHTML = `<div class="text-muted small">Aucun échantillon disponible.</div>`;
        return;
    }

    container.innerHTML = sample.map(s => `
        <div class="audit-trace-item">
            <div style="font-weight:900; margin-bottom:6px;">${escapeHtml(s.sev)}</div>
            <div>${escapeHtml(trimLine(s.text))}</div>
        </div>
    `).join('');
}

async function generateCategorizedInsights(data) {
    const segments = data.segments || {};
    const candidates = [
        ...(segments.ERROR || []).slice(0, 3).map(t => ({ sev: 'ERROR', text: t })),
        ...(segments.WARNING || []).slice(0, 2).map(t => ({ sev: 'WARNING', text: t })),
        ...(segments.INFO || []).slice(0, 1).map(t => ({ sev: 'INFO', text: t })),
    ].slice(0, 5);

    if (!candidates.length) {
        setHtml('findingsImmediate', emptyFinding('Aucun log à analyser.'));
        setHtml('findingsLongterm', '');
        setHtml('findingsObservations', '');
        return;
    }

    const immediate = [];
    const longterm = [];
    const obs = [];

    for (const item of candidates) {
        const analysis = await aiAnalyze(item.text);
        const commands = extractCommands(analysis);
        const category = categorize(analysis, item.sev);
        const findingHtml = renderFinding({
            title: buildTitle(item.sev, analysis),
            analysis,
            commands,
            trace: item.text
        });

        if (category === 'immediate') immediate.push(findingHtml);
        else if (category === 'longterm') longterm.push(findingHtml);
        else obs.push(findingHtml);
    }

    setHtml('findingsImmediate', immediate.join('') || emptyFinding('Aucune action immédiate détectée.'));
    setHtml('findingsLongterm', longterm.join('') || emptyFinding('Aucune recommandation long-terme détectée.'));
    setHtml('findingsObservations', obs.join('') || emptyFinding('Aucune observation additionnelle.'));

    // Attache les gestionnaires de copie pour les blocs de terminal.
    document.querySelectorAll('[data-copy-terminal]').forEach(btn => {
        btn.addEventListener('click', async () => {
            const target = btn.getAttribute('data-copy-terminal');
            const pre = document.getElementById(target);
            if (!pre) return;
            await copyToClipboard(pre.textContent || '');
            btn.textContent = 'Copié';
            setTimeout(() => btn.textContent = 'Copier', 900);
        });
    });
}

async function aiAnalyze(line) {
    const res = await fetch('/ai-analyze-line', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ line })
    });
    const payload = await res.json();
    return payload.analysis || payload.message || payload.error || 'Aucune analyse.';
}

function categorize(text, sev) {
    const t = String(text || '').toLowerCase();
    if (sev === 'ERROR') return 'immediate';
    if (t.includes('immediate') || t.includes('urgent') || t.includes('critical') || t.includes('immédiat') || t.includes('urgence')) return 'immediate';
    if (t.includes('recommend') || t.includes('hardening') || t.includes('should') || t.includes('recommand') || t.includes('à long terme')) return 'longterm';
    return 'observation';
}

function buildTitle(sev, analysis) {
    if (sev === 'ERROR') return 'Constat critique';
    if (sev === 'WARNING') return 'Observation de risque';
    if (String(analysis || '').toLowerCase().includes('security')) return 'Observation de sécurité';
    return 'Observation';
}

function renderFinding({ title, analysis, commands, trace }) {
    const cmdBlocks = commands.map((cmd, idx) => {
        const id = `term_${Math.random().toString(16).slice(2)}_${idx}`;
        return `
            <div class="audit-terminal">
                <div class="audit-terminal-header">
                    <span>Correction suggérée</span>
                    <button class="btn btn-outline-saas btn-sm no-print" type="button" data-copy-terminal="${id}">Copier</button>
                </div>
                <pre id="${id}">${escapeHtml(cmd)}</pre>
            </div>
        `;
    }).join('');

    return `
        <div class="audit-finding">
            <div class="audit-finding-title">${escapeHtml(title)}</div>
            <div class="text-muted small" style="white-space: pre-wrap; line-height: 1.45;">${escapeHtml(analysis)}</div>
            ${cmdBlocks}
            <div class="audit-finding-trace mt-3">
                <div style="font-weight:900; margin-bottom:6px;">Traçabilité</div>
                ${escapeHtml(trimLine(trace))}
            </div>
        </div>
    `;
}

function emptyFinding(text) {
    return `<div class="text-muted small">${escapeHtml(text)}</div>`;
}

function extractCommands(text) {
    const candidates = [];
    const fenced = String(text || '').match(/```([\s\S]*?)```/g);
    if (fenced) {
        fenced.forEach(block => {
            const inner = block.replace(/```/g, '').trim();
            inner.split('\n').map(l => l.trim()).filter(Boolean).forEach(l => candidates.push(l.replace(/^\$\s*/, '')));
        });
    }
    const lines = String(text || '').split('\n').map(l => l.trim()).filter(Boolean);
    const keywords = ['systemctl', 'journalctl', 'dnf', 'yum', 'apt', 'grep', 'tail', 'sshd', 'firewall-cmd', 'chmod', 'chown'];
    lines.forEach(l => {
        const raw = l.replace(/^\$\s*/, '');
        if (raw.length < 8 || raw.length > 200) return;
        if (keywords.some(k => raw.includes(k))) candidates.push(raw);
    });
    return Array.from(new Set(candidates)).slice(0, 3);
}

function trimLine(s) {
    const str = String(s || '').replace(/\s+/g, ' ').trim();
    return str.length > 220 ? `${str.slice(0, 220)}…` : str;
}

function escapeHtml(str) {
    return String(str)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}

function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
    const val = bytes / (1024 ** i);
    return `${val.toFixed(val >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(String(text || ''));
    } catch (e) {
        const ta = document.createElement('textarea');
        ta.value = String(text || '');
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    }
}

/**
 * Envoie une ligne de log spécifique au serveur Flask pour analyse par Gemini AI.
 * @param {string} line - La ligne de texte du log à analyser.
 */
async function analyzeWithAI(line) {
    const responseDiv = document.getElementById('aiResponse');
    const loadingDiv = document.getElementById('aiLoading');
    const modalElement = document.getElementById('aiModal');
    const modal = new bootstrap.Modal(modalElement); // Initialisation du Modal Bootstrap
    
    // Préparation de l'interface du Modal (Affichage du spinner de chargement)
    responseDiv.innerText = '';
    loadingDiv.classList.remove('d-none');
    modal.show();

    try {
        // Appel asynchrone vers la route API de l'IA
        const response = await fetch('/ai-analyze-line', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ line: line })
        });
        const data = await response.json();
        // Affichage du résultat de l'IA ou de l'erreur retournée par le serveur
        responseDiv.innerText = data.analysis || data.error || "Erreur d'analyse.";
    } catch (err) {
        responseDiv.innerText = "Impossible de contacter le serveur AI.";
    } finally {
        // Masquage du spinner une fois la réponse reçue
        loadingDiv.classList.add('d-none');
    }
}

/**
 * Génère un fichier PDF à partir du serveur (FPDF).
 */
function downloadPDF() {
    // Tente de récupérer l'ID depuis les données injectées par le serveur ou le localStorage
    const analysisId = window.SERVER_ANALYSIS_DATA?.analysis_id || 
                       JSON.parse(localStorage.getItem('lastAnalysis') || '{}').analysis_id;

    if (!analysisId) {
        Swal.fire({
            icon: 'warning',
            title: 'Aucune analyse active',
            text: "Aucune analyse n'a été trouvée pour l'exportation.",
            customClass: {
                popup: 'swal-custom-popup',
                title: 'swal-custom-title',
                confirmButton: 'swal-custom-confirm'
            },
            buttonsStyling: false
        });
        return;
    }

    // Rediriger vers la route de téléchargement serveur
    window.location.href = `/download-pdf/${analysisId}`;
}

/**
 * Envoie le rapport PDF par email via l'API avec SweetAlert2 (Thème Sombre SOC).
 */
async function sendReportByEmail() {
    const analysisId = window.SERVER_ANALYSIS_DATA?.analysis_id || 
                       JSON.parse(localStorage.getItem('lastAnalysis') || '{}').analysis_id;

    if (!analysisId) {
        Swal.fire({
            icon: 'warning',
            title: 'Analyse introuvable',
            text: "Aucune analyse n'a été trouvée pour l'envoi.",
            customClass: {
                popup: 'swal-custom-popup',
                title: 'swal-custom-title',
                confirmButton: 'swal-custom-confirm'
            }
        });
        return;
    }

    const { value: recipient, isConfirmed } = await Swal.fire({
        title: 'Envoyer le Rapport Audit',
        input: 'email',
        inputLabel: 'Adresse email de destination',
        inputPlaceholder: "Par défaut : votre adresse de profil",
        showCancelButton: true,
        confirmButtonText: '<i class="fas fa-paper-plane me-2"></i> Envoyer',
        cancelButtonText: 'Annuler',
        customClass: {
            popup: 'swal-custom-popup',
            title: 'swal-custom-title',
            input: 'swal-custom-input',
            confirmButton: 'swal-custom-confirm',
            cancelButton: 'swal-custom-cancel'
        },
        buttonsStyling: false
    });

    if (!isConfirmed) return;

    // Mise à jour de l'état du bouton (Loading)
    const btn = document.getElementById('sendEmailBtn');
    const originalHtml = btn ? btn.innerHTML : '';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Envoi en cours...';
    }

    // Feedback Progressif : Afficher le loader SweetAlert2
    Swal.fire({
        title: 'Transmission en cours...',
        html: '<div class="text-muted mb-3">Génération du PDF et envoi via SMTP sécurisé...</div>',
        allowOutsideClick: false,
        showConfirmButton: false,
        customClass: {
            popup: 'swal-custom-popup',
            title: 'swal-custom-title'
        },
        didOpen: () => {
            Swal.showLoading();
        }
    });

    try {
        const response = await fetch('/api/send-report-email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ analysis_id: analysisId, recipient: recipient || null })
        });

        const result = await response.json();
        if (result.success) {
            Swal.fire({
                icon: 'success',
                title: 'Rapport Envoyé',
                text: result.message || "L'e-mail a été expédié avec succès.",
                customClass: {
                    popup: 'swal-custom-popup',
                    title: 'swal-custom-title',
                    confirmButton: 'swal-custom-confirm'
                },
                buttonsStyling: false
            });
        } else {
            throw new Error(result.message || "Erreur lors de l'envoi.");
        }
    } catch (error) {
        console.error("Email API Error:", error);
        Swal.fire({
            icon: 'error',
            title: 'Échec de l\'envoi',
            text: error.message || "Une erreur est survenue lors de la communication avec le serveur mail.",
            customClass: {
                popup: 'swal-custom-popup',
                title: 'swal-custom-title',
                confirmButton: 'swal-custom-confirm'
            },
            buttonsStyling: false
        });
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
        }
    }
}