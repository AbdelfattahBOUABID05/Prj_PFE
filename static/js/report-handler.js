/**
 * Gestion de l'affichage du rapport d'analyse et intégration de l'IA.
 */
document.addEventListener('DOMContentLoaded', function() {
    // Récupération des données brutes stockées après l'analyse SSH ou Upload
    const rawData = localStorage.getItem('lastAnalysis');
    
    if (!rawData) {
        console.error("Aucune donnée trouvée");
        return;
    }

    // Conversion des données JSON en objet JavaScript
    const data = JSON.parse(rawData);

    if (!document.getElementById('auditSummaryBody')) return; // not on report page anymore

    const stats = data.stats || { errors: 0, warnings: 0, info: 0, total: 0 };
    const meta = data.meta || {};

    const targetIp = meta.server_ip || '--';
    const targetPath = meta.source_path || data.path || data.filename || '/var/log/messages';
    const ts = data.generated_at ? new Date(data.generated_at) : new Date();

    setText('auditTimestamp', ts.toLocaleString('fr-FR'));
    setText('auditTargetIp', targetIp);
    setText('auditTargetPath', targetPath);

    const health = computeHealthScore(stats);
    setGauge(health);

    setText('statCritical', String(stats.errors ?? 0));
    setText('statStability', computeStabilityLabel(stats));
    setText('statConfidence', String(computeConfidence(stats)));

    renderSummary(stats, meta, health);
    renderTraceSamples(data);

    const btn = document.getElementById('generateInsightsBtn');
    if (btn) {
        btn.addEventListener('click', async () => {
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Generating…';
            try {
                await generateCategorizedInsights(data);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fas fa-wand-magic-sparkles me-2"></i>Generate Audit Insights';
            }
        });
    }

    // Render placeholders
    setHtml('findingsImmediate', emptyFinding('Cliquez “Generate Audit Insights” pour générer des actions immédiates basées sur les logs critiques.'));
    setHtml('findingsLongterm', emptyFinding('Les recommandations long-terme seront classées ici (hardening, observability, patching).'));
    setHtml('findingsObservations', emptyFinding('Observations non-critiques (signals, patterns, anomalies) seront listées ici.'));
});

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value ?? '--';
}

function setHtml(id, html) {
    const el = document.getElementById(id);
    if (el) el.innerHTML = html;
}

function computeHealthScore(stats) {
    const errors = Number(stats.errors || 0);
    const info = Number(stats.info || 0);
    const warnings = Number(stats.warnings || 0);
    const denom = Math.max(1, info + errors + warnings);
    const ratio = info / denom; // "healthy" proportion
    const score = Math.round(ratio * 100);
    return Math.max(0, Math.min(100, score));
}

function computeStabilityLabel(stats) {
    const errors = Number(stats.errors || 0);
    const total = Number(stats.total || 0);
    if (total <= 0) return 'N/A';
    const errRate = errors / Math.max(1, total);
    if (errRate >= 0.20) return 'Unstable';
    if (errRate >= 0.08) return 'Degraded';
    return 'Stable';
}

function computeConfidence(stats) {
    const total = Number(stats.total || 0);
    const errors = Number(stats.errors || 0);
    const base = total >= 200 ? 92 : total >= 80 ? 88 : total >= 20 ? 82 : 72;
    const penalty = Math.min(18, Math.round((errors / Math.max(1, total)) * 100));
    return Math.max(60, Math.min(95, base - penalty));
}

function setGauge(score) {
    const gauge = document.getElementById('healthGauge');
    const val = document.getElementById('healthScoreValue');
    const sub = document.getElementById('healthScoreSub');
    if (gauge) gauge.style.setProperty('--p', String(score));
    if (val) val.textContent = String(score);
    if (sub) sub.textContent = score >= 85 ? 'Healthy' : score >= 65 ? 'Watch' : 'Critical';
}

function renderSummary(stats, meta, health) {
    const body = document.getElementById('auditSummaryBody');
    if (!body) return;

    const fileSize = meta.file_size_bytes != null ? formatBytes(meta.file_size_bytes) : '--';
    const lm = meta.last_modified_utc ? new Date(meta.last_modified_utc).toLocaleString('fr-FR') : '--';
    const sourceType = meta.source_type || '--';

    const rows = [
        ['Global Health Score', `${health}%`, 'Ratio Info vs (Errors+Warnings+Info)'],
        ['Critical Issues (Errors)', String(stats.errors ?? 0), 'Priorité haute: investigation immédiate'],
        ['Warnings', String(stats.warnings ?? 0), 'Risque moyen: hardening & tuning'],
        ['Info', String(stats.info ?? 0), 'Volume normal / bruit'],
        ['Total Lines (Analyzed)', String(stats.total ?? 0), 'Total des lignes analysées'],
        ['Source Type', sourceType, 'ssh ou upload'],
        ['File Size', fileSize, 'Taille du fichier côté serveur (si disponible)'],
        ['Last Modified', lm, 'Timestamp serveur (UTC)']
    ];

    body.innerHTML = rows.map(r => `
        <tr>
            <td style="font-weight:900;">${escapeHtml(r[0])}</td>
            <td>${escapeHtml(r[1])}</td>
            <td class="text-muted">${escapeHtml(r[2])}</td>
                </tr>
    `).join('');
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

    // Attach copy handlers for terminal blocks
    document.querySelectorAll('[data-copy-terminal]').forEach(btn => {
        btn.addEventListener('click', async () => {
            const target = btn.getAttribute('data-copy-terminal');
            const pre = document.getElementById(target);
            if (!pre) return;
            await copyToClipboard(pre.textContent || '');
            btn.textContent = 'Copied';
            setTimeout(() => btn.textContent = 'Copy', 900);
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
    return payload.analysis || payload.message || payload.error || 'No analysis.';
}

function categorize(text, sev) {
    const t = String(text || '').toLowerCase();
    if (sev === 'ERROR') return 'immediate';
    if (t.includes('immediate') || t.includes('urgent') || t.includes('critical') || t.includes('immédiat') || t.includes('urgence')) return 'immediate';
    if (t.includes('recommend') || t.includes('hardening') || t.includes('should') || t.includes('recommand') || t.includes('à long terme')) return 'longterm';
    return 'observation';
}

function buildTitle(sev, analysis) {
    if (sev === 'ERROR') return 'Critical finding';
    if (sev === 'WARNING') return 'Risk observation';
    if (String(analysis || '').toLowerCase().includes('security')) return 'Security observation';
    return 'Observation';
}

function renderFinding({ title, analysis, commands, trace }) {
    const cmdBlocks = commands.map((cmd, idx) => {
        const id = `term_${Math.random().toString(16).slice(2)}_${idx}`;
        return `
            <div class="audit-terminal">
                <div class="audit-terminal-header">
                    <span>Suggested Fix</span>
                    <button class="btn btn-outline-saas btn-sm no-print" type="button" data-copy-terminal="${id}">Copy</button>
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
                <div style="font-weight:900; margin-bottom:6px;">Traceability</div>
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
 * Génère un fichier PDF à partir du contenu HTML du rapport.
 */
function downloadPDF() {
    const element = document.getElementById('reportContent');
    const opt = {
        margin: [10, 10],
        filename: 'Rapport_Final_LogAnalyzer.pdf',
        image: { type: 'jpeg', quality: 0.98 },
        html2canvas: { scale: 2, useCORS: true },
        jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
        pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
    };
    const rawData = localStorage.getItem('lastAnalysis');
    const analysisId = rawData ? (JSON.parse(rawData).analysis_id || null) : null;

    // Utilisation de la bibliothèque html2pdf pour la conversion + upload server-side
    const worker = html2pdf().set(opt).from(element);

    worker.outputPdf('blob').then(async (blob) => {
        if (analysisId) {
            try {
                const fd = new FormData();
                fd.append('pdf', blob, opt.filename);
                await fetch(`/api/analyses/${analysisId}/report-pdf`, { method: 'POST', body: fd });
            } catch (e) {
                console.error('PDF upload failed', e);
            }
        }
        // Still download locally
        await worker.save();
    });
}