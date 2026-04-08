// Keep chart instances so we can re-render safely
let severityChart = null;
let activityChart = null;

const COLORS = {
    deepRed: '#B42318',
    amber: '#F79009',
    softBlue: '#2E90FA',
    grid: 'rgba(15, 23, 42, 0.08)',
    text: 'rgba(26, 26, 26, 0.85)'
};

// Attendre le chargement complet du DOM avant d'exécuter le script
document.addEventListener('DOMContentLoaded', function() {
    // Récupération des dernières données d'analyse stockées dans le navigateur
    const savedData = localStorage.getItem('lastAnalysis');
    
    if (savedData) {
        const data = JSON.parse(savedData);
        console.log("Chargement des données SSH...", data);
        // Mise à jour de l'interface utilisateur avec les données récupérées
        updateDashboard(data);
        initDetailsMonitoringView(data);
    }
});

/**
 * Fonction pour actualiser les éléments du tableau de bord (Dashboard)
 * @param {Object} data - Les données de l'analyse des logs
 */
function updateDashboard(data) {
    // Mise à jour du compteur d'erreurs dans l'interface
    const errElem = document.getElementById('errCount');
    if (errElem) errElem.innerText = data.stats.errors;

    renderSeverityChart(data);
    renderActivityChart(data);
    hideSkeleton('severitySkeleton');
    hideSkeleton('activitySkeleton');

    // Mise à jour de la section de notification et ajout du bouton de rapport
    const aiResult = document.getElementById('aiResult');
    if (aiResult) {
        aiResult.innerHTML = `
            <div class="glass-card p-3 text-start">
                <div class="d-flex align-items-start gap-2">
                    <div class="mt-1" style="color:${COLORS.softBlue};"><i class="fas fa-check-circle"></i></div>
                    <div>
                        <div style="font-weight:700; color:${COLORS.text};">Données SSH chargées</div>
                        <div class="small text-muted">Dernière analyse: ${new Date().toLocaleTimeString()}</div>
                    </div>
                </div>
            </div>
            <button class="btn btn-outline-saas btn-sm mt-3">
                <i class="fas fa-magic me-2"></i>Générer un rapport IA
            </button>
        `;
    }
}

function hideSkeleton(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
}

function baseChartOptions() {
    return {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                display: true,
                position: 'bottom',
                labels: {
                    usePointStyle: true,
                    padding: 18,
                    color: COLORS.text,
                    font: { size: 12, family: 'Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif', weight: '600' }
                }
            },
            tooltip: {
                backgroundColor: 'rgba(17, 24, 39, 0.92)',
                titleColor: '#fff',
                bodyColor: '#fff',
                borderColor: 'rgba(255,255,255,0.12)',
                borderWidth: 1
            }
        }
    };
}

function renderSeverityChart(data) {
    const canvas = document.getElementById('logChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (severityChart) severityChart.destroy();

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Errors', 'Warnings', 'Info'],
            datasets: [{
                data: [data.stats.errors, data.stats.warnings, data.stats.info],
                backgroundColor: [
                    COLORS.deepRed,
                    COLORS.amber,
                    COLORS.softBlue
                ],
                hoverOffset: 10,
                borderWidth: 0,
                cutout: '85%', // Taille du trou central
                borderRadius: 10, // Arrondi des segments
                spacing: 5 // Espace entre les segments
            }]
        },
        options: {
            ...baseChartOptions()
        }
    });
}

function renderActivityChart(data) {
    const canvas = document.getElementById('activityChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (activityChart) activityChart.destroy();

    const points = buildActivitySeries(data);
    const labels = points.map(p => p.label);
    const values = points.map(p => p.count);

    const gradient = ctx.createLinearGradient(0, 0, 0, canvas.height || 240);
    gradient.addColorStop(0, 'rgba(46, 144, 250, 0.35)');
    gradient.addColorStop(1, 'rgba(46, 144, 250, 0.02)');

    activityChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Logs',
                data: values,
                borderColor: COLORS.softBlue,
                backgroundColor: gradient,
                fill: true,
                tension: 0.35,
                pointRadius: 2,
                pointHoverRadius: 5,
                pointBackgroundColor: '#ffffff',
                pointBorderColor: COLORS.softBlue,
                borderWidth: 2
            }]
        },
        options: {
            ...baseChartOptions(),
            scales: {
                x: {
                    grid: { color: 'transparent' },
                    ticks: { color: COLORS.text, maxRotation: 0, autoSkip: true, maxTicksLimit: 7 }
                },
                y: {
                    grid: { color: COLORS.grid },
                    ticks: { color: COLORS.text, precision: 0 },
                    beginAtZero: true
                }
            },
            animation: {
                duration: 650,
                easing: 'easeOutQuart'
            }
        }
    });
}

function buildActivitySeries(data) {
    // Build a simple time series by parsing timestamps from log lines.
    // Fallback: if no timestamps, show a 10-bucket distribution across the loaded lines.
    const allLines = [];
    const segments = data?.segments || {};
    for (const key of Object.keys(segments)) {
        const lines = segments[key] || [];
        for (const line of lines) allLines.push(line);
    }

    const parsed = allLines
        .map(line => ({ line, date: parseSyslogDate(line) }))
        .filter(x => x.date instanceof Date && !Number.isNaN(x.date.getTime()))
        .sort((a, b) => a.date - b.date);

    if (parsed.length < 3) {
        const buckets = 10;
        const step = Math.max(1, Math.ceil(allLines.length / buckets));
        const result = [];
        for (let i = 0; i < buckets; i++) {
            const start = i * step;
            const end = Math.min(allLines.length, (i + 1) * step);
            result.push({ label: `#${start + 1}-${end}`, count: Math.max(0, end - start) });
        }
        return result;
    }

    // Bucket per minute
    const map = new Map();
    for (const item of parsed) {
        const d = item.date;
        const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
        map.set(key, (map.get(key) || 0) + 1);
    }

    const keys = Array.from(map.keys()).sort();
    const condensed = keys.slice(Math.max(0, keys.length - 20)); // keep last N buckets for readability
    return condensed.map(k => ({ label: k.split(' ')[1], count: map.get(k) }));
}

function parseSyslogDate(line) {
    // ISO-8601: "2026-04-08T14:56:03" (optionally with ms/timezone)
    const iso = String(line || '').match(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})?)/);
    if (iso) {
        const d = new Date(iso[1]);
        if (!Number.isNaN(d.getTime())) return d;
    }

    // Common syslog: "Mar 10 12:34:56 host ..."
    const m = line.match(/^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/);
    if (!m) return null;

    const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    const month = monthNames.indexOf(m[1]);
    if (month < 0) return null;

    const now = new Date();
    const year = now.getFullYear();
    const day = Number(m[2]);
    const hh = Number(m[3]);
    const mm = Number(m[4]);
    const ss = Number(m[5]);

    // Assume local timezone; good enough for visualization
    return new Date(year, month, day, hh, mm, ss);
}

// ----------------------------
// Monitoring view (Details page)
// ----------------------------

function initDetailsMonitoringView(data) {
    const grid = document.getElementById('logGrid');
    if (!grid) return; // not on details page

    const normalized = normalizeAnalysis(data);
    renderMetadata(normalized);
    renderTimeline(normalized);
    renderGrid(normalized, { severity: 'ALL', q: '' });

    const search = document.getElementById('logSearch');
    const chips = Array.from(document.querySelectorAll('.severity-chip'));
    let state = { severity: 'ALL', q: '' };

    chips.forEach(btn => {
        btn.addEventListener('click', () => {
            chips.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            state = { ...state, severity: btn.dataset.sev || 'ALL' };
            renderGrid(normalized, state);
        });
    });

    if (search) {
        search.addEventListener('input', () => {
            state = { ...state, q: (search.value || '').trim() };
            renderGrid(normalized, state);
        });
    }
}

function normalizeAnalysis(data) {
    const segments = data?.segments || {};
    const file = data?.path || data?.filename || data?.file || '--';
    const capturedAt = data?.generated_at || null;

    const rows = [];
    const push = (sev, line) => {
        const ts = extractTimestampToken(line);
        rows.push({
            id: `${sev}-${rows.length}`,
            severity: sev,
            line: String(line ?? ''),
            timestamp: ts?.display || '',
            timestampDate: ts?.date || null
        });
    };

    (segments.ERROR || []).forEach(l => push('ERROR', l));
    (segments.WARNING || []).forEach(l => push('WARNING', l));
    (segments.INFO || []).forEach(l => push('INFO', l));

    // Stable sort by timestamp if present, else keep severity order
    const withDates = rows.filter(r => r.timestampDate);
    if (withDates.length >= 3) {
        rows.sort((a, b) => {
            const ad = a.timestampDate ? a.timestampDate.getTime() : Number.POSITIVE_INFINITY;
            const bd = b.timestampDate ? b.timestampDate.getTime() : Number.POSITIVE_INFINITY;
            return ad - bd;
        });
    }

    return {
        file,
        capturedAt,
        stats: data?.stats || { errors: 0, warnings: 0, info: 0, total: rows.length },
        rows,
        payloadBytes: safeByteLength(JSON.stringify(data || {}))
    };
}

function renderMetadata(model) {
    const sourceBadge = document.getElementById('sourceBadge');
    const metaFile = document.getElementById('metaFile');
    const metaSize = document.getElementById('metaSize');
    const metaModified = document.getElementById('metaModified');
    const metaLines = document.getElementById('metaLines');

    if (sourceBadge) sourceBadge.textContent = `Source: ${model.file}`;
    if (metaFile) metaFile.textContent = model.file;
    if (metaSize) metaSize.textContent = model.payloadBytes ? `${formatBytes(model.payloadBytes)} (payload)` : '--';
    if (metaModified) metaModified.textContent = model.capturedAt ? new Date(model.capturedAt).toLocaleString() : '--';
    if (metaLines) metaLines.textContent = String(model.rows.length || 0);

    const cE = document.getElementById('count-ERROR');
    const cW = document.getElementById('count-WARNING');
    const cI = document.getElementById('count-INFO');
    if (cE) cE.textContent = String((model.stats?.errors ?? 0));
    if (cW) cW.textContent = String((model.stats?.warnings ?? 0));
    if (cI) cI.textContent = String((model.stats?.info ?? 0));
}

function renderTimeline(model) {
    const container = document.getElementById('timeline');
    if (!container) return;

    const items = model.rows
        .filter(r => r.timestampDate)
        .slice(0, 12);

    if (items.length === 0) {
        container.innerHTML = `<div class="text-muted small">Aucun timestamp détecté dans ces lignes.</div>`;
        return;
    }

    container.innerHTML = items.map((r) => {
        const sevClass = r.severity === 'ERROR' ? 'dot-error' : (r.severity === 'WARNING' ? 'dot-warning' : 'dot-info');
        return `
            <div class="step">
                <div class="dot ${sevClass}"></div>
                <div class="step-content">
                    <div class="step-title">${escapeHtml(r.timestamp || '--')} <span class="step-badge ${sevClass}">${r.severity}</span></div>
                    <div class="step-desc">${escapeHtml(trimMessage(r.line))}</div>
                </div>
            </div>
        `;
    }).join('');
}

function renderGrid(model, state) {
    const grid = document.getElementById('logGrid');
    const count = document.getElementById('gridCount');
    if (!grid) return;

    const q = (state?.q || '').toLowerCase();
    const sev = state?.severity || 'ALL';

    const filtered = model.rows.filter(r => {
        if (sev !== 'ALL' && r.severity !== sev) return false;
        if (!q) return true;
        return r.line.toLowerCase().includes(q) || r.severity.toLowerCase().includes(q) || (r.timestamp || '').toLowerCase().includes(q);
    });

    if (count) count.textContent = `${filtered.length} lignes`;

    if (filtered.length === 0) {
        grid.innerHTML = `<div class="log-empty">Aucune ligne ne correspond au filtre.</div>`;
        return;
    }

    grid.innerHTML = filtered.map((r, idx) => {
        const sevClass = r.severity === 'ERROR' ? 'sev-error' : (r.severity === 'WARNING' ? 'sev-warning' : 'sev-info');
        const delay = Math.min(420, idx * 14);
        const ts = r.timestamp ? `<span class="log-ts">${escapeHtml(r.timestamp)}</span>` : `<span class="log-ts">--</span>`;
        return `
            <div class="log-row ${sevClass}" data-id="${r.id}" style="animation-delay:${delay}ms;">
                <button class="exp-btn" type="button" aria-label="Expand" data-action="expand">
                    <i class="fas fa-plus"></i>
                </button>
                <div class="log-sev">${r.severity}</div>
                <div class="log-time d-none d-md-block">${ts}</div>
                <div class="log-msg">${renderHighlightedMessage(r.line)}</div>
                <div class="log-expanded d-none">
                    <div class="expanded-actions">
                        <button class="btn btn-outline-saas btn-sm" data-action="copy">
                            <i class="fas fa-copy me-2"></i>Copy line
                        </button>
                        <button class="btn btn-saas btn-sm" data-action="ai">
                            <i class="fas fa-robot me-2"></i>AI Analyze
                        </button>
                    </div>
                    <pre class="expanded-pre">${escapeHtml(r.line)}</pre>
                </div>
            </div>
        `;
    }).join('');

    // Event delegation
    grid.onclick = async (e) => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;
        const rowEl = e.target.closest('.log-row');
        if (!rowEl) return;
        const id = rowEl.getAttribute('data-id');
        const row = model.rows.find(x => x.id === id);
        if (!row) return;

        const action = btn.getAttribute('data-action');
        if (action === 'expand') {
            toggleExpand(rowEl, btn);
            return;
        }
        if (action === 'copy') {
            await copyToClipboard(row.line);
            return;
        }
        if (action === 'ai') {
            await runAiInsight(row.line);
            return;
        }
    };
};

function toggleExpand(rowEl, btn) {
    const expanded = rowEl.querySelector('.log-expanded');
    if (!expanded) return;
    const isOpen = !expanded.classList.contains('d-none');
    expanded.classList.toggle('d-none', isOpen);
    const icon = btn.querySelector('i');
    if (icon) icon.className = isOpen ? 'fas fa-plus' : 'fas fa-minus';
}

async function runAiInsight(line) {
    const empty = document.getElementById('insightEmpty');
    const card = document.getElementById('insightCard');
    const text = document.getElementById('insightText');
    const actions = document.getElementById('insightActions');

    if (empty) empty.classList.add('d-none');
    if (card) card.classList.remove('d-none');
    if (text) text.textContent = 'Analyse en cours…';
    if (actions) actions.innerHTML = '';

    try {
        const res = await fetch('/ai-analyze-line', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ line })
        });
        const payload = await res.json();
        const analysis = payload?.analysis || payload?.message || 'Aucune réponse.';
        if (text) text.textContent = analysis;

        const commands = extractCommands(analysis);
        if (actions && commands.length) {
            actions.innerHTML = commands.map((cmd, idx) => `
                <button class="btn btn-outline-saas btn-sm" data-cmd-idx="${idx}">
                    <i class="fas fa-terminal me-2"></i>Copy command
                </button>
            `).join('');
            actions.onclick = async (e) => {
                const b = e.target.closest('button[data-cmd-idx]');
                if (!b) return;
                const cmd = commands[Number(b.getAttribute('data-cmd-idx'))];
                if (cmd) await copyToClipboard(cmd);
            };
        }
    } catch (e) {
        if (text) text.textContent = `Erreur IA: ${String(e?.message || e)}`;
    }
}

function extractTimestampToken(line) {
    const d = parseSyslogDate(line);
    if (!d) return null;
    const iso = String(line || '').match(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})?)/);
    if (iso) {
        return { date: d, display: iso[1] };
    }
    const m = String(line || '').match(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/);
    return {
        date: d,
        display: m ? m[1] : d.toLocaleString()
    };
}

function trimMessage(line) {
    const s = String(line || '');
    return s.length > 120 ? `${s.slice(0, 120)}…` : s;
}

function renderHighlightedMessage(line) {
    const safe = escapeHtml(String(line || ''));
    // Highlight timestamp token (syslog) subtly
    return safe
        .replace(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/, '<span class="log-ts">$1</span>')
        .replace(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})?)/, '<span class="log-ts">$1</span>');
}

function extractCommands(text) {
    const lines = String(text || '').split('\n').map(l => l.trim()).filter(Boolean);
    const candidates = [];

    // Prefer fenced code blocks if any
    const fenced = String(text || '').match(/```([\s\S]*?)```/g);
    if (fenced) {
        fenced.forEach(block => {
            const inner = block.replace(/```/g, '').trim();
            inner.split('\n').map(l => l.trim()).filter(Boolean).forEach(l => candidates.push(l.replace(/^\$\s*/, '')));
        });
    }

    // Heuristic single-line commands
    const keywords = ['systemctl', 'journalctl', 'dnf', 'yum', 'apt', 'grep', 'tail', 'sshd', 'firewall-cmd'];
    lines.forEach(l => {
        const raw = l.replace(/^\$\s*/, '');
        if (raw.length < 8 || raw.length > 160) return;
        if (keywords.some(k => raw.includes(k))) candidates.push(raw);
    });

    // unique, keep max 3
    const uniq = Array.from(new Set(candidates)).slice(0, 3);
    return uniq;
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(String(text || ''));
    } catch (e) {
        // Fallback
        const ta = document.createElement('textarea');
        ta.value = String(text || '');
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    }
}

function escapeHtml(str) {
    return String(str)
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
}

function safeByteLength(str) {
    try {
        return new Blob([str]).size;
    } catch {
        return (str || '').length;
    }
}

function formatBytes(bytes) {
    if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
    const val = bytes / (1024 ** i);
    return `${val.toFixed(val >= 10 || i === 0 ? 0 : 1)} ${units[i]}`;
}