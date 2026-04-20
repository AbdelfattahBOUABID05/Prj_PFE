// Conserve les instances des graphiques pour un re-rendu propre.
let statsChart = null; // Instance globale pour le graphique des stats
let severityChart = null;
let activityChart = null;
let currentAnalysisData = null;
const CRITICAL_ALERTS_STORAGE_KEY = 'criticalAlerts';

/**
 * Lit une variable CSS du thème actif.
 */
function readCssVar(name, fallback = '') {
    const value = getComputedStyle(document.documentElement).getPropertyValue(name);
    return value ? value.trim() : fallback;
}

/**
 * Palette dépendante du thème courant (clair/sombre).
 */
function getThemeColors() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    return {
        deepRed: isDark ? '#f43f5e' : '#B42318', // Cyber Red gradient start
        deepRedSoft: isDark ? 'rgba(244, 63, 94, 0.2)' : 'rgba(180, 35, 24, 0.15)',
        amber: isDark ? '#fbbf24' : '#F79009',
        softBlue: isDark ? '#3b82f6' : '#2E90FA', // Cyber Blue
        softBlueSoft: isDark ? 'rgba(59, 130, 246, 0.2)' : 'rgba(46, 144, 250, 0.15)',
        grid: isDark ? 'rgba(159, 179, 207, 0.1)' : 'rgba(15, 23, 42, 0.05)',
        text: isDark ? 'rgba(255, 255, 255, 0.9)' : 'rgba(26, 26, 26, 0.85)',
        tooltipBg: isDark ? 'rgba(15, 24, 40, 0.95)' : 'rgba(17, 24, 39, 0.92)',
        pointBg: isDark ? '#0f172a' : '#ffffff',
        glassBg: isDark ? 'rgba(30, 41, 59, 0.7)' : 'rgba(255, 255, 255, 0.7)',
        glassBorder: isDark ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)'
    };
}

// Attendre le chargement complet du DOM avant d'exécuter le script
document.addEventListener('DOMContentLoaded', function() {
    // Initialise la préférence visuelle enregistrée et relie les boutons.
    initThemeSwitch();
    initNotificationsUI();
    initStatsFilters(); // Initialisation des filtres de stats

    // Priorité à l'analyse injectée par le serveur (Session Flask)
    // Sinon, repli sur le localStorage (pour compatibilité immédiate après analyse)
    const data = window.SERVER_ANALYSIS_DATA || JSON.parse(localStorage.getItem('lastAnalysis') || 'null');
    
    if (data) {
        currentAnalysisData = data;
        console.log("Chargement des données d'analyse...", data);
        // Mise à jour de l'interface utilisateur avec les données récupérées
        updateDashboard(data);
        initDetailsMonitoringView(data);
    }

    // Charger les stats initiales (7 jours par défaut)
    loadStats('7d');
});

/**
 * Initialisation des filtres de statistiques
 */
function initStatsFilters() {
    const periodRadios = document.querySelectorAll('input[name="period"]');
    periodRadios.forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.checked) {
                loadStats(e.target.value);
                document.getElementById('custom-range-container')?.classList.add('d-none');
            }
        });
    });

    const customToggle = document.getElementById('custom-range-toggle');
    customToggle?.addEventListener('click', () => {
        const container = document.getElementById('custom-range-container');
        container?.classList.toggle('d-none');
    });

    const applyCustomBtn = document.getElementById('apply-custom');
    applyCustomBtn?.addEventListener('click', () => {
        const start = document.getElementById('start-date').value;
        const end = document.getElementById('end-date').value;
        if (start && end) {
            loadStats('custom', start, end);
        } else {
            Swal.fire('Erreur', 'Veuillez sélectionner une date de début et de fin.', 'warning');
        }
    });
}

/**
 * Charge les statistiques depuis l'API et met à jour l'UI
 */
async function loadStats(period, start = null, end = null) {
    const loader = document.getElementById('chart-loader');
    loader?.classList.remove('d-none');

    let url = `/api/stats?period=${period}`;
    if (period === 'custom' && start && end) {
        url += `&start_date=${start}&end_date=${end}`;
    }

    try {
        const response = await fetch(url);
        const data = await response.json();

        if (data.error) throw new Error(data.error);

        updateStatsUI(data);
        renderStatsChart(data);
    } catch (error) {
        console.error("Erreur stats:", error);
        // Optionnel: afficher une erreur sur le chart
    } finally {
        loader?.classList.add('d-none');
    }
}

function updateStatsUI(data) {
    const totalLogs = data.total_logs || 0;
    const totalAnomalies = (data.total_errors || 0) + (data.total_warnings || 0);
    const totalNormal = Math.max(0, totalLogs - totalAnomalies);

    animateCounter('m-total', totalLogs);
    animateCounter('m-anomaly', totalAnomalies);
    animateCounter('m-normal', totalNormal);
}

function animateCounter(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    
    const start = parseInt(el.textContent) || 0;
    const duration = 800;
    const startTime = performance.now();

    function update(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const ease = 1 - Math.pow(1 - progress, 3); // easeOutCubic
        const current = Math.floor(start + (target - start) * ease);
        
        el.textContent = current;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    requestAnimationFrame(update);
}

function renderStatsChart(data) {
    const canvas = document.getElementById('statsChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (statsChart) statsChart.destroy();

    const colors = getThemeColors();

    statsChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: data.labels,
            datasets: [
                {
                    label: 'Critique',
                    data: data.critique,
                    backgroundColor: colors.deepRed,
                    borderRadius: 4,
                    stack: 'Stack 0',
                },
                {
                    label: 'Avertissement',
                    data: data.avertissement,
                    backgroundColor: colors.amber,
                    borderRadius: 4,
                    stack: 'Stack 0',
                },
                {
                    label: 'Info',
                    data: data.info,
                    backgroundColor: colors.softBlue,
                    borderRadius: 4,
                    stack: 'Stack 0',
                }
            ]
        },
        options: {
            ...baseChartOptions(),
            plugins: {
                ...baseChartOptions().plugins,
                legend: {
                    ...baseChartOptions().plugins.legend,
                    position: 'top',
                    align: 'end'
                }
            },
            scales: {
                x: {
                    stacked: true,
                    grid: { display: false },
                    ticks: { color: colors.text }
                },
                y: {
                    stacked: true,
                    grid: { color: colors.grid, drawBorder: false },
                    ticks: { color: colors.text, precision: 0 },
                    beginAtZero: true
                }
            },
            animation: {
                duration: 1000,
                easing: 'easeOutQuart'
            }
        }
    });
}

/**
 * Met à jour les éléments du tableau de bord.
 * @param {Object} data - Données issues de l'analyse des logs.
 */
function updateDashboard(data) {
    currentAnalysisData = data;
    const colors = getThemeColors();

    renderSeverityChart(data);
    renderActivityChart(data);
    hideSkeleton('severitySkeleton');
    hideSkeleton('activitySkeleton');

    // Met à jour la zone "Points Clés de l'Audit IA"
    const aiResult = document.getElementById('aiResult');
    if (aiResult) {
        const meta = data.meta || {};
        const auditPoints = meta.audit_points || data.audit_points;
        const insights = meta.ai_insights || data.ai_insights || "Analyse en cours...";
        
        let bulletPoints = "";
        if (Array.isArray(auditPoints) && auditPoints.length > 0) {
            // Priorité aux points d'audit structurés
            bulletPoints = `<ul class="mb-0 ps-3">` + 
                auditPoints.map(p => `<li class="mb-2">${p}</li>`).join('') + 
                `</ul>`;
        } else {
            // Transformation du texte en liste à puces si c'est un paragraphe long
            bulletPoints = insights;
            if (insights.length > 50 && !insights.includes('<li>')) {
                const sentences = insights.split('. ').filter(s => s.trim().length > 0);
                bulletPoints = `<ul class="mb-0 ps-3">` + 
                    sentences.map(s => `<li class="mb-2">${s.trim().replace(/\.$/, '')}.</li>`).join('') + 
                    `</ul>`;
            }
        }

        aiResult.innerHTML = `
            <div class="glass-card p-4 text-start" style="border-left: 4px solid ${colors.softBlue};">
                <div class="d-flex align-items-start gap-3">
                    <div class="mt-1" style="color:${colors.softBlue}; font-size: 1.2rem;"><i class="fas fa-robot"></i></div>
                    <div class="w-100">
                        <div class="d-flex justify-content-between align-items-center mb-2">
                            <div style="font-weight:700; color:${colors.text}; font-size: 1.1rem;">Synthèse de l'Audit</div>
                            <div class="small text-muted"><i class="far fa-clock me-1"></i>${new Date().toLocaleTimeString()}</div>
                        </div>
                        <div class="ai-insights-list" style="color:${colors.text}; line-height: 1.6;">
                            ${bulletPoints}
                        </div>
                        <div class="mt-3 d-flex gap-2">
                            <button id="generateReportBtn" class="btn btn-saas btn-sm" type="button">
                                <i class="fas fa-magic me-2"></i>Affiner l'analyse
                            </button>
                            <a href="/report" class="btn btn-outline-saas btn-sm">
                                <i class="fas fa-external-link-alt me-2"></i>Rapport complet
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        `;
        attachGenerateReportHandler();
    }

    // Déclenche une alerte immédiate si des signaux critiques sont détectés.
    notifyCriticalIfNeeded(data);
}

function attachGenerateReportHandler() {
    const btn = document.getElementById('generateReportBtn');
    if (!btn || btn.dataset.bound === '1') return;
    btn.dataset.bound = '1';

    btn.addEventListener('click', async () => {
        const original = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Analyse en cours...';
        try {
            const res = await fetch('/generate-report', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scope: 'day' })
            });
            const payload = await res.json();
            if (!res.ok || payload?.status !== 'success') {
                throw new Error(payload?.message || 'Erreur inconnue');
            }
            window.location.href = '/report';
        } catch (e) {
            Swal.fire({
                icon: 'error',
                title: 'Échec de la génération',
                text: 'Erreur lors de la génération du rapport. Veuillez réessayer.',
                customClass: {
                    popup: 'swal-custom-popup',
                    title: 'swal-custom-title',
                    confirmButton: 'swal-custom-confirm'
                },
                buttonsStyling: false
            });
            btn.disabled = false;
            btn.innerHTML = original;
        }
    });
}

function hideSkeleton(id) {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
}

function baseChartOptions() {
    const colors = getThemeColors();
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
                    color: colors.text,
                    font: { size: 12, family: 'Inter, system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif', weight: '600' }
                }
            },
            tooltip: {
                backgroundColor: colors.tooltipBg,
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

    const colors = getThemeColors();

    // Priorité aux données IA si disponibles
    const counts = data.meta?.severity_counts || data.severity_counts;
    let chartData = [];
    let labels = ['Erreurs', 'Avertissements', 'Info'];

    if (counts && (counts.Critique !== undefined || counts.Moyen !== undefined)) {
        chartData = [counts.Critique || 0, counts.Moyen || 0, counts.Faible || 0];
        labels = ['Critique', 'Moyen', 'Faible'];
    } else {
        // Fallback sur les stats de base si l'IA n'a pas renvoyé de counts
        chartData = [data.stats?.errors || 0, data.stats?.warnings || 0, data.stats?.info || 0];
    }

    // Vérification si données vides
    if (chartData.every(v => v === 0)) {
        ctx.font = "14px Inter";
        ctx.fillStyle = colors.text;
        ctx.textAlign = "center";
        ctx.fillText("Données indisponibles", canvas.width / 2, canvas.height / 2);
        return;
    }

    // Création de gradients cyber
    const gradRed = ctx.createLinearGradient(0, 0, 0, 200);
    gradRed.addColorStop(0, colors.deepRed);
    gradRed.addColorStop(1, '#991b1b');

    const gradBlue = ctx.createLinearGradient(0, 0, 0, 200);
    gradBlue.addColorStop(0, colors.softBlue);
    gradBlue.addColorStop(1, '#1e40af');

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: chartData,
                backgroundColor: [
                    gradRed,
                    colors.amber,
                    gradBlue
                ],
                hoverOffset: 12,
                borderWidth: 0,
                cutout: '80%',
                borderRadius: 12,
                spacing: 8
            }]
        },
        options: {
            ...baseChartOptions(),
            plugins: {
                ...baseChartOptions().plugins,
                legend: {
                    ...baseChartOptions().plugins.legend,
                    position: 'right',
                    labels: {
                        ...baseChartOptions().plugins.legend.labels,
                        padding: 20
                    }
                }
            }
        }
    });
}

function renderActivityChart(data) {
    const canvas = document.getElementById('activityChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (activityChart) activityChart.destroy();

    const colors = getThemeColors();
    
    // Priorité à la tendance IA
    const aiTrend = data.meta?.activity_trend || data.activity_trend;
    let labels = [];
    let values = [];

    if (Array.isArray(aiTrend) && aiTrend.length > 0) {
        values = aiTrend;
        labels = aiTrend.map((_, i) => `T${i+1}`);
    } else {
        const points = buildActivitySeries(data);
        labels = points.map(p => p.label);
        values = points.map(p => p.count);
    }

    // Vérification si données vides
    if (values.length === 0 || values.every(v => v === 0)) {
        ctx.font = "14px Inter";
        ctx.fillStyle = colors.text;
        ctx.textAlign = "center";
        ctx.fillText("Données indisponibles", canvas.width / 2, canvas.height / 2);
        return;
    }

    const gradient = ctx.createLinearGradient(0, 0, 0, 300);
    gradient.addColorStop(0, colors.softBlueSoft);
    gradient.addColorStop(1, 'transparent');

    activityChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [{
                label: 'Volume de Logs',
                data: values,
                borderColor: colors.softBlue,
                backgroundColor: gradient,
                fill: true,
                tension: 0.4,
                pointRadius: 4,
                pointHoverRadius: 6,
                pointBackgroundColor: colors.softBlue,
                pointBorderColor: '#fff',
                pointBorderWidth: 2,
                borderWidth: 3
            }]
        },
        options: {
            ...baseChartOptions(),
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: colors.text, maxRotation: 0, autoSkip: true, maxTicksLimit: 7 }
                },
                y: {
                    grid: { color: colors.grid, drawBorder: false },
                    ticks: { color: colors.text, precision: 0 },
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Initialise le thème (sombre/clair), synchronise l'UI et persiste le choix.
 */
function initThemeSwitch() {
    const root = document.documentElement;
    const savedTheme = localStorage.getItem('themePreference');
    const preferredDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const initialTheme = savedTheme || (preferredDark ? 'dark' : 'light');

    applyTheme(initialTheme);

    const toggles = Array.from(document.querySelectorAll('#themeToggle'));
    toggles.forEach((btn) => {
        btn.addEventListener('click', () => {
            const nextTheme = root.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            applyTheme(nextTheme);
            localStorage.setItem('themePreference', nextTheme);
        });
    });
}

function applyTheme(theme) {
    const root = document.documentElement;
    const resolvedTheme = theme === 'dark' ? 'dark' : 'light';
    root.setAttribute('data-theme', resolvedTheme);
    root.style.colorScheme = resolvedTheme;
    updateThemeToggleLabel(resolvedTheme);

    // Recalcule les graphiques selon la nouvelle palette.
    if (currentAnalysisData) {
        renderSeverityChart(currentAnalysisData);
        renderActivityChart(currentAnalysisData);
    }
}

function updateThemeToggleLabel(theme) {
    const isDark = theme === 'dark';
    const toggles = Array.from(document.querySelectorAll('#themeToggle'));
    toggles.forEach((btn) => {
        const icon = btn.querySelector('i');
        if (icon) icon.className = isDark ? 'fas fa-sun' : 'fas fa-moon';
        btn.setAttribute('title', isDark ? 'Mode clair' : 'Mode sombre');
        btn.setAttribute('aria-label', isDark ? 'Activer le mode clair' : 'Activer le mode sombre');
    });
}

/**
 * Détecte les signaux critiques et affiche une alerte toast unique par analyse.
 */
function notifyCriticalIfNeeded(data) {
    if (!isDashboardPage() || !data) return;
    if (!hasCriticalSignal(data)) return;

    const alertKey = buildCriticalAlertKey(data);
    if (alertKey && localStorage.getItem(alertKey) === '1') return;

    showCriticalToast();
    persistCriticalAlert(data);
    renderNotificationsMenu();
    if (alertKey) localStorage.setItem(alertKey, '1');
}

function isDashboardPage() {
    return Boolean(document.querySelector('.dashboard-page'));
}

function hasCriticalSignal(data) {
    const level = String(
        data?.security_level ||
        data?.ai?.security_level ||
        data?.meta?.security_level ||
        ''
    ).toUpperCase();
    if (level === 'CRITICAL') return true;

    const statsCritical = Number(data?.stats?.critical || 0);
    if (statsCritical > 0) return true;

    const segments = data?.segments || {};
    const criticalSegment = segments.CRITICAL || segments.critical || [];
    if (Array.isArray(criticalSegment) && criticalSegment.length > 0) return true;

    const lines = []
        .concat(Array.isArray(segments.ERROR) ? segments.ERROR : [])
        .concat(Array.isArray(criticalSegment) ? criticalSegment : []);

    return lines.some((line) => /critical|critique/i.test(String(line || '')));
}

function buildCriticalAlertKey(data) {
    if (data?.analysis_id) return `criticalAlertShown:${data.analysis_id}`;
    if (data?.generated_at) return `criticalAlertShown:time:${data.generated_at}`;

    const err = Number(data?.stats?.errors || 0);
    const total = Number(data?.stats?.total || 0);
    const fallback = `${err}-${total}`;
    return `criticalAlertShown:fallback:${fallback}`;
}

function showCriticalToast() {
    const title = "Alerte de Sécurité !";
    const text = "Des événements critiques ont été repérés dans l'analyse en cours.";

    Swal.fire({
        toast: true,
        position: 'top-end',
        icon: 'error',
        title,
        text,
        showConfirmButton: false,
        timer: 6500,
        timerProgressBar: true,
        background: '#111827',
        color: '#f3f4f6',
        customClass: {
            popup: 'swal-custom-popup',
            title: 'swal-custom-title'
        }
    });
}

/**
 * Persiste les alertes critiques pour affichage dans la cloche de notifications.
 */
function persistCriticalAlert(data) {
    const list = getStoredCriticalAlerts();
    const id = String(data?.analysis_id || data?.generated_at || Date.now());
    if (list.some((item) => item.id === id)) return;

    list.unshift({
        id,
        title: 'Alerte critique détectée',
        message: "Des événements critiques ont été repérés dans l'analyse en cours.",
        at: new Date().toISOString()
    });

    localStorage.setItem(CRITICAL_ALERTS_STORAGE_KEY, JSON.stringify(list.slice(0, 25)));
}

function getStoredCriticalAlerts() {
    try {
        const raw = localStorage.getItem(CRITICAL_ALERTS_STORAGE_KEY);
        const parsed = JSON.parse(raw || '[]');
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function initNotificationsUI() {
    renderNotificationsMenu();
    bindNotificationActions();
}

function bindNotificationActions() {
    const clearBtn = document.getElementById('clearNotificationsBtn');
    if (!clearBtn || clearBtn.dataset.bound === '1') return;
    clearBtn.dataset.bound = '1';
    clearBtn.addEventListener('click', (e) => {
        e.preventDefault();
        localStorage.setItem(CRITICAL_ALERTS_STORAGE_KEY, JSON.stringify([]));
        renderNotificationsMenu();
    });
}

function renderNotificationsMenu() {
    const listEl = document.getElementById('notification-list');
    const emptyEl = document.getElementById('notification-empty');
    const countEl = document.getElementById('notification-count');
    if (!listEl || !emptyEl || !countEl) return;

    const alerts = getStoredCriticalAlerts();
    countEl.textContent = String(alerts.length);
    countEl.classList.toggle('d-none', alerts.length === 0);

    if (alerts.length === 0) {
        emptyEl.classList.remove('d-none');
        listEl.innerHTML = '';
        return;
    }

    emptyEl.classList.add('d-none');
    listEl.innerHTML = alerts.map((item) => {
        const when = formatNotificationTime(item.at);
        return `
            <div class="notification-list-item">
                <div class="notification-list-title">${escapeHtml(item.title || 'Alerte critique')}</div>
                <div class="notification-list-meta">${escapeHtml(item.message || '')}</div>
                <div class="notification-list-meta">${escapeHtml(when)}</div>
            </div>
        `;
    }).join('');
}

function formatNotificationTime(iso) {
    try {
        return new Date(iso).toLocaleString();
    } catch {
        return '';
    }
}

function buildActivitySeries(data) {
    // Construit une série temporelle simple depuis les horodatages des lignes.
    // Repli : s'il n'y a pas d'horodatage, affiche une distribution en 10 segments.
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

    // Agrégation par minute
    const map = new Map();
    for (const item of parsed) {
        const d = item.date;
        const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
        map.set(key, (map.get(key) || 0) + 1);
    }

    const keys = Array.from(map.keys()).sort();
    const condensed = keys.slice(Math.max(0, keys.length - 20)); // Conserve les derniers segments pour la lisibilité.
    return condensed.map(k => ({ label: k.split(' ')[1], count: map.get(k) }));
}

function parseSyslogDate(line) {
    // ISO-8601: "2026-04-08T14:56:03" (éventuellement avec ms/fuseau)
    const iso = String(line || '').match(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})?)/);
    if (iso) {
        const d = new Date(iso[1]);
        if (!Number.isNaN(d.getTime())) return d;
    }

    // Syslog classique : "Mar 10 12:34:56 host ..."
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

    // Suppose le fuseau local : suffisant pour la visualisation.
    return new Date(year, month, day, hh, mm, ss);
}

// ----------------------------
// Vue monitoring (page Détails)
// ----------------------------

function initDetailsMonitoringView(data) {
    const grid = document.getElementById('logGrid');
    if (!grid) return; // Pas sur la page Détails.

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
    // Recherche du chemin du fichier dans plusieurs endroits possibles (compatibilité session/meta)
    const file = data?.path || data?.filename || data?.file || data?.meta?.source_path || data?.meta?.filename || '--';
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

    // Tri stable par horodatage si présent, sinon conserve l'ordre par sévérité.
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

    if (sourceBadge) sourceBadge.textContent = `Source : ${model.file}`;
    if (metaFile) metaFile.textContent = model.file;
    if (metaSize) metaSize.textContent = model.payloadBytes ? `${formatBytes(model.payloadBytes)} (charge utile)` : '--';
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
                <button class="exp-btn" type="button" aria-label="Développer" data-action="expand">
                    <i class="fas fa-plus"></i>
                </button>
                <div class="log-sev">${r.severity}</div>
                <div class="log-time d-none d-md-block">${ts}</div>
                <div class="log-msg">${renderHighlightedMessage(r.line)}</div>
                <div class="log-expanded d-none">
                    <div class="expanded-actions">
                        <button class="btn btn-outline-saas btn-sm" data-action="copy">
                            <i class="fas fa-copy me-2"></i>Copier la ligne
                        </button>
                        <button class="btn btn-saas btn-sm" data-action="ai">
                            <i class="fas fa-robot me-2"></i>Analyser avec IA
            </button>
                    </div>
                    <pre class="expanded-pre">${escapeHtml(r.line)}</pre>
                </div>
            </div>
        `;
    }).join('');

    // Délégation d'événements
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
                    <i class="fas fa-terminal me-2"></i>Copier la commande
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
    // Met en évidence le token d'horodatage (syslog) de façon discrète.
    return safe
        .replace(/^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/, '<span class="log-ts">$1</span>')
        .replace(/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+\-]\d{2}:\d{2})?)/, '<span class="log-ts">$1</span>');
}

function extractCommands(text) {
    const lines = String(text || '').split('\n').map(l => l.trim()).filter(Boolean);
    const candidates = [];

    // Priorise les blocs de code si présents.
    const fenced = String(text || '').match(/```([\s\S]*?)```/g);
    if (fenced) {
        fenced.forEach(block => {
            const inner = block.replace(/```/g, '').trim();
            inner.split('\n').map(l => l.trim()).filter(Boolean).forEach(l => candidates.push(l.replace(/^\$\s*/, '')));
        });
    }

    // Heuristique pour extraire des commandes sur une ligne.
    const keywords = ['systemctl', 'journalctl', 'dnf', 'yum', 'apt', 'grep', 'tail', 'sshd', 'firewall-cmd'];
    lines.forEach(l => {
        const raw = l.replace(/^\$\s*/, '');
        if (raw.length < 8 || raw.length > 160) return;
        if (keywords.some(k => raw.includes(k))) candidates.push(raw);
    });

    // Uniques, maximum 3.
    const uniq = Array.from(new Set(candidates)).slice(0, 3);
    return uniq;
}

async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(String(text || ''));
    } catch (e) {
        // Repli
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