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

    // 1. Affichage des métadonnées (Date et Chemin du fichier)
    document.getElementById('reportDate').innerText = new Date().toLocaleString('fr-FR');
    
    const pathElement = document.getElementById('repFilePath');
    if (pathElement) {
        pathElement.innerText = data.path || "/var/log/messages";
    }

    // 2. Mise à jour des compteurs statistiques (Total, Erreurs, Warnings)
    document.getElementById('repTotal').innerText = data.stats.total;
    document.getElementById('repErrors').innerText = data.stats.errors;
    document.getElementById('repWarnings').innerText = data.stats.warnings;

    // 3. Génération dynamique du tableau des logs
    const tableBody = document.getElementById('reportTableBody');
    if (tableBody) {
        tableBody.innerHTML = ''; 
        
        // Fusion des segments et limitation aux 30 premières lignes pour la lisibilité
        const sampleLogs = [
            ...data.segments.ERROR.map(msg => ({ type: 'ERROR', text: msg })),
            ...data.segments.WARNING.map(msg => ({ type: 'WARNING', text: msg })),
            ...data.segments.INFO.map(msg => ({ type: 'INFO', text: msg }))
        ].slice(0, 30); 

        sampleLogs.forEach(log => {
            // Détermination de la couleur du badge selon le type de log
            const badgeClass = log.type === 'ERROR' ? 'bg-danger' : (log.type === 'WARNING' ? 'bg-warning text-dark' : 'bg-info');
            
            // Insertion d'une ligne cliquable avec protection contre les caractères spéciaux
            tableBody.innerHTML += `
                <tr onclick="analyzeWithAI(\`${log.text.replace(/[`"']/g, "")}\`)" style="cursor:pointer;" title="Cliquer pour analyser avec l'IA">
                    <td><span class="badge ${badgeClass}">${log.type}</span></td>
                    <td class="text-muted small">
                        ${log.text} 
                        <i class="fas fa-magic text-primary ms-2 opacity-75"></i>
                    </td>
                </tr>
            `;
        });
    }

    // 4. Initialisation du graphique circulaire (Pie Chart) pour la répartition des logs
    const chartCanvas = document.getElementById('reportChart');
    if (chartCanvas) {
        const ctx = chartCanvas.getContext('2d');
        new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Errors', 'Warnings', 'Info'],
                datasets: [{
                    data: [data.stats.errors, data.stats.warnings, data.stats.info],
                    backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'bottom' } }
            }
        });
    }
});

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
    // Utilisation de la bibliothèque html2pdf pour la conversion
    html2pdf().set(opt).from(element).save();
}