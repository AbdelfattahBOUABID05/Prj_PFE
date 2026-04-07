// Variable globale pour stocker l'instance du graphique afin de pouvoir le réinitialiser
let myChart = null;

// Attendre le chargement complet du DOM avant d'exécuter le script
document.addEventListener('DOMContentLoaded', function() {
    // Récupération des dernières données d'analyse stockées dans le navigateur
    const savedData = localStorage.getItem('lastAnalysis');
    
    if (savedData) {
        const data = JSON.parse(savedData);
        console.log("Chargement des données SSH...", data);
        // Mise à jour de l'interface utilisateur avec les données récupérées
        updateDashboard(data);
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

    // Récupération de l'élément Canvas pour le graphique
    const canvas = document.getElementById('logChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    
    // Si un graphique existe déjà, on le détruit pour éviter les superpositions
    if (myChart) myChart.destroy();

    // Création d'un nouveau graphique de type 'doughnut' (Beignet)
    myChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Errors', 'Warnings', 'Info'],
            datasets: [{
                data: [data.stats.errors, data.stats.warnings, data.stats.info],
                backgroundColor: [
                    '#ff4d4d', // Rouge pour les erreurs
                    '#ffcc00', // Jaune pour les avertissements
                    '#2ecc71'  // Vert pour les informations
                ],
                hoverOffset: 10,
                borderWidth: 0,
                cutout: '85%', // Taille du trou central
                borderRadius: 10, // Arrondi des segments
                spacing: 5 // Espace entre les segments
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom', // Affichage de la légende en bas
                    labels: {
                        usePointStyle: true,
                        padding: 20,
                        font: { size: 12, family: 'Poppins' }
                    }
                }
            }
        }
    });

    // Mise à jour de la section de notification et ajout du bouton de rapport
    const aiResult = document.getElementById('aiResult');
    if (aiResult) {
        aiResult.innerHTML = `
            <div class="alert alert-success border-0 shadow-sm text-start">
                <i class="fas fa-check-circle me-2"></i> 
                Logs récupérés via <b>SSH</b> avec succès.
                <br><small class="text-muted">Dernière analyse: ${new Date().toLocaleTimeString()}</small>
            </div>
            <button class="btn btn-outline-primary btn-sm mt-2">
                <i class="fas fa-magic me-2"></i>Générer un rapport IA
            </button>
        `;
    }
}