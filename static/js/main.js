let myChart = null;

// هاد الدالة كتشغل أوتوماتيكياً ملي كتحل الصفحة
document.addEventListener('DOMContentLoaded', function() {
    const savedData = localStorage.getItem('lastAnalysis');
    
    if (savedData) {
        const data = JSON.parse(savedData);
        console.log("Chargement des données SSH...", data);
        updateDashboard(data);
    }
});

function updateDashboard(data) {
    // 1. تحديث الأرقام (تأكد أن ID كيطابق HTML)
    const errElem = document.getElementById('errCount');
    if (errElem) errElem.innerText = data.stats.errors;

    // 2. تحديث المبيان (Chart.js)
    const canvas = document.getElementById('logChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    
    if (myChart) myChart.destroy();

    myChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Errors', 'Warnings', 'Info'],
            datasets: [{
                data: [data.stats.errors, data.stats.warnings, data.stats.info],
                backgroundColor: [
                    '#ff4d4d', // Red لـ Errors
                    '#ffcc00', // Yellow لـ Warnings
                    '#2ecc71'  // Green لـ Info
                ],
                hoverOffset: 10,
                borderWidth: 0,
                cutout: '85%', // هادي هي اللي كترقق الدائرة (كلما كبر العدد كترقاق)
                borderRadius: 10, // كترد الجناب ديال الألوان دايرين (Rounded)
                spacing: 5 // كتدير فراغ صغير بين كل لون ولون
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'bottom', // كيبانو السميات لتحت بشكل منظم
                    labels: {
                        usePointStyle: true,
                        padding: 20,
                        font: { size: 12, family: 'Poppins' }
                    }
                }
            }
        }
    });

    // 3. تحديث قسم الـ AI
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