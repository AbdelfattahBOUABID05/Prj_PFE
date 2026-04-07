document.addEventListener('DOMContentLoaded', function() {
    const rawData = localStorage.getItem('lastAnalysis');
    
    if (!rawData) {
        console.error("Aucune donnée trouvée");
        return;
    }

    const data = JSON.parse(rawData);

    // 1. تعبئة التاريخ والمسار
    document.getElementById('reportDate').innerText = new Date().toLocaleString('fr-FR');
    
    const pathElement = document.getElementById('repFilePath');
    if (pathElement) {
        pathElement.innerText = data.path || "/var/log/messages";
    }

    // 2. تعبئة الأرقام
    document.getElementById('repTotal').innerText = data.stats.total;
    document.getElementById('repErrors').innerText = data.stats.errors;
    document.getElementById('repWarnings').innerText = data.stats.warnings;

    // 3. تعبئة الجدول
    const tableBody = document.getElementById('reportTableBody');
    if (tableBody) {
        tableBody.innerHTML = ''; 
        const sampleLogs = [
            ...data.segments.ERROR.map(msg => ({ type: 'ERROR', text: msg })),
            ...data.segments.WARNING.map(msg => ({ type: 'WARNING', text: msg })),
            ...data.segments.INFO.map(msg => ({ type: 'INFO', text: msg }))
        ].slice(0, 30); // عرض أول 30 سطر

        sampleLogs.forEach(log => {
            const badgeClass = log.type === 'ERROR' ? 'bg-danger' : (log.type === 'WARNING' ? 'bg-warning text-dark' : 'bg-info');
            tableBody.innerHTML += `
                <tr>
                    <td><span class="badge ${badgeClass}">${log.type}</span></td>
                    <td class="text-break text-muted small">${log.text}</td>
                </tr>
            `;
        });
    }

    // 4. رسم المبيان
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

// دالة تحميل PDF (بقت كما هي مع إعدادات الهوامش)
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
    html2pdf().set(opt).from(element).save();
}