// Cargar datos del dashboard
async function loadDashboardData() {
    try {
        const response = await fetch('/api/dashboard/metrics');
        const data = await response.json();
        
        // Actualizar métricas
        document.getElementById('totalScans').textContent = data.total_scans || 0;
        document.getElementById('criticalFindings').textContent = data.findings?.critical || 0;
        document.getElementById('highFindings').textContent = data.findings?.high || 0;
        document.getElementById('mediumFindings').textContent = data.findings?.medium || 0;
        document.getElementById('lowFindings').textContent = data.findings?.low || 0;
        document.getElementById('infoFindings').textContent = data.findings?.info || 0;
        
        // Cargar escaneos recientes
        loadRecentScans();
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
    }
}

// Cargar escaneos recientes
async function loadRecentScans() {
    try {
        const response = await fetch('/api/scans');
        const scans = await response.json();
        
        const tbody = document.getElementById('recentScansBody');
        tbody.innerHTML = '';
        
        scans.slice(0, 10).forEach(scan => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${new Date(scan.start_time).toLocaleString()}</td>
                <td>${scan.target}</td>
                <td>${scan.type}</td>
                <td>${scan.findings_count}</td>
                <td>
                    <button onclick="viewScan('${scan.id}')" class="btn btn-small">Ver</button>
                </td>
            `;
            tbody.appendChild(row);
        });
        
        // Hacer que las filas sean clickables
        document.querySelectorAll('#recentScansBody tr').forEach(row => {
            row.addEventListener('click', function() {
                const scanId = this.querySelector('button')?.getAttribute('onclick')?.match(/'([^']+)'/)[1];
                if (scanId) viewScan(scanId);
            });
        });
        
    } catch (error) {
        console.error('Error loading recent scans:', error);
    }
}

// Ver detalles de un escaneo
function viewScan(scanId) {
    navigateTo('/results.html');
    setTimeout(() => {
        if (typeof loadScanDetail === 'function') {
            loadScanDetail(scanId);
        }
    }, 500);
}

// Limpiar historial
document.addEventListener('click', function(e) {
    if (e.target.id === 'clearHistoryBtn') {
        if (confirm('¿Estás seguro de limpiar todo el historial?')) {
            fetch('/api/scans/clear', {
                method: 'POST'
            }).then(() => {
                loadDashboardData();
                showNotification('Historial limpiado', 'success');
            });
        }
    }
    
    if (e.target.id === 'updateThreatsBtn') {
        fetch('/api/threats/update', {
            method: 'POST'
        }).then(response => response.json())
          .then(data => {
              showNotification('Bases de amenazas actualizadas', 'success');
          });
    }
});

// Inicializar
document.addEventListener('DOMContentLoaded', function() {
    if (document.querySelector('.dashboard')) {
        loadDashboardData();
        
        // Actualizar cada 30 segundos
        setInterval(loadDashboardData, 30000);
    }
});
