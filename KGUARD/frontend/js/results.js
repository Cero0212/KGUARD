// Cargar lista de resultados
async function loadResults() {
    try {
        const response = await fetch('/api/scans');
        const scans = await response.json();
        
        const container = document.getElementById('scansList');
        if (!container) return;
        container.innerHTML = '';
        
        if (scans.length === 0) {
            container.innerHTML = '<p class="text-center">No hay escaneos guardados</p>';
            return;
        }
        
        scans.forEach(scan => {
            const div = document.createElement('div');
            div.className = 'scan-item';
            div.dataset.scanId = scan.id;
            
            const summary = scan.summary || {};
            const badges = Object.entries(summary)
                .filter(([_, count]) => count > 0)
                .map(([severity, count]) => 
                    `<span class="severity-badge ${severity}">${severity}: ${count}</span>`
                ).join('');
            
            div.innerHTML = `
                <div class="scan-info">
                    <h3>${scan.target}</h3>
                    <div class="scan-meta">
                        ${new Date(scan.start_time).toLocaleString()} | 
                        Tipo: ${scan.type} | 
                        Hallazgos: ${scan.findings_count}
                    </div>
                    <div class="scan-summary">
                        ${badges}
                    </div>
                </div>
                <div class="scan-actions">
                    <button class="btn btn-small btn-ver">Ver</button>
                </div>
            `;
            
            div.querySelector('.btn-ver').onclick = () => loadScanDetail(scan.id);
            div.onclick = (e) => {
                if (!e.target.closest('button')) loadScanDetail(scan.id);
            };
            
            container.appendChild(div);
        });
        
        if (document.getElementById('scanDetail')) {
            document.getElementById('scanDetail').style.display = 'none';
        }
        
    } catch (error) {
        console.error('Error loading results:', error);
    }
}

// Cargar detalle de un escaneo
async function loadScanDetail(scanId) {
    try {
        const response = await fetch(`/api/scan/results/${scanId}`);
        const scan = await response.json();
        
        document.getElementById('scanDetail').style.display = 'block';
        document.getElementById('detailTitle').textContent = `Escaneo: ${scan.target}`;
        
        // Guardar datos del scan actual en el objeto window para exportación
        window.currentScanData = scan;

        document.querySelectorAll('.scan-item').forEach(item => {
            item.classList.toggle('selected', item.dataset.scanId === scanId);
        });
        
        const findingsContainer = document.getElementById('findingsList');
        findingsContainer.innerHTML = '';
        
        if (!scan.findings || scan.findings.length === 0) {
            findingsContainer.innerHTML = '<p>No se encontraron hallazgos</p>';
        } else {
            scan.findings.forEach(finding => {
                const findingDiv = document.createElement('div');
                findingDiv.className = `finding-item ${finding.severity || 'info'}`;
                
                const evidence = finding.evidence ? 
                    `<pre class="finding-evidence">${JSON.stringify(finding.evidence, null, 2)}</pre>` : '';
                
                findingDiv.innerHTML = `
                    <div class="finding-header">
                        <span class="finding-title">${finding.title}</span>
                        <span class="severity-badge ${finding.severity || 'info'}">${finding.severity || 'info'}</span>
                    </div>
                    <div class="finding-description">${finding.description || ''}</div>
                    <div class="finding-remediation">
                        <strong>Remediación:</strong> ${finding.remediation || 'No especificada'}
                    </div>
                    ${evidence}
                `;
                findingsContainer.appendChild(findingDiv);
            });
        }
        
        // Configurar botones de exportación con la data cargada
        document.getElementById('exportJsonBtn').onclick = () => exportScan('json');
        document.getElementById('exportHtmlBtn').onclick = () => exportScan('html');
        document.getElementById('exportPdfBtn').onclick = () => exportScan('pdf');
        
        document.getElementById('deleteScanBtn').onclick = async () => {
            if (confirm('¿Eliminar este escaneo?')) {
                await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
                if (window.showNotification) window.showNotification('Escaneo eliminado', 'success');
                loadResults();
            }
        };
        
    } catch (error) {
        console.error('Error loading scan detail:', error);
    }
}

// FUNCIONES DE EXPORTACIÓN REAL
async function exportScan(format) {
    const scan = window.currentScanData;
    if (!scan) return;

    if (window.showNotification) window.showNotification(`Generando reporte ${format.toUpperCase()}...`, 'info');

    const fileName = `KGUARD_${scan.target.replace(/[^a-z0-9]/gi, '_')}_${scan.id.substring(0,8)}`;

    if (format === 'json') {
        downloadBlob(JSON.stringify(scan, null, 2), `${fileName}.json`, 'application/json');
    } 
    else if (format === 'html') {
        const htmlContent = `
            <html>
            <head>
                <title>Reporte KGUARD - ${scan.target}</title>
                <style>
                    body { font-family: Arial; padding: 40px; background: #f4f4f4; }
                    .report-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                    .finding { border-left: 5px solid #ccc; padding: 10px; margin: 10px 0; background: #fafafa; }
                    .high { border-left-color: #ff4d4d; }
                    .medium { border-left-color: #ffa64d; }
                    .info { border-left-color: #4da6ff; }
                </style>
            </head>
            <body>
                <div class="report-card">
                    <h1>Reporte de Seguridad KGUARD</h1>
                    <p><strong>Objetivo:</strong> ${scan.target}</p>
                    <p><strong>Fecha:</strong> ${new Date(scan.start_time).toLocaleString()}</p>
                    <hr>
                    ${scan.findings.map(f => `
                        <div class="finding ${f.severity}">
                            <h3>${f.title} (${f.severity})</h3>
                            <p>${f.description}</p>
                            <p><strong>Remediación:</strong> ${f.remediation}</p>
                        </div>
                    `).join('')}
                </div>
            </body>
            </html>`;
        downloadBlob(htmlContent, `${fileName}.html`, 'text/html');
    } 
    else if (format === 'pdf') {
        const { jsPDF } = window.jspdf;
        const doc = new jsPDF();
        
        doc.setFontSize(20);
        doc.text("Reporte de Escaneo KGUARD", 14, 20);
        doc.setFontSize(12);
        doc.text(`Objetivo: ${scan.target}`, 14, 30);
        doc.text(`Fecha: ${new Date(scan.start_time).toLocaleString()}`, 14, 38);

        const tableBody = scan.findings.map(f => [f.title, f.severity, f.description.substring(0, 100) + '...']);
        
        doc.autoTable({
            startY: 45,
            head: [['Hallazgo', 'Severidad', 'Resumen']],
            body: tableBody,
        });

        doc.save(`${fileName}.pdf`);
    }
}

function downloadBlob(content, fileName, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(url);
}

// Filtros y eventos iniciales
document.addEventListener('DOMContentLoaded', function() {
    if (document.querySelector('.results-page') || document.getElementById('scansList')) {
        loadResults();
        
        const searchInput = document.getElementById('searchResults');
        if (searchInput) {
            searchInput.addEventListener('input', function(e) {
                const term = e.target.value.toLowerCase();
                document.querySelectorAll('.scan-item').forEach(item => {
                    item.style.display = item.textContent.toLowerCase().includes(term) ? 'flex' : 'none';
                });
            });
        }
    }
});
