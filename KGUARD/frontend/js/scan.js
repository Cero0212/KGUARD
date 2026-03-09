// Inicializar página de escaneo
async function initScanPage() {
    await loadModules();
    setupScanEvents();
}

// Cargar módulos disponibles
async function loadModules() {
    try {
        // Simular módulos (en producción vendrían del backend)
        const modules = [
            { id: 'system_vulnerabilities', name: 'Vulnerabilidades del Sistema', description: 'Analiza configuraciones inseguras' },
            { id: 'web_vulnerabilities', name: 'Vulnerabilidades Web', description: 'OWASP Top 10, XSS, SQLi' },
            { id: 'malware_analysis', name: 'Análisis de Malware', description: 'Detección de malware y virus' },
            { id: 'network_scanner', name: 'Escáner de Red', description: 'Descubre hosts y puertos' },
            { id: 'osint_module', name: 'OSINT', description: 'Información pública del objetivo' }
        ];
        
        const container = document.getElementById('modulesList');
        if (!container) return;
        container.innerHTML = '';
        
        modules.forEach(module => {
            const div = document.createElement('div');
            div.className = 'module-item';
            div.innerHTML = `
                <input type="checkbox" id="mod_${module.id}" value="${module.id}" checked>
                <div class="module-info">
                    <div class="module-name">${module.name}</div>
                    <div class="module-desc">${module.description}</div>
                </div>
            `;
            container.appendChild(div);
        });
        
    } catch (error) {
        console.error('Error loading modules:', error);
    }
}

// Función auxiliar segura para notificaciones
function triggerNotify(msg, type) {
    if (window.showNotification) {
        window.showNotification(msg, type);
    } else {
        alert(msg); // Fallback si la función no existe
    }
}

// Configurar eventos de escaneo
function setupScanEvents() {
    const startBtn = document.getElementById('startScanBtn');
    if (startBtn) startBtn.addEventListener('click', startScan);
    
    const targetType = document.getElementById('targetType');
    if (targetType) {
        targetType.addEventListener('change', function() {
            const type = this.value;
            const input = document.getElementById('target');
            
            const placeholders = {
                'ip': '192.168.1.1',
                'domain': 'ejemplo.com',
                'url': 'https://ejemplo.com',
                'network': '192.168.1.0/24',
                'file': '/ruta/al/archivo'
            };
            
            input.placeholder = placeholders[type] || 'Ingrese el objetivo';
        });
    }
}

// Iniciar escaneo
async function startScan() {
    const target = document.getElementById('target').value;
    if (!target) {
        triggerNotify('Por favor ingrese un objetivo', 'error');
        return;
    }
    
    const modules = [];
    document.querySelectorAll('#modulesList input:checked').forEach(cb => {
        modules.push(cb.value);
    });
    
    if (modules.length === 0) {
        triggerNotify('Seleccione al menos un módulo', 'error');
        return;
    }
    
    document.getElementById('scanProgress').style.display = 'block';
    document.getElementById('startScanBtn').disabled = true;
    
    try {
        const response = await fetch('/api/scan/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: target,
                type: document.getElementById('targetType').value,
                modules: modules,
                useAI: document.getElementById('useAI').checked,
                deepScan: document.getElementById('deepScan').checked
            })
        });
        
        const data = await response.json();
        const scanId = data.scan_id;
        
        const interval = setInterval(async () => {
            const statusResponse = await fetch(`/api/scan/status/${scanId}`);
            const statusData = await statusResponse.json();
            
            // Normalizar estado a minúsculas para evitar errores de comparación
            const currentStatus = (statusData.status || '').toLowerCase();

            document.getElementById('progressFill').style.width = `${statusData.progress || 0}%`;
            document.getElementById('progressStatus').textContent = 
                `Progreso: ${statusData.progress || 0}% - Estado: ${statusData.status}`;
            
            if (currentStatus === 'completed' || currentStatus === 'failed') {
                clearInterval(interval);
                document.getElementById('startScanBtn').disabled = false;
                
                if (currentStatus === 'completed') {
                    triggerNotify('Escaneo completado con éxito', 'success');
                    
                    setTimeout(() => {
                        if (window.navigateTo) {
                            window.navigateTo('results.html');
                        } else {
                            window.location.href = 'results.html';
                        }
                    }, 1200);
                } else {
                    triggerNotify('El escaneo ha fallado', 'error');
                }
            }
        }, 2000);
        
    } catch (error) {
        console.error('Error starting scan:', error);
        triggerNotify('Error al iniciar escaneo', 'error');
        document.getElementById('scanProgress').style.display = 'none';
        document.getElementById('startScanBtn').disabled = false;
    }
}

// Inicializar si estamos en la página de escaneo
document.addEventListener('DOMContentLoaded', function() {
    if (document.querySelector('.scan-page') || document.getElementById('modulesList')) {
        initScanPage();
    }
});
