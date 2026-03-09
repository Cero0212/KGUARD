const API = '';

const Pages = {
  dashboard: { title: 'Dashboard',  render: renderDashboard },
  scan:      { title: 'New Scan',   render: renderScan },
  results:   { title: 'Results',    render: renderResults },
  settings:  { title: 'Settings',   render: renderSettings },
};

let currentPage = 'dashboard';
let serviceActive = false;

document.addEventListener('DOMContentLoaded', () => {
  refreshStatus();
  setInterval(refreshStatus, 30000);
  navigate('dashboard');
});

async function refreshStatus() {
  try {
    const d = await api('/api/status');
    serviceActive = d.status === 'active';
    const dot = document.getElementById('serviceDot');
    const txt = document.getElementById('serviceText');
    const btn = document.getElementById('btnActivate');
    if (dot)  dot.className = 'dot' + (serviceActive ? ' active' : '');
    if (txt)  txt.textContent = serviceActive ? `Active` : 'Inactive';
    if (btn)  btn.textContent = serviceActive ? 'Deactivate' : 'Activate';
    const st = document.getElementById('scansToday');
    if (st) st.textContent = d.scans_today ?? 0;
  } catch { /* server not running yet */ }
}

async function toggleService() {
  const endpoint = serviceActive ? '/api/deactivate' : '/api/activate';
  try {
    await api(endpoint, { method: 'POST' });
    await refreshStatus();
    toast(serviceActive ? 'Service deactivated' : 'Service activated', 'success');
  } catch (e) {
    toast(e.message, 'error');
  }
}

function navigate(page) {
  if (!Pages[page]) return;
  currentPage = page;
  document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
  const navEl = document.getElementById(`nav-${page}`);
  if (navEl) navEl.classList.add('active');
  const titleEl = document.getElementById('topbarTitle');
  if (titleEl) titleEl.textContent = Pages[page].title;
  document.getElementById('pageContent').innerHTML = '';
  Pages[page].render();
}

async function api(path, opts = {}) {
  const res = await fetch(API + path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

function toast(msg, type = 'info') {
  const c = document.getElementById('toastContainer');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  const icons = { success: '✓', error: '✗', info: 'i' };
  t.innerHTML = `<span>${icons[type] || 'i'}</span><span>${msg}</span>`;
  c.appendChild(t);
  setTimeout(() => t.remove(), 3500);
}

function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${sev}</span>`;
}

function fmtDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return isNaN(d) ? ts : d.toLocaleString();
}


/* ═══════════════════════════════════════════
   DASHBOARD
═══════════════════════════════════════════ */
async function renderDashboard() {
  document.getElementById('pageContent').innerHTML = `
    <div class="page-header">
      <h1>Dashboard</h1>
      <p>Overview of security findings and recent activity</p>
    </div>
    <div class="stats-grid" id="statsGrid">
      ${['total','critical','high','medium','low','info'].map(s => `
        <div class="stat-card ${s}">
          <div class="stat-label">${s === 'total' ? 'Total Scans' : s}</div>
          <div class="stat-value" id="stat-${s}">—</div>
        </div>`).join('')}
    </div>
    <div class="card">
      <div class="card-title">Recent Scans</div>
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th>Target</th><th>Type</th><th>Date</th>
            <th>Findings</th><th>Risk</th><th></th>
          </tr></thead>
          <tbody id="recentBody"></tbody>
        </table>
      </div>
    </div>
    <div class="flex gap-8 mt-16">
      <button class="btn btn-ghost btn-sm" onclick="clearHistory()">Clear History</button>
      <button class="btn btn-ghost btn-sm" onclick="updateThreats()">↻ Update Threat DB</button>
    </div>`;

  await loadDashboardData();
}

async function loadDashboardData() {
  try {
    const metrics = await api('/api/dashboard/metrics');
    document.getElementById('stat-total').textContent    = metrics.total_scans ?? 0;
    document.getElementById('stat-critical').textContent = metrics.findings?.critical ?? 0;
    document.getElementById('stat-high').textContent     = metrics.findings?.high ?? 0;
    document.getElementById('stat-medium').textContent   = metrics.findings?.medium ?? 0;
    document.getElementById('stat-low').textContent      = metrics.findings?.low ?? 0;
    document.getElementById('stat-info').textContent     = metrics.findings?.info ?? 0;
  } catch { }

  try {
    const scans = await api('/api/scans');
    const tbody = document.getElementById('recentBody');
    if (!tbody) return;
    if (!scans.length) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:32px">No scans yet. Start a new scan.</td></tr>`;
      return;
    }
    tbody.innerHTML = scans.slice(0, 10).map(s => {
      const summary = s.summary || {};
      const top = ['critical','high','medium'].filter(k => summary[k] > 0).map(k =>
        `<span class="badge badge-${k}">${summary[k]} ${k}</span>`).join(' ');
      return `<tr onclick="goToScan('${s.id}')">
        <td><span style="color:var(--text-primary)">${s.target}</span></td>
        <td>${s.type || '—'}</td>
        <td>${fmtDate(s.start_time)}</td>
        <td>${s.findings_count ?? 0}</td>
        <td>${top || '<span class="text-muted">—</span>'}</td>
        <td><button class="btn btn-ghost btn-sm" onclick="event.stopPropagation();goToScan('${s.id}')">View</button></td>
      </tr>`;
    }).join('');
  } catch { }
}

function goToScan(id) {
  navigate('results');
  setTimeout(() => loadScanDetail(id), 100);
}

async function clearHistory() {
  if (!confirm('Delete all scan history?')) return;
  await api('/api/scans/clear', { method: 'POST' });
  toast('History cleared', 'success');
  loadDashboardData();
}

async function updateThreats() {
  toast('Updating threat intelligence…', 'info');
  try {
    const r = await api('/api/threats/update', { method: 'POST' });
    const msgs = [];
    if (r.signatures?.message) msgs.push(r.signatures.message);
    if (r.cves?.message)       msgs.push(r.cves.message);
    toast(msgs.join(' · ') || 'Done', 'success');
  } catch (e) {
    toast(e.message, 'error');
  }
}


/* ═══════════════════════════════════════════
   NEW SCAN
═══════════════════════════════════════════ */
const MODULES = [
  { id: 'system_vulnerabilities', name: 'System Vulnerabilities', desc: 'OS config, patch level, SUID, firewall' },
  { id: 'web_vulnerabilities',    name: 'Web Vulnerabilities',    desc: 'OWASP Top 10, headers, injection' },
  { id: 'malware_analysis',       name: 'Malware Analysis',       desc: 'Hash-based and heuristic detection' },
  { id: 'network_scanner',        name: 'Network Scanner',        desc: 'Port scan, service fingerprinting' },
  { id: 'osint_module',           name: 'OSINT',                  desc: 'DNS, IP reputation, digital exposure' },
];

const TARGET_PLACEHOLDERS = {
  ip:      '192.168.1.1',
  domain:  'example.com',
  url:     'https://example.com',
  network: '192.168.1.0/24',
  file:    '/path/to/file',
};

function renderScan() {
  document.getElementById('pageContent').innerHTML = `
    <div class="page-header">
      <h1>New Scan</h1>
      <p>Configure and launch a security assessment</p>
    </div>
    <div class="grid-2">
      <div>
        <div class="card">
          <div class="form-group">
            <label class="form-label">Target Type</label>
            <select class="form-control" id="targetType" onchange="updatePlaceholder()">
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="url">URL</option>
              <option value="network">Network (CIDR)</option>
              <option value="file">File Path</option>
            </select>
          </div>
          <div class="form-group">
            <label class="form-label">Target</label>
            <input class="form-control" type="text" id="target" placeholder="192.168.1.1">
          </div>
          <div class="form-group">
            <label class="form-label">Scan Modules</label>
            <div class="checkbox-grid" id="modulesList"></div>
          </div>
          <div class="flex gap-8 mt-16">
            <button class="btn btn-primary" id="startBtn" onclick="startScan()" style="flex:1">
              ▶ Start Scan
            </button>
          </div>
        </div>
      </div>
      <div>
        <div class="card" id="scanProgressCard" style="display:none">
          <div class="card-title">Scan Progress</div>
          <p id="progressTarget" style="color:var(--text-secondary);margin-bottom:12px;font-size:12px"></p>
          <div class="progress-track">
            <div class="progress-fill" id="progressBar" style="width:0%"></div>
          </div>
          <p id="progressStatus" style="color:var(--text-muted);font-size:11px;margin-top:6px">Initializing…</p>
        </div>
        <div class="card mt-16">
          <div class="card-title">Module Reference</div>
          <div id="moduleRef" style="font-size:12px;color:var(--text-secondary)"></div>
        </div>
      </div>
    </div>`;

  const ml = document.getElementById('modulesList');
  const mr = document.getElementById('moduleRef');
  MODULES.forEach(m => {
    const div = document.createElement('div');
    div.className = 'check-item checked';
    div.dataset.id = m.id;
    div.innerHTML = `<input type="checkbox" checked><div class="check-box">✓</div>
      <div class="check-label"><div class="check-name">${m.name}</div><div class="check-desc">${m.desc}</div></div>`;
    div.onclick = () => {
      div.classList.toggle('checked');
      div.querySelector('.check-box').textContent = div.classList.contains('checked') ? '✓' : '';
      div.querySelector('input').checked = div.classList.contains('checked');
    };
    ml.appendChild(div);

    mr.innerHTML += `<div style="margin-bottom:10px;padding:8px;background:var(--bg-raised);border-radius:4px;">
      <div style="color:var(--text-primary);margin-bottom:2px">${m.name}</div>
      <div style="color:var(--text-muted)">${m.desc}</div>
    </div>`;
  });
}

function updatePlaceholder() {
  const type = document.getElementById('targetType').value;
  document.getElementById('target').placeholder = TARGET_PLACEHOLDERS[type] || '';
}

async function startScan() {
  const target = document.getElementById('target').value.trim();
  if (!target) { toast('Enter a target', 'error'); return; }

  const modules = [...document.querySelectorAll('#modulesList .check-item.checked')].map(d => d.dataset.id);
  if (!modules.length) { toast('Select at least one module', 'error'); return; }

  document.getElementById('startBtn').disabled = true;
  document.getElementById('scanProgressCard').style.display = 'block';
  document.getElementById('progressTarget').textContent = `Target: ${target}`;

  try {
    const { scan_id } = await api('/api/scan/start', {
      method: 'POST',
      body: { target, type: document.getElementById('targetType').value, modules }
    });

    const poll = setInterval(async () => {
      const s = await api(`/api/scan/status/${scan_id}`);
      const pct = s.progress || 0;
      document.getElementById('progressBar').style.width = pct + '%';
      document.getElementById('progressStatus').textContent =
        `${pct}% — ${s.current_module ? s.current_module.replace(/_/g, ' ') : s.status}`;

      if (s.status === 'completed') {
        clearInterval(poll);
        toast('Scan complete', 'success');
        setTimeout(() => { navigate('results'); setTimeout(() => loadScanDetail(scan_id), 150); }, 800);
      } else if (s.status === 'failed') {
        clearInterval(poll);
        toast(`Scan failed: ${s.error || 'unknown error'}`, 'error');
        document.getElementById('startBtn').disabled = false;
      }
    }, 1500);

  } catch (e) {
    toast(e.message, 'error');
    document.getElementById('startBtn').disabled = false;
  }
}


/* ═══════════════════════════════════════════
   RESULTS
═══════════════════════════════════════════ */
let _scans = [];
let _activeScanId = null;

async function renderResults() {
  document.getElementById('pageContent').innerHTML = `
    <div class="page-header">
      <h1>Results</h1>
      <p>Browse scan history and detailed findings</p>
    </div>
    <div style="display:grid;grid-template-columns:280px 1fr;gap:16px;align-items:start">
      <div class="card" style="padding:0">
        <div style="padding:12px 16px;border-bottom:1px solid var(--border)">
          <input class="form-control" type="text" placeholder="Filter scans…" id="scanFilter"
            oninput="filterScans()" style="margin:0">
        </div>
        <div id="scanList" style="max-height:70vh;overflow-y:auto"></div>
      </div>
      <div id="scanDetail"></div>
    </div>`;

  await loadResultsList();
}

async function loadResultsList() {
  try {
    _scans = await api('/api/scans');
    renderScanList(_scans);
  } catch (e) {
    toast(e.message, 'error');
  }
}

function renderScanList(scans) {
  const el = document.getElementById('scanList');
  if (!el) return;
  if (!scans.length) {
    el.innerHTML = `<div class="empty-state"><div class="icon">◎</div><p>No scans yet</p></div>`;
    return;
  }
  el.innerHTML = scans.map(s => {
    const summary = s.summary || {};
    const badges = ['critical','high','medium'].filter(k => summary[k] > 0)
      .map(k => `<span class="badge badge-${k}">${summary[k]}</span>`).join('');
    return `<div class="scan-row ${s.id === _activeScanId ? 'active' : ''}" onclick="loadScanDetail('${s.id}')">
      <div style="flex:1;min-width:0">
        <div class="scan-target" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${s.target}</div>
        <div class="scan-meta">${fmtDate(s.start_time)} · ${s.findings_count} findings</div>
      </div>
      <div class="scan-badges">${badges}</div>
    </div>`;
  }).join('');
}

function filterScans() {
  const q = document.getElementById('scanFilter').value.toLowerCase();
  renderScanList(_scans.filter(s => s.target.toLowerCase().includes(q) || (s.type || '').includes(q)));
}

async function loadScanDetail(scanId) {
  _activeScanId = scanId;
  renderScanList(_scans);

  const el = document.getElementById('scanDetail');
  if (!el) return;
  el.innerHTML = `<div class="card"><p style="color:var(--text-muted);text-align:center;padding:32px">Loading…</p></div>`;

  try {
    const scan = await api(`/api/scan/results/${scanId}`);
    const findings = scan.findings || [];
    const summary = scan.summary || {};

    const summaryBadges = ['critical','high','medium','low','info']
      .filter(k => (summary[k] || 0) > 0)
      .map(k => `<div class="stat-card ${k}" style="padding:12px;flex:1;min-width:80px">
        <div class="stat-label">${k}</div>
        <div class="stat-value" style="font-size:24px">${summary[k]}</div>
      </div>`).join('');

    el.innerHTML = `
      <div class="card" style="margin-bottom:12px">
        <div class="flex-center gap-8" style="margin-bottom:16px;flex-wrap:wrap">
          <div style="flex:1">
            <div style="font-family:var(--font-display);font-size:16px;color:var(--text-primary)">${scan.target}</div>
            <div style="font-size:11px;color:var(--text-muted)">${fmtDate(scan.start_time)}${scan.end_time ? ' → ' + fmtDate(scan.end_time) : ''}</div>
          </div>
          <div class="flex gap-8">
            <button class="btn btn-ghost btn-sm" onclick="exportScan('${scanId}','json')">JSON</button>
            <button class="btn btn-ghost btn-sm" onclick="exportScan('${scanId}','html')">HTML</button>
            <button class="btn btn-ghost btn-sm" onclick="exportScan('${scanId}','pdf')">PDF</button>
            <button class="btn btn-danger btn-sm" onclick="deleteScan('${scanId}')">Delete</button>
          </div>
        </div>
        <div class="flex gap-8" style="flex-wrap:wrap">${summaryBadges}</div>
      </div>
      <div id="findingsContainer"></div>`;

    window._currentScan = scan;

    const fc = document.getElementById('findingsContainer');
    if (!findings.length) {
      fc.innerHTML = `<div class="empty-state"><div class="icon">✓</div><p>No findings — clean scan</p></div>`;
      return;
    }

    const order = ['critical','high','medium','low','info'];
    const sorted = [...findings].sort((a, b) =>
      order.indexOf(a.severity) - order.indexOf(b.severity));

    fc.innerHTML = sorted.map((f, i) => `
      <div class="finding-card ${f.severity}">
        <div class="finding-header" onclick="toggleFinding(${i})">
          <span class="finding-title">${f.title || 'Unnamed finding'}</span>
          <div class="flex-center gap-8">
            ${f.category ? `<span style="font-size:10px;color:var(--text-muted)">${f.category}</span>` : ''}
            ${severityBadge(f.severity || 'info')}
            <span id="chevron-${i}" style="color:var(--text-muted);font-size:10px">▼</span>
          </div>
        </div>
        <div class="finding-body" id="finding-body-${i}">
          <p>${f.description || ''}</p>
          ${f.remediation ? `<div class="finding-remediation"><strong>Remediation</strong>${f.remediation}</div>` : ''}
          ${f.url || f.host ? `<p style="margin-top:8px;font-size:11px"><span style="color:var(--text-muted)">Target:</span> ${f.url || f.host}${f.port ? ':' + f.port : ''}</p>` : ''}
        </div>
      </div>`).join('');

  } catch (e) {
    document.getElementById('scanDetail').innerHTML =
      `<div class="card"><p style="color:var(--critical)">Error: ${e.message}</p></div>`;
  }
}

function toggleFinding(i) {
  const body = document.getElementById(`finding-body-${i}`);
  const ch = document.getElementById(`chevron-${i}`);
  const open = body.classList.toggle('open');
  if (ch) ch.textContent = open ? '▲' : '▼';
}

async function deleteScan(scanId) {
  if (!confirm('Delete this scan?')) return;
  await api(`/api/scans/${scanId}`, { method: 'DELETE' });
  toast('Scan deleted', 'success');
  _activeScanId = null;
  document.getElementById('scanDetail').innerHTML = '';
  await loadResultsList();
}

async function exportScan(scanId, format) {
  const scan = window._currentScan;
  if (!scan) return;

  const name = `KGUARD_${scan.target.replace(/[^a-z0-9]/gi,'_')}_${scanId.slice(0,8)}`;
  const findings = scan.findings || [];

  if (format === 'json') {
    dlBlob(JSON.stringify(scan, null, 2), `${name}.json`, 'application/json');
  } else if (format === 'html') {
    const rows = findings.map(f => `
      <div style="border-left:3px solid var(--${f.severity});padding:12px;margin:8px 0;background:#1a1a1a;border-radius:4px">
        <strong style="color:#eee">${f.title}</strong>
        <span style="float:right;font-size:12px;opacity:.7">${f.severity}</span>
        <p style="color:#aaa;margin:6px 0">${f.description || ''}</p>
        ${f.remediation ? `<p style="color:#6ecc9a;font-size:12px">↳ ${f.remediation}</p>` : ''}
      </div>`).join('');
    dlBlob(`<!DOCTYPE html><html><head><meta charset="UTF-8">
      <title>KGUARD Report — ${scan.target}</title>
      <style>body{font-family:monospace;background:#111;color:#ddd;padding:40px;max-width:900px;margin:0 auto}
      h1{color:#00d4ff} .meta{color:#777;font-size:13px;margin-bottom:24px}
      :root{--critical:#ff3b5c;--high:#ff7b00;--medium:#f5c518;--low:#22d3a5;--info:#4b9eff}</style>
      </head><body>
      <h1>KGUARD Security Report</h1>
      <div class="meta">Target: ${scan.target} · Date: ${fmtDate(scan.start_time)} · Findings: ${findings.length}</div>
      ${rows}</body></html>`, `${name}.html`, 'text/html');
  } else if (format === 'pdf') {
    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();
    doc.setFontSize(18);
    doc.setTextColor(0, 212, 255);
    doc.text('KGUARD Security Report', 14, 20);
    doc.setTextColor(150, 150, 150);
    doc.setFontSize(10);
    doc.text(`Target: ${scan.target}`, 14, 30);
    doc.text(`Date: ${fmtDate(scan.start_time)}`, 14, 36);
    doc.text(`Findings: ${findings.length}`, 14, 42);
    doc.autoTable({
      startY: 50,
      head: [['Title', 'Severity', 'Description']],
      body: findings.map(f => [f.title, f.severity, (f.description || '').slice(0, 100)]),
      styles: { fontSize: 8, cellPadding: 3 },
      headStyles: { fillColor: [20, 27, 34], textColor: [0, 212, 255] },
      alternateRowStyles: { fillColor: [14, 19, 24] },
    });
    doc.save(`${name}.pdf`);
  }
}

function dlBlob(content, name, mime) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([content], { type: mime }));
  a.download = name;
  a.click();
}


/* ═══════════════════════════════════════════
   SETTINGS
═══════════════════════════════════════════ */
function renderSettings() {
  document.getElementById('pageContent').innerHTML = `
    <div class="page-header">
      <h1>Settings</h1>
      <p>Configura el comportamiento del escáner e integraciones</p>
    </div>

    <div class="settings-section">
      <h2>Servicio</h2>
      <div class="form-group">
        <label class="form-label">Puerto</label>
        <input class="form-control" type="number" value="1717" disabled style="max-width:140px">
        <div class="form-hint">El puerto no se puede cambiar mientras el servicio está activo.</div>
      </div>
    </div>

    <div class="settings-section">
      <h2>Valores por defecto del escaneo</h2>
      <div class="grid-2">
        <div class="form-group">
          <label class="form-label">Timeout (segundos)</label>
          <input class="form-control" type="number" id="cfgTimeout" value="300">
        </div>
        <div class="form-group">
          <label class="form-label">Escaneos concurrentes máx.</label>
          <input class="form-control" type="number" id="cfgConcurrent" value="3" min="1" max="10">
        </div>
      </div>
    </div>

    <div class="settings-section">
      <h2>API Integrations</h2>
      <div class="form-group">
        <label class="form-label" style="display:flex;align-items:center;gap:10px">
          VirusTotal API Key
          <span id="vtStatus" style="font-size:11px;font-weight:normal"></span>
        </label>
        <div style="display:flex;gap:8px">
          <input class="form-control" type="password" id="cfgVtKey"
            placeholder="Pega tu API key aquí para configurarla">
          <button class="btn btn-ghost btn-sm" onclick="toggleVtVisibility()" title="Mostrar / ocultar" style="padding:8px 12px;flex-shrink:0">👁</button>
        </div>
        <div id="vtHint" class="form-hint">
          Necesaria para consultas de hash en el análisis de malware. Se guarda de forma persistente.
        </div>
      </div>
    </div>

    <div class="settings-section">
      <h2>Threat Intelligence</h2>
      <p style="color:var(--text-secondary);font-size:12px;margin-bottom:12px">
        Sincroniza CVEs desde circl.lu y carga firmas OWASP/CIS en la base de datos local.
      </p>
      <button class="btn btn-ghost" onclick="updateThreats()">↻ Sincronizar base de amenazas</button>
    </div>

    <div class="flex gap-8 mt-16">
      <button class="btn btn-primary" onclick="saveSettings()">Guardar configuración</button>
      <button class="btn btn-ghost" onclick="clearVtKey()" style="color:var(--critical);border-color:var(--critical)">Borrar API Key VT</button>
    </div>`;

  loadSettingsData();
}

/* ═══════════════════════════════════════════
   SETTINGS — carga y guarda desde el backend
═══════════════════════════════════════════ */
async function loadSettingsData() {
  try {
    const s = await api('/api/settings');
    const vtInput  = document.getElementById('cfgVtKey');
    const vtStatus = document.getElementById('vtStatus');
    const vtHint   = document.getElementById('vtHint');

    if (s.virustotal_configured) {
      if (vtInput)  { vtInput.value = ''; vtInput.placeholder = '••••••••  (guardada — escribe para reemplazar)'; }
      if (vtStatus) { vtStatus.textContent = '✓ Configurada'; vtStatus.style.color = 'var(--low)'; }
      if (vtHint)   vtHint.style.display = 'none';
    } else {
      if (vtInput)  vtInput.placeholder = 'Pega tu API key aquí';
      if (vtStatus) { vtStatus.textContent = '✗ No configurada'; vtStatus.style.color = 'var(--text-muted)'; }
    }

    const el = (id) => document.getElementById(id);
    if (el('cfgTimeout'))    el('cfgTimeout').value    = s.scan_timeout   ?? 300;
    if (el('cfgConcurrent')) el('cfgConcurrent').value = s.max_concurrent ?? 3;
  } catch { }
}

async function saveSettings() {
  const vtKey   = document.getElementById('cfgVtKey')?.value.trim()   || '';
  const timeout = document.getElementById('cfgTimeout')?.value         || '300';
  const conc    = document.getElementById('cfgConcurrent')?.value      || '3';

  const payload = {
    scan_timeout:  parseInt(timeout),
    max_concurrent: parseInt(conc),
  };
  if (vtKey && !vtKey.includes('•')) {
    payload.virustotal_api_key = vtKey;
  }

  try {
    await api('/api/settings', { method: 'POST', body: payload });
    toast('Configuración guardada', 'success');
    await loadSettingsData();
  } catch (e) {
    toast('Error al guardar: ' + e.message, 'error');
  }
}

async function clearVtKey() {
  if (!confirm('¿Eliminar la API Key de VirusTotal?')) return;
  try {
    await api('/api/settings', { method: 'POST', body: { virustotal_api_key: '' } });
    toast('API Key eliminada', 'info');
    await loadSettingsData();
  } catch (e) {
    toast(e.message, 'error');
  }
}

function toggleVtVisibility() {
  const input = document.getElementById('cfgVtKey');
  if (input) input.type = input.type === 'password' ? 'text' : 'password';
}
