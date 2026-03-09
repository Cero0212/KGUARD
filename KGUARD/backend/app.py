import os
import json
import logging
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from config import Config
from core.scanner_engine import ScannerEngine
from core.service_controller import ServiceController
from database.db_manager import DatabaseManager

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s — %(message)s'
)
logger = logging.getLogger(__name__)

SETTINGS_FILE = Path(Config.DATA_DIR) / 'settings.json'


def _load_settings() -> dict:
    if SETTINGS_FILE.exists():
        try:
            return json.loads(SETTINGS_FILE.read_text())
        except Exception:
            pass
    return {}


def _apply_settings(settings: dict):
    vt = settings.get('virustotal_api_key', '')
    if vt:
        os.environ['VIRUSTOTAL_API_KEY'] = vt
        Config.VIRUSTOTAL_API_KEY = vt


# Aplicar settings guardados al arrancar
_apply_settings(_load_settings())

app = Flask(__name__, static_folder='../frontend', static_url_path='')
CORS(app)

_scanner = ScannerEngine()
_service = ServiceController()
_db = DatabaseManager()


@app.route('/')
def index():
    return send_from_directory('../frontend', 'index.html')


@app.route('/<path:path>')
def static_files(path):
    return send_from_directory('../frontend', path)


@app.route('/api/status')
def api_status():
    return jsonify({
        'status': 'active' if _service.is_running() else 'inactive',
        'uptime': _service.get_uptime(),
        'scans_today': _db.get_scans_count_today()
    })


@app.route('/api/activate', methods=['POST'])
def api_activate():
    try:
        _service.start()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/deactivate', methods=['POST'])
def api_deactivate():
    try:
        _service.stop()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/scan/start', methods=['POST'])
def api_scan_start():
    data = request.get_json() or {}
    target = (data.get('target') or '').strip()
    scan_type = data.get('type', 'manual')
    modules = data.get('modules', [])

    if not target:
        return jsonify({'error': 'Target is required'}), 400
    if not modules:
        return jsonify({'error': 'Select at least one module'}), 400

    scan_id = _scanner.start_scan(target, scan_type, modules)
    return jsonify({'scan_id': scan_id, 'status': 'started'})


@app.route('/api/scan/status/<scan_id>')
def api_scan_status(scan_id):
    return jsonify(_scanner.get_status(scan_id))


@app.route('/api/scan/results/<scan_id>')
def api_scan_results(scan_id):
    result = _scanner.get_results(scan_id)
    if not result:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(result)


@app.route('/api/scans')
def api_scans():
    return jsonify(_db.get_all_scans())


@app.route('/api/scans/<scan_id>', methods=['DELETE'])
def api_delete_scan(scan_id):
    _db.delete_scan(scan_id)
    return jsonify({'success': True})


@app.route('/api/scans/clear', methods=['POST'])
def api_clear_scans():
    _db.clear_all_scans()
    return jsonify({'success': True})


@app.route('/api/dashboard/metrics')
def api_metrics():
    return jsonify(_db.get_dashboard_metrics())


@app.route('/api/threats/update', methods=['POST'])
def api_threats_update():
    from database.threat_intel_updater import ThreatIntelUpdater
    result = ThreatIntelUpdater().update_all()
    return jsonify(result)


@app.route('/api/cve/search')
def api_cve_search():
    query = request.args.get('q', '').strip()
    if not query:
        return jsonify([])
    return jsonify(_db.search_cve(query))


@app.route('/api/vulnerabilities')
def api_vulnerabilities():
    category = request.args.get('category')
    return jsonify(_db.get_vuln_signatures(category))


@app.route('/api/settings', methods=['GET'])
def api_settings_get():
    settings = _load_settings()
    vt = settings.get('virustotal_api_key', '')
    return jsonify({
        'virustotal_api_key': '••••••••' if vt else '',
        'virustotal_configured': bool(vt),
        'scan_timeout': settings.get('scan_timeout', 300),
        'max_concurrent': settings.get('max_concurrent', 3),
    })


@app.route('/api/settings', methods=['POST'])
def api_settings_save():
    data = request.get_json() or {}
    settings = _load_settings()

    vt_key = data.get('virustotal_api_key')
    if vt_key is not None:
        if vt_key and '•' not in vt_key:
            settings['virustotal_api_key'] = vt_key
        elif vt_key == '':
            settings.pop('virustotal_api_key', None)
            os.environ.pop('VIRUSTOTAL_API_KEY', None)
            Config.VIRUSTOTAL_API_KEY = ''

    if 'scan_timeout' in data:
        settings['scan_timeout'] = int(data['scan_timeout'])
    if 'max_concurrent' in data:
        settings['max_concurrent'] = int(data['max_concurrent'])

    SETTINGS_FILE.write_text(json.dumps(settings, indent=2))
    _apply_settings(settings)

    return jsonify({'success': True, 'virustotal_configured': bool(settings.get('virustotal_api_key'))})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=Config.PORT, debug=False)
