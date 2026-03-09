import uuid
import threading
import importlib
import logging
from datetime import datetime

from config import Config
from database.db_manager import DatabaseManager
from ai.risk_classifier import RiskClassifier

logger = logging.getLogger(__name__)

MODULE_MAP = {
    'system_vulnerabilities': 'modules.system_vulnerabilities',
    'web_vulnerabilities':    'modules.web_vulnerabilities',
    'malware_analysis':       'modules.malware_analysis',
    'network_scanner':        'modules.network_scanner',
    'osint_module':           'modules.osint_module',
}


class ScannerEngine:
    def __init__(self):
        self._scans: dict = {}
        self._lock = threading.Lock()
        self.db = DatabaseManager()
        self.classifier = RiskClassifier()

    def start_scan(self, target: str, scan_type: str, modules: list) -> str | None:
        if not modules:
            return None

        scan_id = str(uuid.uuid4())
        with self._lock:
            self._scans[scan_id] = {
                'status': 'starting',
                'progress': 0,
                'target': target,
                'type': scan_type,
                'start_time': datetime.now().isoformat(),
                'current_module': None
            }

        t = threading.Thread(target=self._run, args=(scan_id, target, scan_type, modules), daemon=True)
        t.start()
        return scan_id

    def _run(self, scan_id: str, target: str, scan_type: str, modules: list):
        results = {
            'scan_id': scan_id,
            'target': target,
            'type': scan_type,
            'start_time': datetime.now().isoformat(),
            'findings': [],
            'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }

        try:
            for i, module_name in enumerate(modules):
                with self._lock:
                    if scan_id in self._scans:
                        self._scans[scan_id].update({
                            'status': 'running',
                            'progress': int((i / len(modules)) * 100),
                            'current_module': module_name
                        })

                for finding in self._run_module(module_name, target):
                    finding['severity'] = self.classifier.classify(finding)
                    sev = finding['severity']
                    if sev in results['summary']:
                        results['summary'][sev] += 1
                    results['findings'].append(finding)

            results['end_time'] = datetime.now().isoformat()
            self.db.save_scan(results)

            with self._lock:
                if scan_id in self._scans:
                    self._scans[scan_id].update({'status': 'completed', 'progress': 100})

        except Exception as e:
            logger.error(f"Scan {scan_id} failed: {e}")
            with self._lock:
                if scan_id in self._scans:
                    self._scans[scan_id].update({'status': 'failed', 'error': str(e)})

    def _run_module(self, module_name: str, target: str) -> list:
        path = MODULE_MAP.get(module_name)
        if not path:
            return []
        try:
            mod = importlib.import_module(path)
            importlib.reload(mod)
            return mod.scan(target) if hasattr(mod, 'scan') else []
        except Exception as e:
            logger.warning(f"Module {module_name} error: {e}")
            return [{'title': f'Module error: {module_name}', 'description': str(e), 'severity': 'info'}]

    def get_status(self, scan_id: str) -> dict:
        with self._lock:
            return dict(self._scans.get(scan_id, {'status': 'not_found'}))

    def get_results(self, scan_id: str) -> dict | None:
        scans = self.db.get_all_scans()
        for s in scans:
            if s['id'] == scan_id:
                s['findings'] = self.db.get_scan_findings(scan_id)
                return s
        return None
