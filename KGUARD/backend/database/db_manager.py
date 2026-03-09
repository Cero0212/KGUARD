import sqlite3
import json
from datetime import datetime, date
from typing import List, Dict, Any, Optional
from contextlib import contextmanager
from pathlib import Path
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import Config


class DatabaseManager:
    def __init__(self):
        self.db_path = str(Config.DB_PATH)
        self._init_database()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_database(self):
        with self._conn() as conn:
            c = conn.cursor()

            c.execute('''CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                type TEXT,
                start_time TEXT,
                end_time TEXT,
                findings_count INTEGER DEFAULT 0,
                summary TEXT DEFAULT '{}',
                file_path TEXT
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                title TEXT,
                description TEXT,
                severity TEXT DEFAULT 'info',
                remediation TEXT,
                evidence TEXT,
                created_at TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS malware_signatures (
                hash TEXT PRIMARY KEY,
                name TEXT,
                type TEXT,
                added_date TEXT
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS cve_database (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                published TEXT,
                ref_links TEXT,
                affected_software TEXT
            )''')

            c.execute('''CREATE TABLE IF NOT EXISTS vuln_signatures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT,
                severity TEXT,
                description TEXT,
                detection_pattern TEXT,
                remediation TEXT,
                ref_links TEXT,
                source TEXT
            )''')

            conn.commit()

    def save_scan(self, scan_data: Dict[str, Any]):
        with self._conn() as conn:
            c = conn.cursor()
            c.execute(
                'INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?)',
                (
                    scan_data['scan_id'],
                    scan_data.get('target', ''),
                    scan_data.get('type', ''),
                    scan_data.get('start_time', ''),
                    scan_data.get('end_time', ''),
                    len(scan_data.get('findings', [])),
                    json.dumps(scan_data.get('summary', {})),
                    f"scans/scan_{scan_data['scan_id']}.json"
                )
            )
            for f in scan_data.get('findings', []):
                c.execute(
                    '''INSERT INTO findings
                       (scan_id, title, description, severity, remediation, evidence, created_at)
                       VALUES (?,?,?,?,?,?,?)''',
                    (
                        scan_data['scan_id'],
                        f.get('title', ''),
                        f.get('description', ''),
                        f.get('severity', 'info'),
                        f.get('remediation', ''),
                        json.dumps(f),
                        datetime.now().isoformat()
                    )
                )
            conn.commit()

    def get_all_scans(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                'SELECT * FROM scans ORDER BY start_time DESC'
            ).fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d['summary'] = json.loads(d.get('summary') or '{}')
                result.append(d)
            return result

    def get_scan_findings(self, scan_id: str) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                'SELECT * FROM findings WHERE scan_id = ? ORDER BY severity',
                (scan_id,)
            ).fetchall()
            result = []
            for row in rows:
                d = dict(row)
                try:
                    d['evidence'] = json.loads(d.get('evidence') or '{}')
                except Exception:
                    d['evidence'] = {}
                result.append(d)
            return result

    def get_scans_count_today(self) -> int:
        today = date.today().isoformat()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM scans WHERE start_time LIKE ?",
                (f"{today}%",)
            ).fetchone()
            return row[0] if row else 0

    def delete_scan(self, scan_id: str):
        with self._conn() as conn:
            conn.execute('DELETE FROM findings WHERE scan_id = ?', (scan_id,))
            conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
            conn.commit()

    def clear_all_scans(self):
        with self._conn() as conn:
            conn.execute('DELETE FROM findings')
            conn.execute('DELETE FROM scans')
            conn.commit()

    def get_dashboard_metrics(self) -> Dict:
        with self._conn() as conn:
            total = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
            rows = conn.execute(
                'SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity'
            ).fetchall()
            severity = {r['severity']: r['cnt'] for r in rows}
            today_count = self.get_scans_count_today()
            return {
                'total_scans': total,
                'scans_today': today_count,
                'findings': severity
            }

    def add_malware_signatures(self, signatures: List[Dict]):
        with self._conn() as conn:
            conn.executemany(
                'INSERT OR IGNORE INTO malware_signatures VALUES (?,?,?,?)',
                [(s['hash'], s['name'], s['type'], datetime.now().isoformat()) for s in signatures]
            )
            conn.commit()

    def lookup_malware_hash(self, file_hash: str) -> Optional[Dict]:
        with self._conn() as conn:
            row = conn.execute(
                'SELECT name, type FROM malware_signatures WHERE hash = ?',
                (file_hash,)
            ).fetchone()
            return dict(row) if row else None

    def save_cves(self, cves: List[Dict]):
        with self._conn() as conn:
            conn.executemany(
                '''INSERT OR REPLACE INTO cve_database
                   (cve_id, description, cvss_score, severity, published, ref_links, affected_software)
                   VALUES (?,?,?,?,?,?,?)''',
                [(
                    c.get('id', ''),
                    c.get('summary', ''),
                    c.get('cvss', 0.0),
                    c.get('severity', 'unknown'),
                    c.get('Published', ''),
                    json.dumps(c.get('references', [])),
                    json.dumps(c.get('vulnerable_configuration', []))
                ) for c in cves]
            )
            conn.commit()

    def get_cve_count(self) -> int:
        with self._conn() as conn:
            return conn.execute('SELECT COUNT(*) FROM cve_database').fetchone()[0]

    def search_cve(self, query: str) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                '''SELECT cve_id, description, cvss_score, severity, published
                   FROM cve_database
                   WHERE cve_id LIKE ? OR description LIKE ?
                   ORDER BY cvss_score DESC LIMIT 20''',
                (f'%{query}%', f'%{query}%')
            ).fetchall()
            return [dict(r) for r in rows]

    def save_vuln_signatures(self, sigs: List[Dict]):
        with self._conn() as conn:
            conn.executemany(
                '''INSERT OR IGNORE INTO vuln_signatures
                   (name, category, severity, description, detection_pattern, remediation, ref_links, source)
                   VALUES (?,?,?,?,?,?,?,?)''',
                [(
                    s.get('name', ''),
                    s.get('category', ''),
                    s.get('severity', 'medium'),
                    s.get('description', ''),
                    s.get('detection_pattern', ''),
                    s.get('remediation', ''),
                    json.dumps(s.get('references', [])),
                    s.get('source', '')
                ) for s in sigs]
            )
            conn.commit()

    def get_vuln_signatures(self, category: str = None) -> List[Dict]:
        with self._conn() as conn:
            if category:
                rows = conn.execute(
                    'SELECT * FROM vuln_signatures WHERE category = ?', (category,)
                ).fetchall()
            else:
                rows = conn.execute('SELECT * FROM vuln_signatures').fetchall()
            return [dict(r) for r in rows]
