import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    SCANS_DIR = BASE_DIR / 'scans'
    DATA_DIR = BASE_DIR / 'data'
    DB_PATH = DATA_DIR / 'threats.db'
    MALWARE_DB_PATH = DATA_DIR / 'malware_signatures.db'
    CACHE_DIR = DATA_DIR / 'cache'
    LOGS_DIR = BASE_DIR / 'logs'

    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')

    SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', 300))
    MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', 3))
    PORT = int(os.environ.get('PORT', 1717))

    for _dir in (SCANS_DIR, DATA_DIR, CACHE_DIR, LOGS_DIR):
        _dir.mkdir(parents=True, exist_ok=True)
