import requests
import logging
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config import Config

logger = logging.getLogger(__name__)


BUILTIN_WEB_SIGNATURES = [
    {
        'name': 'SQL Injection',
        'category': 'web',
        'severity': 'critical',
        'description': 'Unsanitized user input passed directly into SQL queries allows attackers to read, modify or delete database data.',
        'detection_pattern': "' OR 1=1|UNION SELECT|--\\s|;DROP TABLE",
        'remediation': 'Use parameterized queries or prepared statements. Never concatenate user input into SQL strings.',
        'references': ['https://owasp.org/www-community/attacks/SQL_Injection', 'https://cwe.mitre.org/data/definitions/89.html'],
        'source': 'OWASP Top 10'
    },
    {
        'name': 'Cross-Site Scripting (XSS)',
        'category': 'web',
        'severity': 'high',
        'description': 'Reflected or stored scripts injected into pages allow attackers to hijack user sessions or deface sites.',
        'detection_pattern': '<script>|onerror=|onload=|javascript:|alert\\(',
        'remediation': 'Encode all user-supplied output. Implement a strict Content-Security-Policy header.',
        'references': ['https://owasp.org/www-community/attacks/xss/', 'https://cwe.mitre.org/data/definitions/79.html'],
        'source': 'OWASP Top 10'
    },
    {
        'name': 'Cross-Site Request Forgery (CSRF)',
        'category': 'web',
        'severity': 'high',
        'description': 'State-changing requests accepted without CSRF tokens allow attackers to perform actions on behalf of authenticated users.',
        'detection_pattern': 'missing csrf|no csrf token',
        'remediation': 'Implement synchronizer token pattern or SameSite cookie attribute.',
        'references': ['https://owasp.org/www-community/attacks/csrf', 'https://cwe.mitre.org/data/definitions/352.html'],
        'source': 'OWASP Top 10'
    },
    {
        'name': 'Missing Security Headers',
        'category': 'web',
        'severity': 'medium',
        'description': 'HTTP response headers that instruct browsers to apply security controls are absent.',
        'detection_pattern': 'missing header|no x-frame|no csp|no hsts',
        'remediation': 'Add X-Frame-Options, X-Content-Type-Options, CSP, HSTS and Referrer-Policy headers.',
        'references': ['https://owasp.org/www-project-secure-headers/'],
        'source': 'OWASP'
    },
    {
        'name': 'Directory Traversal',
        'category': 'web',
        'severity': 'high',
        'description': 'Path traversal sequences in file parameters allow reading arbitrary files on the server.',
        'detection_pattern': '../|..\\\\|%2e%2e%2f',
        'remediation': 'Canonicalize and validate all file paths. Use a whitelist of allowed paths.',
        'references': ['https://owasp.org/www-community/attacks/Path_Traversal'],
        'source': 'OWASP'
    },
    {
        'name': 'Server-Side Request Forgery (SSRF)',
        'category': 'web',
        'severity': 'high',
        'description': 'Server fetches attacker-controlled URLs, enabling internal network scanning and metadata service access.',
        'detection_pattern': 'ssrf|server-side request|internal url',
        'remediation': 'Validate and whitelist allowed URL schemes and hosts. Block requests to private IP ranges.',
        'references': ['https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/'],
        'source': 'OWASP Top 10 2021'
    },
    {
        'name': 'Insecure Direct Object Reference (IDOR)',
        'category': 'web',
        'severity': 'high',
        'description': 'Predictable identifiers in URLs or parameters allow unauthorized access to other users\' resources.',
        'detection_pattern': 'idor|object reference|user_id=|account_id=',
        'remediation': 'Implement access control checks on every object reference. Use indirect references.',
        'references': ['https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html'],
        'source': 'OWASP'
    },
    {
        'name': 'XML External Entity (XXE)',
        'category': 'web',
        'severity': 'high',
        'description': 'XML parsers configured to process external entity references can expose internal files or perform SSRF.',
        'detection_pattern': '<!ENTITY|SYSTEM "file:|xxe',
        'remediation': 'Disable external entity processing in all XML parsers. Use JSON where possible.',
        'references': ['https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing'],
        'source': 'OWASP'
    },
    {
        'name': 'Broken Authentication',
        'category': 'web',
        'severity': 'critical',
        'description': 'Weak session management, credential storage or authentication flows allow account takeover.',
        'detection_pattern': 'broken auth|weak session|default credentials|no mfa',
        'remediation': 'Enforce MFA, secure session tokens, bcrypt password hashing and account lockout policies.',
        'references': ['https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/'],
        'source': 'OWASP Top 10 2021'
    },
    {
        'name': 'Sensitive Data Exposure',
        'category': 'web',
        'severity': 'high',
        'description': 'Cleartext transmission or storage of sensitive data such as passwords, keys and PII.',
        'detection_pattern': 'plaintext password|cleartext|no encryption|http://',
        'remediation': 'Encrypt sensitive data at rest and in transit. Use TLS 1.2+ for all communications.',
        'references': ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/'],
        'source': 'OWASP Top 10 2021'
    },
]

BUILTIN_NETWORK_SIGNATURES = [
    {
        'name': 'Open Telnet Service',
        'category': 'network',
        'severity': 'high',
        'description': 'Telnet transmits credentials and data in cleartext, making it trivial to intercept.',
        'detection_pattern': 'port 23 open|telnet',
        'remediation': 'Disable Telnet. Replace with SSH for all remote administration.',
        'references': ['https://www.cisecurity.org/controls/'],
        'source': 'CIS Controls'
    },
    {
        'name': 'Open FTP Service',
        'category': 'network',
        'severity': 'medium',
        'description': 'FTP transmits credentials in cleartext and may allow anonymous access.',
        'detection_pattern': 'port 21 open|ftp',
        'remediation': 'Replace with SFTP or FTPS. Disable anonymous FTP access.',
        'references': ['https://www.cisecurity.org/controls/'],
        'source': 'CIS Controls'
    },
    {
        'name': 'Exposed RDP Service',
        'category': 'network',
        'severity': 'high',
        'description': 'RDP exposed to the internet is a common ransomware entry point via brute force.',
        'detection_pattern': 'port 3389 open|rdp',
        'remediation': 'Place RDP behind a VPN. Enable NLA. Restrict access by IP.',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2019-0708'],
        'source': 'NIST NVD'
    },
    {
        'name': 'Exposed SMB Service',
        'category': 'network',
        'severity': 'high',
        'description': 'SMB exposed externally is exploitable by worms like WannaCry (EternalBlue).',
        'detection_pattern': 'port 445 open|smb',
        'remediation': 'Block SMB at the firewall perimeter. Apply MS17-010 patch.',
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2017-0144'],
        'source': 'NIST NVD'
    },
    {
        'name': 'Open VNC Service',
        'category': 'network',
        'severity': 'high',
        'description': 'VNC without strong authentication provides graphical remote access to attackers.',
        'detection_pattern': 'port 5900 open|vnc',
        'remediation': 'Restrict VNC to trusted IPs or VPN. Enforce password authentication.',
        'references': ['https://www.cvedetails.com/cve/CVE-2006-2369/'],
        'source': 'CVE Details'
    },
    {
        'name': 'MySQL Exposed',
        'category': 'network',
        'severity': 'high',
        'description': 'Database port accessible from the internet without firewall protection.',
        'detection_pattern': 'port 3306 open|mysql',
        'remediation': 'Bind MySQL to localhost only. Use firewall rules to restrict access.',
        'references': ['https://dev.mysql.com/doc/refman/8.0/en/security-guidelines.html'],
        'source': 'MySQL Security'
    },
]

BUILTIN_SYSTEM_SIGNATURES = [
    {
        'name': 'World-Writable Files',
        'category': 'system',
        'severity': 'medium',
        'description': 'Files writable by any user can be modified to achieve privilege escalation.',
        'detection_pattern': 'world-writable|chmod 777|o+w',
        'remediation': 'Remove world-write permissions. Audit files with find / -perm -002.',
        'references': ['https://www.cisecurity.org/benchmark/debian_linux'],
        'source': 'CIS Benchmark'
    },
    {
        'name': 'SUID/SGID Binaries',
        'category': 'system',
        'severity': 'medium',
        'description': 'Unusual SUID binaries can be abused for local privilege escalation.',
        'detection_pattern': 'suid|sgid|setuid|setgid',
        'remediation': 'Audit SUID binaries with find / -perm /4000. Remove unnecessary SUID bits.',
        'references': ['https://gtfobins.github.io/'],
        'source': 'GTFOBins'
    },
    {
        'name': 'Unpatched System Packages',
        'category': 'system',
        'severity': 'medium',
        'description': 'Outdated packages may contain known exploitable vulnerabilities.',
        'detection_pattern': 'pending updates|upgradable|out of date',
        'remediation': 'Apply all available security updates. Enable automatic security updates.',
        'references': ['https://www.cisecurity.org/controls/'],
        'source': 'CIS Controls'
    },
    {
        'name': 'Disabled Host Firewall',
        'category': 'system',
        'severity': 'high',
        'description': 'No local firewall means all ports are reachable from the network.',
        'detection_pattern': 'firewall disabled|ufw inactive|iptables empty',
        'remediation': 'Enable and configure ufw or iptables with a default-deny policy.',
        'references': ['https://www.cisecurity.org/controls/'],
        'source': 'CIS Controls'
    },
]


class ThreatIntelUpdater:
    CVE_API = "https://cve.circl.lu/api/last/50"

    def __init__(self):
        from database.db_manager import DatabaseManager
        self.db = DatabaseManager()

    def update_all(self) -> dict:
        results = {}
        results['signatures'] = self._seed_builtin_signatures()
        results['cves'] = self._fetch_cves()
        return results

    def _seed_builtin_signatures(self) -> dict:
        all_sigs = BUILTIN_WEB_SIGNATURES + BUILTIN_NETWORK_SIGNATURES + BUILTIN_SYSTEM_SIGNATURES
        self.db.save_vuln_signatures(all_sigs)
        return {'success': True, 'count': len(all_sigs), 'message': f'Loaded {len(all_sigs)} vulnerability signatures'}

    def _fetch_cves(self) -> dict:
        try:
            r = requests.get(self.CVE_API, timeout=15)
            if r.status_code == 200:
                cves = r.json()
                self.db.save_cves(cves)
                return {'success': True, 'count': len(cves), 'message': f'Synced {len(cves)} CVEs from circl.lu'}
            return {'success': False, 'error': f'HTTP {r.status_code}'}
        except Exception as e:
            logger.warning(f"CVE fetch failed: {e}")
            return {'success': False, 'error': str(e)}
