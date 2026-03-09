import re
from typing import Dict, Any


class RiskClassifier:
    KEYWORDS = {
        'critical': [
            'exploit', 'rce', 'remote code execution', 'root access', 'admin bypass',
            'credential dump', 'backdoor', 'ransomware', 'trojan', 'rootkit',
            'privilege escalation', 'arbitrary code', 'unauthenticated rce',
            'sql injection', 'command injection', 'deserialization'
        ],
        'high': [
            'vulnerability', 'cve', 'injection', 'xss', 'csrf', 'buffer overflow',
            'malware', 'virus', 'path traversal', 'lfi', 'rfi', 'ssrf',
            'authentication bypass', 'idor', 'xxe', 'open redirect',
            'insecure deserialization', 'hardcoded password'
        ],
        'medium': [
            'misconfiguration', 'information disclosure', 'outdated', 'default credentials',
            'weak password', 'directory listing', 'cors', 'clickjacking',
            'missing header', 'self-signed', 'deprecated', 'ssl', 'tls'
        ],
        'low': [
            'information', 'banner', 'version disclosure', 'cookie', 'cache',
            'fingerprint', 'notice', 'warning', 'best practice'
        ]
    }

    CVSS_THRESHOLDS = {
        'critical': 9.0,
        'high': 7.0,
        'medium': 4.0,
        'low': 0.1
    }

    def classify(self, finding: Dict[str, Any]) -> str:
        if finding.get('severity') in ('critical', 'high', 'medium', 'low', 'info'):
            return finding['severity']

        cvss = finding.get('cvss_score')
        if cvss is not None:
            return self._classify_by_cvss(float(cvss))

        text = (finding.get('title', '') + ' ' + finding.get('description', '')).lower()

        for severity, words in self.KEYWORDS.items():
            if any(w in text for w in words):
                return severity

        if re.search(r'\bCVE-\d{4}-\d{4,7}\b', text, re.IGNORECASE):
            return 'high'
        if re.search(r'password|passwd|credential|secret|token', text):
            return 'critical'
        if re.search(r'port\s+\d+\s+open', text):
            return 'medium'

        return 'info'

    def _classify_by_cvss(self, score: float) -> str:
        if score >= self.CVSS_THRESHOLDS['critical']:
            return 'critical'
        if score >= self.CVSS_THRESHOLDS['high']:
            return 'high'
        if score >= self.CVSS_THRESHOLDS['medium']:
            return 'medium'
        if score >= self.CVSS_THRESHOLDS['low']:
            return 'low'
        return 'info'

    def get_explanation(self, finding: Dict[str, Any]) -> str:
        severity = self.classify(finding)
        return {
            'critical': 'Immediate exploitation risk — requires urgent remediation',
            'high': 'High-impact vulnerability requiring priority attention',
            'medium': 'Moderate risk that should be addressed in the next cycle',
            'low': 'Minor issue with limited exploitation potential',
            'info': 'Informational finding for awareness'
        }.get(severity, 'Unclassified')
