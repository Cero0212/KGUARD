import requests
import re
import logging
from urllib.parse import urlparse, urljoin

requests.packages.urllib3.disable_warnings()
logger = logging.getLogger(__name__)

NAME = "Web Vulnerabilities"
DESCRIPTION = "OWASP Top 10, security headers, injection detection"

SECURITY_HEADERS = {
    'X-Frame-Options': ('medium', 'Enables clickjacking protection. Add X-Frame-Options: SAMEORIGIN.'),
    'X-Content-Type-Options': ('low', 'Prevents MIME-type sniffing. Add X-Content-Type-Options: nosniff.'),
    'Content-Security-Policy': ('high', 'Missing CSP allows XSS and data injection. Define a strict policy.'),
    'Strict-Transport-Security': ('medium', 'HSTS forces HTTPS. Add Strict-Transport-Security: max-age=31536000; includeSubDomains.'),
    'Referrer-Policy': ('low', 'Controls referrer leakage. Add Referrer-Policy: strict-origin-when-cross-origin.'),
    'Permissions-Policy': ('low', 'Restricts browser feature access. Add Permissions-Policy header.'),
}

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR \"1\"=\"1",
]

COMMON_SENSITIVE_PATHS = [
    '/.git/config', '/.env', '/wp-config.php', '/config.php',
    '/server-status', '/phpinfo.php', '/adminer.php',
    '/api/v1/users', '/actuator/env', '/actuator/health',
    '/.htaccess', '/web.config', '/crossdomain.xml',
]


def scan(target: str) -> list:
    findings = []

    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    try:
        resp = requests.get(target, timeout=10, verify=False,
                            headers={'User-Agent': 'KGUARD/1.0 Security Scanner'})
    except requests.exceptions.SSLError:
        try:
            resp = requests.get(target.replace('https://', 'http://'), timeout=10, verify=False)
        except Exception as e:
            return [_err(f"Connection failed: {e}")]
    except requests.exceptions.ConnectionError:
        return [_err(f"Cannot reach {target}")]
    except Exception as e:
        return [_err(str(e))]

    findings += _check_headers(resp, target)
    findings += _check_server_info(resp, target)
    findings += _check_cookies(resp, target)
    findings += _check_mixed_content(resp, target)
    findings += _check_forms_csrf(resp, target)
    findings += _check_cors(resp, target)
    findings += _probe_sensitive_paths(target)
    findings += _check_http_methods(target)

    return findings


def _check_headers(resp, target):
    findings = []
    for header, (severity, remediation) in SECURITY_HEADERS.items():
        if header not in resp.headers:
            findings.append({
                'title': f'Missing Security Header: {header}',
                'description': f'The response does not include {header}.',
                'url': target,
                'severity': severity,
                'remediation': remediation,
                'category': 'Headers'
            })
    return findings


def _check_server_info(resp, target):
    findings = []
    server = resp.headers.get('Server', '')
    powered = resp.headers.get('X-Powered-By', '')
    if server and re.search(r'[\d.]', server):
        findings.append({
            'title': 'Server Version Disclosed',
            'description': f'Server header reveals: {server}',
            'url': target,
            'severity': 'low',
            'remediation': 'Remove or genericize the Server header in your web server configuration.',
            'category': 'Information Disclosure'
        })
    if powered:
        findings.append({
            'title': 'Technology Stack Disclosed',
            'description': f'X-Powered-By reveals: {powered}',
            'url': target,
            'severity': 'low',
            'remediation': 'Remove the X-Powered-By header.',
            'category': 'Information Disclosure'
        })
    return findings


def _check_cookies(resp, target):
    findings = []
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append('missing Secure flag')
        if not cookie.has_nonstandard_attr('HttpOnly'):
            issues.append('missing HttpOnly flag')
        if not cookie.has_nonstandard_attr('SameSite'):
            issues.append('missing SameSite attribute')
        if issues:
            findings.append({
                'title': f'Insecure Cookie: {cookie.name}',
                'description': f'Cookie {cookie.name} has: {", ".join(issues)}.',
                'url': target,
                'severity': 'medium',
                'remediation': 'Set Secure; HttpOnly; SameSite=Strict on all session cookies.',
                'category': 'Session Management'
            })
    return findings


def _check_mixed_content(resp, target):
    findings = []
    if target.startswith('https://') and 'http://' in resp.text:
        findings.append({
            'title': 'Mixed Content Detected',
            'description': 'HTTPS page loads resources over HTTP, undermining transport security.',
            'url': target,
            'severity': 'medium',
            'remediation': 'Ensure all sub-resources are loaded over HTTPS.',
            'category': 'Transport Security'
        })
    return findings


def _check_forms_csrf(resp, target):
    findings = []
    if 'text/html' not in resp.headers.get('Content-Type', ''):
        return findings
    html = resp.text.lower()
    form_count = html.count('<form')
    if form_count > 0:
        has_csrf = any(t in html for t in ['csrf', '_token', 'authenticity_token', 'nonce'])
        if not has_csrf:
            findings.append({
                'title': 'Potential CSRF Vulnerability',
                'description': f'Found {form_count} form(s) without visible CSRF tokens.',
                'url': target,
                'severity': 'high',
                'remediation': 'Implement synchronizer CSRF tokens on all state-changing forms.',
                'category': 'CSRF'
            })
    return findings


def _check_cors(resp, target):
    findings = []
    acao = resp.headers.get('Access-Control-Allow-Origin', '')
    if acao == '*':
        findings.append({
            'title': 'Permissive CORS Policy',
            'description': 'Access-Control-Allow-Origin: * allows any origin to read responses.',
            'url': target,
            'severity': 'medium',
            'remediation': 'Restrict CORS to trusted origins. Never use wildcard on authenticated endpoints.',
            'category': 'CORS'
        })
    return findings


def _probe_sensitive_paths(target):
    findings = []
    base = target.rstrip('/')
    for path in COMMON_SENSITIVE_PATHS:
        try:
            r = requests.get(base + path, timeout=5, verify=False, allow_redirects=False)
            if r.status_code in (200, 301, 302) and r.status_code != 404:
                findings.append({
                    'title': f'Sensitive Path Accessible: {path}',
                    'description': f'Server returned HTTP {r.status_code} for {path}.',
                    'url': base + path,
                    'severity': 'high' if any(k in path for k in ['.env', 'config', '.git']) else 'medium',
                    'remediation': f'Restrict access to {path} via firewall rules or web server configuration.',
                    'category': 'Information Disclosure'
                })
        except Exception:
            pass
    return findings


def _check_http_methods(target):
    findings = []
    try:
        r = requests.options(target, timeout=5, verify=False)
        allow = r.headers.get('Allow', '') + r.headers.get('Public', '')
        dangerous = [m for m in ['TRACE', 'PUT', 'DELETE', 'CONNECT'] if m in allow.upper()]
        if dangerous:
            findings.append({
                'title': 'Dangerous HTTP Methods Enabled',
                'description': f'Server permits: {", ".join(dangerous)}',
                'url': target,
                'severity': 'medium',
                'remediation': 'Disable unused HTTP methods in your web server configuration.',
                'category': 'Configuration'
            })
    except Exception:
        pass
    return findings


def _err(msg):
    return {'title': 'Scan Error', 'description': msg, 'severity': 'info', 'remediation': 'Verify target is reachable.'}
