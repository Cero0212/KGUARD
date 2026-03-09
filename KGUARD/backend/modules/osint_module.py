import socket
import requests
import json
import logging
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

NAME = "OSINT & Digital Exposure"
DESCRIPTION = "DNS, IP reputation, exposed services and data breach indicators"


def scan(target: str) -> list:
    findings = []

    host = _extract_host(target)

    findings += _dns_lookup(host)
    findings += _check_ip_reputation(host)
    findings += _check_whois_exposure(host)
    findings += _check_robots_sitemap(target)
    findings += _check_security_txt(target)

    return findings


def _extract_host(target: str) -> str:
    if target.startswith(('http://', 'https://')):
        return urlparse(target).netloc
    return target.split('/')[0]


def _dns_lookup(host: str) -> list:
    findings = []
    try:
        ip = socket.gethostbyname(host)
        findings.append({
            'title': 'DNS Resolution',
            'description': f'{host} resolves to {ip}',
            'severity': 'info',
            'remediation': 'Ensure DNS records are accurate and no sensitive subdomains are exposed.',
            'category': 'OSINT'
        })

        try:
            reverse = socket.gethostbyaddr(ip)[0]
            findings.append({
                'title': 'Reverse DNS Record',
                'description': f'PTR: {ip} → {reverse}',
                'severity': 'info',
                'remediation': 'Reverse DNS may reveal hosting provider or internal naming conventions.',
                'category': 'OSINT'
            })
        except Exception:
            pass

    except socket.gaierror:
        findings.append({
            'title': 'DNS Resolution Failed',
            'description': f'Could not resolve {host}',
            'severity': 'info',
            'remediation': 'Verify the target hostname is correct.'
        })
    return findings


def _check_ip_reputation(host: str) -> list:
    findings = []
    try:
        ip = socket.gethostbyname(host)
        r = requests.get(
            f'https://ipapi.co/{ip}/json/',
            timeout=6,
            headers={'User-Agent': 'KGUARD/1.0'}
        )
        if r.status_code == 200:
            data = r.json()
            org = data.get('org', '')
            country = data.get('country_name', '')
            findings.append({
                'title': 'IP Geolocation & ASN',
                'description': f'IP {ip} — {org} — {country}',
                'severity': 'info',
                'remediation': 'Verify hosting location complies with your data residency requirements.',
                'category': 'OSINT'
            })
            if any(k in org.lower() for k in ['tor', 'vpn', 'proxy', 'bulletproof']):
                findings.append({
                    'title': 'Suspicious Hosting Provider',
                    'description': f'IP hosted by potentially anonymizing or high-risk ASN: {org}',
                    'severity': 'medium',
                    'remediation': 'Investigate if this hosting is intentional.',
                    'category': 'OSINT'
                })
    except Exception as e:
        logger.debug(f"IP reputation check failed: {e}")
    return findings


def _check_whois_exposure(host: str) -> list:
    findings = []
    try:
        r = requests.get(
            f'https://rdap.org/domain/{host}',
            timeout=8,
            headers={'User-Agent': 'KGUARD/1.0'}
        )
        if r.status_code == 200:
            data = r.json()
            entities = data.get('entities', [])
            exposed_emails = []
            for e in entities:
                for v in e.get('vcardArray', [[]])[1:][0] if len(e.get('vcardArray', [[]])) > 1 else []:
                    if isinstance(v, list) and len(v) > 3 and '@' in str(v[3]):
                        exposed_emails.append(str(v[3]))

            if exposed_emails:
                findings.append({
                    'title': 'Email Addresses in WHOIS',
                    'description': f'Publicly visible emails: {", ".join(set(exposed_emails))}',
                    'severity': 'low',
                    'remediation': 'Enable WHOIS privacy protection to hide registrant contact data.',
                    'category': 'OSINT'
                })
            else:
                findings.append({
                    'title': 'WHOIS Privacy Enabled',
                    'description': 'No registrant emails found in public WHOIS data.',
                    'severity': 'info',
                    'remediation': 'Good. Maintain WHOIS privacy protection.',
                    'category': 'OSINT'
                })
    except Exception as e:
        logger.debug(f"WHOIS check failed: {e}")
    return findings


def _check_robots_sitemap(target: str) -> list:
    findings = []
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    base = target.rstrip('/')

    try:
        r = requests.get(f'{base}/robots.txt', timeout=6, verify=False,
                         headers={'User-Agent': 'KGUARD/1.0'})
        if r.status_code == 200 and 'disallow' in r.text.lower():
            disallowed = [l.split(':', 1)[1].strip() for l in r.text.splitlines()
                          if l.lower().startswith('disallow') and l.split(':', 1)[1].strip()]
            if disallowed:
                findings.append({
                    'title': f'robots.txt Reveals Hidden Paths ({len(disallowed)} entries)',
                    'description': f'Disallowed paths: {", ".join(disallowed[:8])}',
                    'severity': 'low',
                    'remediation': 'Do not rely on robots.txt for access control. Use authentication.',
                    'category': 'OSINT'
                })
    except Exception:
        pass

    return findings


def _check_security_txt(target: str) -> list:
    findings = []
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    base = target.rstrip('/')
    try:
        for path in ['/.well-known/security.txt', '/security.txt']:
            r = requests.get(base + path, timeout=5, verify=False)
            if r.status_code == 200 and 'contact' in r.text.lower():
                findings.append({
                    'title': 'security.txt Present',
                    'description': 'A security.txt file with a responsible disclosure contact exists.',
                    'severity': 'info',
                    'remediation': 'Ensure security.txt is kept up to date.',
                    'category': 'OSINT'
                })
                return findings
        findings.append({
            'title': 'No security.txt Found',
            'description': 'Missing security.txt makes it harder for researchers to report vulnerabilities.',
            'severity': 'info',
            'remediation': 'Create /.well-known/security.txt per RFC 9116.',
            'category': 'OSINT'
        })
    except Exception:
        pass
    return findings
