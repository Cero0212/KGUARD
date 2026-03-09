import socket
import subprocess
import ipaddress
import platform
import logging

logger = logging.getLogger(__name__)

NAME = "Network Scanner"
DESCRIPTION = "Host discovery, port scanning, service fingerprinting"

PORT_RISK = {
    21:   ('FTP',     'medium', 'FTP transmits credentials in cleartext. Replace with SFTP.'),
    22:   ('SSH',     'low',    'Ensure key-based auth only and disable root login.'),
    23:   ('Telnet',  'high',   'Telnet is unencrypted. Migrate to SSH immediately.'),
    25:   ('SMTP',    'medium', 'Verify relay is restricted to prevent spam abuse.'),
    53:   ('DNS',     'low',    'Restrict zone transfers and enable DNSSEC.'),
    80:   ('HTTP',    'low',    'Enforce HTTPS redirect. Do not serve sensitive data over HTTP.'),
    110:  ('POP3',    'medium', 'POP3 is cleartext. Use POP3S (port 995).'),
    111:  ('RPC',     'high',   'Block RPC from external access.'),
    135:  ('RPC',     'high',   'Windows RPC exposed — restrict at firewall.'),
    139:  ('NetBIOS', 'high',   'NetBIOS should not be exposed externally.'),
    143:  ('IMAP',    'medium', 'Use IMAPS (port 993) instead.'),
    443:  ('HTTPS',   'info',   'Verify TLS version and cipher strength.'),
    445:  ('SMB',     'high',   'SMB exposed externally is critical. Patch EternalBlue (MS17-010).'),
    993:  ('IMAPS',   'info',   'Verify certificate validity.'),
    995:  ('POP3S',   'info',   'Verify certificate validity.'),
    1433: ('MSSQL',   'high',   'Database port must not be internet-facing.'),
    1723: ('PPTP',    'medium', 'PPTP VPN has known weaknesses. Migrate to WireGuard or OpenVPN.'),
    2049: ('NFS',     'high',   'NFS exposed externally allows unauthorized file access.'),
    3306: ('MySQL',   'high',   'Bind MySQL to localhost. Database ports must not be internet-facing.'),
    3389: ('RDP',     'high',   'RDP is a common ransomware vector. Restrict to VPN only.'),
    5432: ('Postgres','high',   'Bind PostgreSQL to localhost only.'),
    5900: ('VNC',     'high',   'VNC without authentication provides full GUI access to attackers.'),
    6379: ('Redis',   'critical','Redis with no auth allows full data access and code execution.'),
    8080: ('HTTP-Alt','low',    'Ensure staging/dev services are not publicly accessible.'),
    8443: ('HTTPS-Alt','info',  'Verify certificate and application security.'),
    27017:('MongoDB', 'critical','MongoDB without auth exposes all data. Bind to localhost.'),
}


def scan(target: str) -> list:
    try:
        if '/' in target:
            return _scan_network(target)
        return _scan_host(target)
    except Exception as e:
        return [{'title': 'Network scan error', 'description': str(e), 'severity': 'info',
                 'remediation': 'Verify target address'}]


def _scan_network(network: str) -> list:
    findings = []
    try:
        net = ipaddress.ip_network(network, strict=False)
        active = []
        for i, ip in enumerate(net.hosts()):
            if i >= 20:
                break
            if _ping(str(ip)):
                active.append(str(ip))

        findings.append({
            'title': f'Active Hosts: {len(active)} found',
            'description': f'Discovered hosts: {", ".join(active) if active else "none"}',
            'severity': 'info',
            'remediation': 'Review each discovered host and disable unnecessary services.'
        })

        for host in active[:5]:
            findings += _scan_host(host)

    except Exception as e:
        findings.append({'title': 'Network scan error', 'description': str(e), 'severity': 'info',
                         'remediation': 'Verify CIDR notation'})
    return findings


def _scan_host(host: str) -> list:
    findings = []

    if not _ping(host):
        findings.append({
            'title': f'Host Unreachable: {host}',
            'description': 'No response to ICMP probe. Host may be offline or firewalled.',
            'severity': 'info',
            'remediation': 'Verify connectivity'
        })
        return findings

    open_ports = []
    for port in PORT_RISK:
        if _check_port(host, port):
            open_ports.append(port)

    if not open_ports:
        findings.append({
            'title': 'No Common Ports Open',
            'description': f'No well-known service ports found on {host}.',
            'severity': 'info',
            'remediation': 'N/A'
        })
        return findings

    for port in open_ports:
        service, severity, remediation = PORT_RISK[port]
        banner = _grab_banner(host, port)
        desc = f'Service {service} is accessible on {host}:{port}.'
        if banner:
            desc += f' Banner: {banner}'
        findings.append({
            'title': f'Open Port {port}/{service}',
            'description': desc,
            'host': host,
            'port': port,
            'service': service,
            'severity': severity,
            'remediation': remediation,
            'category': 'Network'
        })

    findings += _check_dangerous_combos(host, open_ports)
    return findings


def _check_dangerous_combos(host: str, ports: list) -> list:
    findings = []
    if 6379 in ports:
        findings.append({
            'title': 'Redis Exposed — Potential RCE',
            'description': 'Unauthenticated Redis allows config rewrites that can achieve remote code execution.',
            'host': host,
            'severity': 'critical',
            'remediation': 'Bind Redis to 127.0.0.1 and set a strong requirepass.',
            'category': 'Network'
        })
    if 27017 in ports:
        findings.append({
            'title': 'MongoDB Exposed — No Auth by Default',
            'description': 'MongoDB default config requires no authentication. All data accessible.',
            'host': host,
            'severity': 'critical',
            'remediation': 'Enable --auth flag and bind to localhost.',
            'category': 'Network'
        })
    if 445 in ports:
        findings.append({
            'title': 'SMB Exposed — EternalBlue Risk',
            'description': 'SMB on port 445 may be vulnerable to MS17-010 (EternalBlue) used by WannaCry.',
            'host': host,
            'severity': 'high',
            'remediation': 'Apply MS17-010 patch. Block port 445 at the perimeter firewall.',
            'category': 'Network'
        })
    return findings


def _ping(host: str) -> bool:
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        result = subprocess.run(
            ['ping', param, '1', '-W', '1', host],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=4
        )
        return result.returncode == 0
    except Exception:
        return False


def _check_port(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def _grab_banner(host: str, port: int) -> str:
    try:
        with socket.create_connection((host, port), timeout=2) as s:
            s.settimeout(2)
            banner = s.recv(256).decode('utf-8', errors='ignore').strip()
            return banner[:120] if banner else ''
    except Exception:
        return ''
