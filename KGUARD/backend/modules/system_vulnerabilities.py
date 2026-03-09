import platform
import subprocess
import os
import re
import logging

logger = logging.getLogger(__name__)

NAME = "System Vulnerabilities"
DESCRIPTION = "OS configuration, patch level, firewall and privilege analysis"


def scan(target: str) -> list:
    os_type = platform.system()
    if os_type == 'Windows':
        return _scan_windows()
    if os_type == 'Linux':
        return _scan_linux()
    return [{'title': 'Unsupported OS', 'description': f'{os_type} has no dedicated analysis module.',
             'severity': 'info', 'remediation': 'N/A'}]


def _scan_windows() -> list:
    findings = []

    try:
        out = _run_ps('Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled | ConvertTo-Json')
        if out:
            import json
            data = json.loads(out)
            if not data.get('RealTimeProtectionEnabled'):
                findings.append({
                    'title': 'Windows Defender Real-Time Protection Disabled',
                    'description': 'Real-time protection is off. Malware may run undetected.',
                    'severity': 'high',
                    'remediation': 'Enable via Windows Security > Virus & Threat Protection.',
                    'category': 'Endpoint Protection'
                })
    except Exception:
        findings.append({'title': 'Defender status unavailable', 'description': 'Could not query Windows Defender.',
                         'severity': 'medium', 'remediation': 'Verify manually via Windows Security.'})

    try:
        out = _run_ps('(Get-HotFix | Measure-Object).Count')
        count = int(out.strip()) if out.strip().isdigit() else 0
        if count < 5:
            findings.append({
                'title': 'Low Patch Count Detected',
                'description': f'Only {count} hotfixes applied. System may be missing critical updates.',
                'severity': 'medium',
                'remediation': 'Run Windows Update immediately and enable automatic updates.',
                'category': 'Patch Management'
            })
    except Exception:
        pass

    try:
        out = _run_ps('Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json')
        if out and 'false' in out.lower():
            findings.append({
                'title': 'Windows Firewall Disabled on One or More Profiles',
                'description': 'Firewall inactive on Domain, Private or Public profile.',
                'severity': 'high',
                'remediation': 'Enable Windows Firewall on all network profiles.',
                'category': 'Firewall'
            })
    except Exception:
        pass

    return findings


def _scan_linux() -> list:
    findings = []

    findings += _check_updates()
    findings += _check_firewall()
    findings += _check_sshd()
    findings += _check_suid()
    findings += _check_world_writable()
    findings += _check_empty_passwords()
    findings += _check_cron()

    return findings


def _check_updates() -> list:
    findings = []
    try:
        if _cmd_exists('apt'):
            out = subprocess.check_output(
                ['apt', 'list', '--upgradable'], stderr=subprocess.DEVNULL, timeout=20
            ).decode()
            count = max(0, len(out.strip().splitlines()) - 1)
            severity = 'high' if count > 20 else 'medium' if count > 0 else 'info'
            findings.append({
                'title': f'Pending Updates: {count} packages',
                'description': f'{count} upgradable packages detected.',
                'severity': severity,
                'remediation': 'Run: sudo apt update && sudo apt upgrade -y',
                'category': 'Patch Management'
            })
        elif _cmd_exists('yum'):
            out = subprocess.check_output(
                ['yum', 'check-update', '--quiet'], stderr=subprocess.DEVNULL, timeout=20
            ).decode()
            count = len([l for l in out.splitlines() if l and not l.startswith(' ')])
            if count > 0:
                findings.append({
                    'title': f'Pending Updates: {count} packages (yum)',
                    'description': f'{count} updates available via yum.',
                    'severity': 'medium',
                    'remediation': 'Run: sudo yum update -y',
                    'category': 'Patch Management'
                })
    except subprocess.TimeoutExpired:
        findings.append({'title': 'Update check timed out', 'description': 'apt/yum took too long.',
                         'severity': 'info', 'remediation': 'Run update check manually.'})
    except Exception:
        pass
    return findings


def _check_firewall() -> list:
    findings = []
    active = False
    try:
        out = subprocess.check_output(['ufw', 'status'], stderr=subprocess.DEVNULL).decode()
        active = 'active' in out.lower()
    except Exception:
        pass
    if not active:
        try:
            out = subprocess.check_output(['systemctl', 'is-active', 'firewalld'], stderr=subprocess.DEVNULL).decode()
            active = 'active' in out.lower()
        except Exception:
            pass
    if not active:
        findings.append({
            'title': 'Host Firewall Not Active',
            'description': 'Neither ufw nor firewalld appears to be running.',
            'severity': 'high',
            'remediation': 'Enable ufw: sudo ufw enable. Or install: sudo apt install ufw.',
            'category': 'Firewall'
        })
    return findings


def _check_sshd() -> list:
    findings = []
    sshd_config = '/etc/ssh/sshd_config'
    if not os.path.exists(sshd_config):
        return findings
    try:
        with open(sshd_config) as f:
            content = f.read()
        if re.search(r'^\s*PermitRootLogin\s+yes', content, re.MULTILINE):
            findings.append({
                'title': 'SSH Root Login Permitted',
                'description': 'Direct root login over SSH is enabled.',
                'severity': 'high',
                'remediation': 'Set PermitRootLogin no in /etc/ssh/sshd_config and restart sshd.',
                'category': 'SSH'
            })
        if re.search(r'^\s*PasswordAuthentication\s+yes', content, re.MULTILINE):
            findings.append({
                'title': 'SSH Password Authentication Enabled',
                'description': 'Password-based SSH login is allowed, enabling brute-force attacks.',
                'severity': 'medium',
                'remediation': 'Set PasswordAuthentication no and use key-based authentication only.',
                'category': 'SSH'
            })
        if not re.search(r'^\s*Protocol\s+2', content, re.MULTILINE):
            findings.append({
                'title': 'SSH Protocol Version Not Explicitly Set to 2',
                'description': 'SSHv1 may be negotiated if Protocol is not explicitly 2.',
                'severity': 'low',
                'remediation': 'Add "Protocol 2" to sshd_config.',
                'category': 'SSH'
            })
    except PermissionError:
        pass
    return findings


def _check_suid() -> list:
    findings = []
    try:
        out = subprocess.check_output(
            ['find', '/usr', '/bin', '/sbin', '-perm', '/4000', '-type', 'f'],
            stderr=subprocess.DEVNULL, timeout=15
        ).decode()
        suid_files = [l for l in out.strip().splitlines() if l]
        suspicious = [f for f in suid_files if any(s in f for s in ['python', 'perl', 'ruby', 'vim', 'nano', 'nmap', 'bash', 'sh'])]
        if suspicious:
            findings.append({
                'title': f'Suspicious SUID Binaries Found ({len(suspicious)})',
                'description': f'GTFOBins-exploitable SUID: {", ".join(suspicious[:5])}',
                'severity': 'high',
                'remediation': 'Remove SUID bit with chmod u-s <binary>. Review all SUID files.',
                'category': 'Privilege Escalation'
            })
    except Exception:
        pass
    return findings


def _check_world_writable() -> list:
    findings = []
    try:
        out = subprocess.check_output(
            ['find', '/tmp', '/var/tmp', '-perm', '-0002', '-not', '-type', 'd'],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode()
        files = [l for l in out.strip().splitlines() if l]
        if files:
            findings.append({
                'title': f'World-Writable Files Detected ({len(files)})',
                'description': f'Example: {files[0]}',
                'severity': 'medium',
                'remediation': 'Remove world-write permissions: chmod o-w <file>',
                'category': 'File Permissions'
            })
    except Exception:
        pass
    return findings


def _check_empty_passwords() -> list:
    findings = []
    try:
        out = subprocess.check_output(
            ['awk', '-F:', '($2 == "" ) {print $1}', '/etc/shadow'],
            stderr=subprocess.DEVNULL
        ).decode()
        accounts = [l for l in out.strip().splitlines() if l]
        if accounts:
            findings.append({
                'title': f'Accounts with Empty Passwords ({len(accounts)})',
                'description': f'Accounts: {", ".join(accounts)}',
                'severity': 'critical',
                'remediation': 'Set strong passwords immediately with passwd <user>.',
                'category': 'Authentication'
            })
    except Exception:
        pass
    return findings


def _check_cron() -> list:
    findings = []
    cron_dirs = ['/etc/cron.d', '/etc/cron.daily', '/var/spool/cron']
    writable = []
    for d in cron_dirs:
        try:
            if os.path.exists(d) and os.access(d, os.W_OK):
                writable.append(d)
        except Exception:
            pass
    if writable:
        findings.append({
            'title': 'Writable Cron Directories',
            'description': f'Cron path writable by current user: {", ".join(writable)}',
            'severity': 'high',
            'remediation': 'Restrict cron directory permissions to root:root 0755.',
            'category': 'Privilege Escalation'
        })
    return findings


def _run_ps(command: str) -> str:
    result = subprocess.run(
        ['powershell', '-NonInteractive', '-Command', command],
        capture_output=True, text=True, timeout=15
    )
    return result.stdout.strip()


def _cmd_exists(cmd: str) -> bool:
    try:
        subprocess.run(['which', cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False
