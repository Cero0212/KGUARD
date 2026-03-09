import re
import ipaddress
from pathlib import Path
from urllib.parse import urlparse


def validate_target(target: str, target_type: str) -> tuple[bool, str]:
    validators = {
        'ip':      validate_ip,
        'url':     validate_url,
        'domain':  validate_domain,
        'network': validate_network,
        'file':    validate_file_path,
    }
    fn = validators.get(target_type)
    return fn(target) if fn else (False, 'Unknown target type')


def validate_ip(ip: str) -> tuple[bool, str]:
    try:
        ipaddress.ip_address(ip)
        return True, 'Valid IP'
    except ValueError:
        return False, 'Invalid IP address'


def validate_url(url: str) -> tuple[bool, str]:
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    parsed = urlparse(url)
    if parsed.netloc:
        return True, 'Valid URL'
    return False, 'Invalid URL'


def validate_domain(domain: str) -> tuple[bool, str]:
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(pattern, domain):
        return True, 'Valid domain'
    return False, 'Invalid domain'


def validate_network(network: str) -> tuple[bool, str]:
    try:
        ipaddress.ip_network(network, strict=False)
        return True, 'Valid network'
    except ValueError:
        return False, 'Invalid CIDR notation'


def validate_file_path(path: str) -> tuple[bool, str]:
    p = Path(path)
    if p.exists():
        return True, 'Path exists'
    return False, 'File not found'
