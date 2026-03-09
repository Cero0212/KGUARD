from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List


@dataclass
class Scan:
    id: str
    target: str
    type: str
    start_time: str
    end_time: str
    findings_count: int
    summary: Dict[str, int]
    file_path: str


@dataclass
class Finding:
    id: int
    scan_id: str
    title: str
    description: str
    severity: str
    remediation: str
    evidence: Dict[str, Any]
    created_at: str
    category: str = ''


@dataclass
class VulnSignature:
    id: int
    name: str
    category: str
    severity: str
    description: str
    detection_pattern: str
    remediation: str
    references: List[str]
    source: str
