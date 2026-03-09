import json
from datetime import datetime
from pathlib import Path

from config import Config


def save_report(scan_id: str, fmt: str = 'json') -> Path | None:
    scan_file = Path(Config.SCANS_DIR) / f"scan_{scan_id}.json"
    if not scan_file.exists():
        return None

    with open(scan_file) as f:
        data = json.load(f)

    if fmt == 'json':
        return scan_file
    if fmt == 'html':
        return _html_report(data)
    return None


def _html_report(data: dict) -> Path:
    findings_html = ''
    for f in data.get('findings', []):
        sev = f.get('severity', 'info')
        findings_html += f"""
        <div style="border-left:4px solid var(--{sev});padding:12px;margin:10px 0;background:#1e1e1e;border-radius:4px">
          <h3 style="color:#eee;margin:0 0 6px">{f.get('title','')}</h3>
          <p style="color:#aaa;margin:0">{f.get('description','')}</p>
          {f'<p style="color:#6ecc9a;margin:6px 0 0;font-size:13px">↳ {f.get("remediation","")}</p>' if f.get('remediation') else ''}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>KGUARD Report — {data.get('scan_id','')}</title>
  <style>
    :root {{--critical:#ff3b5c;--high:#ff7b00;--medium:#f5c518;--low:#22d3a5;--info:#4b9eff}}
    body {{font-family:monospace;background:#111;color:#ddd;padding:40px;max-width:900px;margin:0 auto}}
    h1 {{color:#00d4ff}} .meta {{color:#777;font-size:13px;margin-bottom:24px}}
  </style>
</head>
<body>
  <h1>KGUARD Security Report</h1>
  <div class="meta">
    Scan ID: {data.get('scan_id','')} ·
    Target: {data.get('target','')} ·
    Date: {data.get('start_time','')}
  </div>
  {findings_html}
</body>
</html>"""

    out = Path(Config.SCANS_DIR) / f"report_{data['scan_id']}.html"
    out.write_text(html)
    return out


def fmt_ts(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return ts or ''
