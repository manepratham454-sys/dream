import os
from urllib.parse import urlparse

def allow_target(url: str) -> bool:
    """Check if *url* is in the allow‑list defined in the environment.
    ALLOW_LIST should be a comma‑separated list of base URLs (e.g.,
    http://localhost:3000,http://example.com). If empty, all URLs are allowed.
    """
    allow_list = os.getenv('ALLOW_LIST', '')
    if not allow_list:
        return True
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    return base.rstrip('/') in [a.rstrip('/') for a in allow_list.split(',') if a]

def normalize_alert(alert: dict) -> dict:
    """Map a ZAP alert dict to our Finding schema fields.
    Only a subset of fields is extracted for the MVP.
    """
    return {
        "name": alert.get('name'),
        "cwe": alert.get('cweid'),
        "owasp_category": alert.get('owaspscg'),
        "severity": alert.get('risk'),
        "url": alert.get('url'),
        "param": alert.get('param'),
        "evidence": alert.get('evidence'),
    }
