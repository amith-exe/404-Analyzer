"""
Exposure checks: /.git/HEAD, /.env, backup files, server-status, phpinfo.
"""
from __future__ import annotations

from typing import Any


EXPOSURE_PATHS = [
    ("/.git/HEAD", "Exposed .git/HEAD", "critical", "git_exposure",
     "Remove the .git directory from the webroot or block access via web server config."),
    ("/.env", "Exposed .env file", "critical", "env_exposure",
     "Remove .env from the webroot; never deploy config files to publicly accessible paths."),
    ("/backup.zip", "Exposed backup archive", "high", "backup_exposure",
     "Remove backup files from the webroot."),
    ("/db.sql", "Exposed database dump", "critical", "backup_exposure",
     "Remove database dump files from the webroot."),
    ("/server-status", "Exposed Apache server-status", "medium", "server_info",
     "Restrict /server-status to localhost/admin IPs via .htaccess or server config."),
    ("/phpinfo.php", "Exposed phpinfo() page", "medium", "server_info",
     "Remove phpinfo() pages from production environments."),
]


def make_exposure_observation(path: str, title: str, severity: str, category: str,
                               recommendation: str, base_url: str,
                               status_code: int, snippet: str) -> dict:
    return {
        "check": f"exposure_{category}",
        "title": title,
        "severity": severity,
        "confidence": "high",
        "category": category,
        "affected_url": base_url.rstrip("/") + path,
        "evidence": {
            "path": path,
            "status_code": status_code,
            "response_snippet": snippet[:300] if snippet else "",
        },
        "recommendation": recommendation,
    }
