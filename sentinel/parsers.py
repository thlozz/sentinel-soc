"""Importação de logs SSH e HTTP para eventos normalizados do Sentinel."""
from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone

import pandas as pd

SSH = re.compile(
    r"(Failed|Accepted)\s+\S+\s+for\s+(?:invalid user\s+)?(\S+)\s+from\s+(\S+)",
    re.IGNORECASE,
)
SYSLOG = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))")
WEB = re.compile(
    r'^(\S+)\s+\S+\s+(\S+)\s+\[([^]]+)\]\s+"([A-Za-z]+)\s+[^"]+"\s+(\d{3})'
)


def anonimizar_ip(ip: str) -> str:
    """Produz pseudônimo estável sem revelar o IP original."""
    ipaddress.ip_address(ip)
    return "ip-" + hashlib.sha256(ip.encode("ascii")).hexdigest()[:12]


def parse_logs(texto: str, year: int | None = None, anonymize: bool = False) -> pd.DataFrame:
    """Interpreta autenticações SSH e respostas HTTP 401/403/2xx."""
    year = year or datetime.now(timezone.utc).year
    eventos = []
    for linha in texto.splitlines():
        ssh = SSH.search(linha)
        if ssh:
            stamp = ISO.match(linha)
            classic = SYSLOG.match(linha)
            if not stamp and not classic:
                continue
            try:
                if stamp:
                    timestamp = datetime.fromisoformat(stamp.group(1).replace("Z", "+00:00"))
                else:
                    timestamp = datetime.strptime(
                        f"{year} {classic.group(1)}", "%Y %b %d %H:%M:%S"
                    ).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
            ip = ssh.group(3)
            if anonymize:
                try:
                    ip = anonimizar_ip(ip)
                except ValueError:
                    continue
            eventos.append((timestamp, ip, ssh.group(2), "authentication",
                            "failure" if ssh.group(1).lower() == "failed" else "success"))
            continue
        web = WEB.match(linha)
        if not web:
            continue
        ip, user, raw_time, _method, code = web.groups()
        if code not in {"401", "403"} and not code.startswith("2"):
            continue
        try:
            timestamp = datetime.strptime(raw_time, "%d/%b/%Y:%H:%M:%S %z")
            if anonymize:
                ip = anonimizar_ip(ip)
        except ValueError:
            continue
        eventos.append((timestamp, ip, user if user != "-" else "desconhecido",
                        "authentication", "failure" if code in {"401", "403"} else "success"))
    return pd.DataFrame(
        eventos, columns=["timestamp", "source_ip", "username", "event_type", "status"]
    )
