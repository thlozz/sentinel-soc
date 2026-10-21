"""Detecção determinística de autenticações com janelas deslizantes."""
from __future__ import annotations

from collections import Counter, deque
from zoneinfo import ZoneInfo

import pandas as pd

REQUIRED = {"timestamp", "source_ip", "username", "event_type", "status"}
COLUMNS = ["timestamp", "severity", "rule", "source_ip", "username", "evidence", "mitre"]


def normalize(df: pd.DataFrame) -> pd.DataFrame:
    """Valida campos e converte horários para UTC."""
    missing = REQUIRED - set(df.columns)
    if missing:
        raise ValueError(f"Colunas ausentes: {', '.join(sorted(missing))}")
    out = df.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], utc=True, errors="coerce", format="mixed")
    if out["timestamp"].isna().any():
        raise ValueError("Há timestamps inválidos no arquivo.")
    for col in ("source_ip", "username", "event_type", "status"):
        out[col] = out[col].astype(str).str.strip().str.lower()
    return out.sort_values("timestamp", kind="stable").reset_index(drop=True)


def detect(
    df: pd.DataFrame,
    threshold: int = 5,
    window_minutes: int = 10,
    users_threshold: int = 5,
    unusual_start: int = 0,
    unusual_end: int = 6,
    timezone: str = "America/Sao_Paulo",
    enable_spraying: bool = True,
    enable_unusual: bool = True,
) -> pd.DataFrame:
    """Aplica regras em O(n) após ordenação, com alertas deduplicados por regra e chave."""
    if min(threshold, window_minutes, users_threshold) < 1:
        raise ValueError("Limiares e janela devem ser positivos.")
    if not (0 <= unusual_start <= 23 and 0 <= unusual_end <= 23):
        raise ValueError("Horários devem estar entre 0 e 23.")
    tz = ZoneInfo(timezone)
    events = normalize(df)
    auth = events[events.event_type == "authentication"]
    alerts = []
    window = pd.Timedelta(minutes=window_minutes)

    def add(timestamp, severity, rule, ip, user, evidence, mitre):
        alerts.append({
            "timestamp": timestamp, "severity": severity, "rule": rule,
            "source_ip": ip, "username": user, "evidence": evidence, "mitre": mitre,
        })

    for (ip, user), group in auth.groupby(["source_ip", "username"], sort=False):
        failures = deque()
        emitted_failure = emitted_success = False
        # Eventos simultâneos: o legado conta todas as falhas no mesmo instante.
        entries = list(group[["timestamp", "status"]].itertuples(index=False, name=None))
        all_failures = [t for t, status in entries if status == "failure"]
        left = right = 0
        for stamp, status in entries:
            while right < len(all_failures) and all_failures[right] <= stamp:
                right += 1
            while left < right and all_failures[left] < stamp - window:
                left += 1
            if status == "failure" and not emitted_failure and right - left >= threshold:
                add(stamp, "Alta", "Falhas repetidas de autenticação", ip, user,
                    f"{right-left} falhas em {window_minutes} minutos", "T1110")
                emitted_failure = True
            if status == "success" and not emitted_success:
                # Sucessos exigem falhas estritamente anteriores.
                previous = left
                while previous < right and all_failures[previous] < stamp:
                    previous += 1
                if previous - left >= threshold:
                    add(stamp, "Crítica", "Sucesso após falhas repetidas", ip, user,
                        f"Sucesso após {previous-left} falhas em {window_minutes} minutos",
                        "T1110, T1078")
                    emitted_success = True

    if enable_spraying:
        for ip, group in auth[auth.status == "failure"].groupby("source_ip", sort=False):
            recent = deque()
            counts = Counter()
            for stamp, user in group[["timestamp", "username"]].itertuples(index=False, name=None):
                recent.append((stamp, user))
                counts[user] += 1
                while recent and recent[0][0] < stamp - window:
                    _, old_user = recent.popleft()
                    counts[old_user] -= 1
                    if not counts[old_user]:
                        del counts[old_user]
                if len(counts) >= users_threshold:
                    add(stamp, "Alta", "Possível password spraying", ip, "múltiplos",
                        f"{len(counts)} usuários distintos com falhas em {window_minutes} minutos",
                        "T1110.003")
                    break

    if enable_unusual:
        for (ip, user), group in auth[auth.status == "success"].groupby(
            ["source_ip", "username"], sort=False
        ):
            for stamp in group.timestamp:
                hour = stamp.tz_convert(tz).hour
                unusual = (
                    unusual_start <= hour < unusual_end
                    if unusual_start < unusual_end
                    else hour >= unusual_start or hour < unusual_end
                    if unusual_start > unusual_end
                    else False
                )
                if unusual:
                    add(stamp, "Média", "Login em horário incomum", ip, user,
                        f"Autenticação às {hour:02d}h em {timezone}; intervalo {unusual_start:02d}h–{unusual_end:02d}h",
                        "Anomalia temporal (sem técnica MITRE atribuída)")
                    break

    if not alerts:
        return pd.DataFrame(columns=COLUMNS)
    return pd.DataFrame(alerts, columns=COLUMNS).sort_values(
        "timestamp", ascending=False, kind="stable"
    ).reset_index(drop=True)
