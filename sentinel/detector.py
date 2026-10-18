"""Deterministic, explainable SOC detections over normalized authentication events."""
from __future__ import annotations
import pandas as pd

REQUIRED = {"timestamp", "source_ip", "username", "event_type", "status"}


def normalize(df: pd.DataFrame) -> pd.DataFrame:
    missing = REQUIRED - set(df.columns)
    if missing:
        raise ValueError(f"Colunas ausentes: {', '.join(sorted(missing))}")
    out = df.copy()
    out["timestamp"] = pd.to_datetime(out["timestamp"], utc=True, errors="coerce")
    if out["timestamp"].isna().any():
        raise ValueError("Há timestamps inválidos no arquivo.")
    for col in ("source_ip", "username", "event_type", "status"):
        out[col] = out[col].astype(str).str.strip().str.lower()
    out = out.sort_values("timestamp").reset_index(drop=True)
    return out


def detect(df: pd.DataFrame, threshold: int = 5, window_minutes: int = 10) -> pd.DataFrame:
    """Detect brute force and success after repeated failures; return deduplicated alerts."""
    events = normalize(df)
    alerts = []
    for (ip, username), group in events.groupby(["source_ip", "username"], sort=False):
        group = group.sort_values("timestamp")
        failures = group[(group.event_type == "authentication") & (group.status == "failure")]
        successes = group[(group.event_type == "authentication") & (group.status == "success")]
        for _, event in failures.iterrows():
            start = event.timestamp - pd.Timedelta(minutes=window_minutes)
            recent = failures[(failures.timestamp >= start) & (failures.timestamp <= event.timestamp)]
            if len(recent) >= threshold:
                alerts.append({"timestamp": event.timestamp, "severity": "High", "rule": "Repeated authentication failures", "source_ip": ip, "username": username, "evidence": f"{len(recent)} falhas em {window_minutes} minutos", "mitre": "T1110"})
                break
        for _, success in successes.iterrows():
            start = success.timestamp - pd.Timedelta(minutes=window_minutes)
            previous = failures[(failures.timestamp >= start) & (failures.timestamp < success.timestamp)]
            if len(previous) >= threshold:
                alerts.append({"timestamp": success.timestamp, "severity": "Critical", "rule": "Successful login after repeated failures", "source_ip": ip, "username": username, "evidence": f"Sucesso após {len(previous)} falhas em {window_minutes} minutos", "mitre": "T1110"})
                break
    columns = ["timestamp", "severity", "rule", "source_ip", "username", "evidence", "mitre"]
    if not alerts:
        return pd.DataFrame(columns=columns)
    return pd.DataFrame(alerts, columns=columns).sort_values("timestamp", ascending=False).reset_index(drop=True)
