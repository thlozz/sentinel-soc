"""Testes de regressão das regras com dados sintéticos."""
from pathlib import Path

import pandas as pd
import pytest

from sentinel.detector import detect, normalize

SAMPLE = Path(__file__).resolve().parents[1] / "data" / "sample_auth.csv"


def test_sample_regressao_legado():
    alerts = detect(pd.read_csv(SAMPLE), enable_spraying=False, enable_unusual=False)
    assert len(alerts) == 4
    assert set(alerts.rule) == {"Falhas repetidas de autenticação", "Sucesso após falhas repetidas"}
    assert len(alerts[alerts.rule == "Falhas repetidas de autenticação"]) == 2
    assert len(alerts[alerts.rule == "Sucesso após falhas repetidas"]) == 2


def test_spraying_varios_usuarios():
    df = pd.DataFrame({
        "timestamp": pd.date_range("2026-01-01T12:00:00Z", periods=5, freq="min"),
        "source_ip": ["192.0.2.5"] * 5,
        "username": ["a", "b", "c", "d", "e"],
        "event_type": ["authentication"] * 5,
        "status": ["failure"] * 5,
    })
    alerts = detect(df, users_threshold=5, enable_unusual=False)
    assert len(alerts) == 1
    assert alerts.iloc[0].mitre == "T1110.003"
    assert "5 usuários distintos" in alerts.iloc[0].evidence


def test_spraying_respeita_janela():
    df = pd.DataFrame({
        "timestamp": ["2026-01-01T12:00:00Z", "2026-01-01T12:30:00Z"],
        "source_ip": ["192.0.2.5"] * 2,
        "username": ["a", "b"],
        "event_type": ["authentication"] * 2,
        "status": ["failure"] * 2,
    })
    assert detect(df, users_threshold=2, window_minutes=10, enable_unusual=False).empty


def test_horario_incomum_fuso():
    df = pd.DataFrame([{
        "timestamp": "2026-01-01T05:00:00Z",
        "source_ip": "192.0.2.5", "username": "ana",
        "event_type": "authentication", "status": "success",
    }])
    alerts = detect(df, unusual_start=0, unusual_end=6, timezone="America/Sao_Paulo")
    assert len(alerts) == 1
    assert "02h" in alerts.iloc[0].evidence


def test_200_mil_eventos():
    times = pd.date_range("2026-01-01T12:00:00Z", periods=200_000, freq="s")
    df = pd.DataFrame({
        "timestamp": times,
        "source_ip": ["192.0.2.10"] * 200_000,
        "username": ["ana"] * 200_000,
        "event_type": ["authentication"] * 200_000,
        "status": ["failure"] * 200_000,
    })
    alerts = detect(df, enable_spraying=False, enable_unusual=False)
    assert len(alerts) == 1
    assert alerts.iloc[0].rule == "Falhas repetidas de autenticação"
