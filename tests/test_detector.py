import pandas as pd
import pytest
from sentinel.detector import detect, normalize


def fixture_events():
    times = pd.date_range("2026-01-01T12:00:00Z", periods=6, freq="min")
    return pd.DataFrame({"timestamp": times, "source_ip": ["192.0.2.10"] * 6, "username": ["alice"] * 6, "event_type": ["authentication"] * 6, "status": ["failure"] * 5 + ["success"]})


def test_bruteforce_and_success():
    alerts = detect(fixture_events())
    assert set(alerts.rule) == {"Falhas repetidas de autenticação", "Sucesso após falhas repetidas"}
    assert set(alerts.mitre) == {"T1110", "T1110, T1078"}


def test_no_false_alert_for_separate_ips():
    df = fixture_events().iloc[:4].copy()
    df.loc[df.index[-1], "source_ip"] = "192.0.2.11"
    assert detect(df).empty


def test_missing_columns():
    with pytest.raises(ValueError, match="Colunas ausentes"):
        normalize(pd.DataFrame({"timestamp": ["2026-01-01"]}))


def test_invalid_timestamp():
    df = fixture_events().astype({"timestamp": "str"})
    df.loc[0, "timestamp"] = "not-a-date"
    with pytest.raises(ValueError, match="timestamps inválidos"):
        normalize(df)
