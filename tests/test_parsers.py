"""Testes dos parsers de registros fictícios."""
import pytest

from sentinel.parsers import anonimizar_ip, parse_logs


def test_ssh_syslog():
    texto = "Oct 08 10:15:01 host sshd[2]: Failed password for root from 192.0.2.1 port 22 ssh2"
    frame = parse_logs(texto, year=2026)
    assert len(frame) == 1
    assert frame.iloc[0].status == "failure"


def test_ssh_iso_fuso():
    texto = "2026-10-08T10:15:01-03:00 host sshd: Accepted password for ana from 192.0.2.1 port 22 ssh2"
    frame = parse_logs(texto)
    assert len(frame) == 1
    assert frame.iloc[0].timestamp.isoformat() == "2026-10-08T10:15:01-03:00"


def test_web_metodo_patch():
    texto = '192.0.2.1 - ana [08/Oct/2026:10:15:01 -0300] "PATCH /login HTTP/1.1" 401 123'
    frame = parse_logs(texto)
    assert len(frame) == 1
    assert frame.iloc[0].status == "failure"


def test_anonimizacao_estavel():
    ip = "192.0.2.1"
    assert anonimizar_ip(ip) == anonimizar_ip(ip)
    assert ip not in anonimizar_ip(ip)


def test_anonimizacao_ip_invalido():
    with pytest.raises(ValueError):
        anonimizar_ip("nao-e-ip")


def test_linha_irrelevante():
    assert parse_logs("linha sem evento").empty
