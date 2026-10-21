"""Interface de triagem e investigação do Sentinel SOC."""
from __future__ import annotations

from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from sentinel.detector import detect, normalize
from sentinel.parsers import anonimizar_ip, parse_logs

st.set_page_config(page_title="Sentinel SOC | Análise de segurança", layout="wide")
st.markdown(
    """<style>
    [data-testid="stAppViewContainer"]{background:#14191d;color:#e9edef}
    [data-testid="stSidebar"]{background:#1b2227;border-right:1px solid #3a444a}
    [data-testid="stHeader"]{background:#14191d}
    [data-testid="stAppViewBlockContainer"]{max-width:1450px;padding-top:1.5rem}
    [data-testid="stMetric"]{border-bottom:1px solid #475159;padding:10px}
    </style>""",
    unsafe_allow_html=True,
)

DATA = Path(__file__).parent / "data" / "sample_auth.csv"
PAGES = ["Fila de alertas", "Investigação", "Explorar eventos", "Indicadores", "Regras", "Relatórios"]

with st.sidebar:
    st.title("Sentinel SOC")
    page = st.radio("Navegação", PAGES)
    st.divider()
    upload = st.file_uploader("Importar eventos", type=["csv", "log", "txt"])
    fmt = st.selectbox("Formato de entrada", ["CSV Sentinel", "SSH / HTTP"])
    anonymize = st.checkbox("Anonimizar endereços IP", value=False)
    st.caption("Dados de demonstração fictícios. Não envie registros sensíveis.")
    st.subheader("Configuração das regras")
    threshold = st.slider("Falhas por usuário", 2, 20, 5)
    window = st.slider("Janela (minutos)", 1, 120, 10)
    users_threshold = st.slider("Usuários distintos por IP", 2, 30, 5)
    timezone = st.selectbox("Fuso horário", ["America/Sao_Paulo", "UTC", "America/Manaus"])
    unusual_start = st.slider("Início do horário incomum", 0, 23, 0)
    unusual_end = st.slider("Fim do horário incomum", 0, 23, 6)
    enable_unusual = st.checkbox("Detectar horário incomum", value=True)
    enable_spraying = st.checkbox("Detectar password spraying", value=True)

try:
    if upload is None:
        events = normalize(pd.read_csv(DATA))
    elif fmt == "CSV Sentinel":
        events = normalize(pd.read_csv(upload))
        if anonymize:
            events["source_ip"] = events.source_ip.map(anonimizar_ip)
    else:
        parsed = parse_logs(upload.getvalue().decode("utf-8"), anonymize=anonymize)
        events = normalize(parsed)
    alerts = detect(
        events, threshold=threshold, window_minutes=window,
        users_threshold=users_threshold, timezone=timezone,
        unusual_start=unusual_start, unusual_end=unusual_end,
        enable_unusual=enable_unusual, enable_spraying=enable_spraying,
    )
except (ValueError, UnicodeDecodeError, OSError, KeyError) as exc:
    st.error(f"Não foi possível processar os eventos: {exc}")
    st.stop()

if "case_notes" not in st.session_state:
    st.session_state.case_notes = {}
if "selected_alert" not in st.session_state:
    st.session_state.selected_alert = 0


def baixar_csv(rotulo: str, frame: pd.DataFrame, nome: str) -> None:
    st.download_button(rotulo, frame.to_csv(index=False).encode("utf-8"), file_name=nome, mime="text/csv")


def investigar(indice: int) -> None:
    alerta = alerts.iloc[indice]
    chave = f"{alerta.timestamp}:{alerta.source_ip}:{alerta.username}:{alerta.rule}"
    st.subheader("Dados do alerta")
    st.write(f"**Regra:** {alerta.rule}")
    st.write(f"**Severidade:** {alerta.severity}")
    st.write(f"**IP:** `{alerta.source_ip}` · **Usuário:** `{alerta.username}`")
    st.write(f"**Horário (UTC):** {alerta.timestamp}")
    st.write(f"**Evidência:** {alerta.evidence}")
    st.write(f"**MITRE ATT&CK:** {alerta.mitre}")
    relacionados = events[events.source_ip == alerta.source_ip]
    if alerta.username != "múltiplos":
        relacionados = relacionados[relacionados.username == alerta.username]
    relacionados = relacionados.sort_values("timestamp")
    st.subheader("Linha do tempo dos eventos relacionados")
    st.dataframe(relacionados, hide_index=True, use_container_width=True)
    notas = st.text_area("Notas do analista (somente nesta sessão)", value=st.session_state.case_notes.get(chave, ""), key=f"nota_{indice}")
    if st.button("Salvar notas nesta sessão"):
        st.session_state.case_notes[chave] = notas
        st.success("Notas salvas somente na sessão atual.")
    linhas = [
        "# Relatório de investigação — Sentinel SOC",
        "",
        "Dados de demonstração ou fornecidos pelo operador. Alerta não confirma comprometimento.",
        "",
        f"- Regra: {alerta.rule}",
        f"- Severidade: {alerta.severity}",
        f"- IP: {alerta.source_ip}",
        f"- Usuário: {alerta.username}",
        f"- Horário (UTC): {alerta.timestamp}",
        f"- Evidência: {alerta.evidence}",
        f"- MITRE ATT&CK: {alerta.mitre}",
        "",
        "## Linha do tempo",
        "",
        "| Horário (UTC) | IP | Usuário | Evento | Resultado |",
        "| --- | --- | --- | --- | --- |",
    ]
    for evento in relacionados.itertuples(index=False):
        linhas.append(f"| {evento.timestamp} | {evento.source_ip} | {evento.username} | {evento.event_type} | {evento.status} |")
    linhas.extend(["", "## Notas do analista", "", notas or "Nenhuma nota registrada."])
    st.download_button("Exportar caso em Markdown", "\n".join(linhas), file_name="investigacao_sentinel.md", mime="text/markdown")
    baixar_csv("Exportar eventos relacionados", relacionados, "eventos_relacionados.csv")


st.title(page)
if page == "Fila de alertas":
    st.caption("Priorize os achados e selecione uma linha para abrir a investigação.")
    a, b, c = st.columns(3)
    gravidade = a.multiselect("Severidade", sorted(alerts.severity.unique()), default=sorted(alerts.severity.unique()))
    regras = b.multiselect("Regra", sorted(alerts.rule.unique()), default=sorted(alerts.rule.unique()))
    busca = c.text_input("Buscar IP ou usuário")
    filtrados = alerts[alerts.severity.isin(gravidade) & alerts.rule.isin(regras)]
    if busca:
        filtrados = filtrados[
            filtrados.source_ip.str.contains(busca, case=False, regex=False)
            | filtrados.username.str.contains(busca, case=False, regex=False)
        ]
    st.metric("Alertas encontrados", len(filtrados))
    selection = st.dataframe(
        filtrados[["severity", "rule", "source_ip", "username", "evidence", "timestamp", "mitre"]],
        hide_index=False, use_container_width=True, on_select="rerun", selection_mode="single-row",
    )
    if selection.selection.rows:
        st.session_state.selected_alert = int(filtrados.index[selection.selection.rows[0]])
        st.session_state.open_investigation = True
        st.rerun()
    baixar_csv("Exportar alertas", filtrados, "alertas.csv")
    st.info("Os alertas são indicadores para investigação, não provas de invasão.")
elif page == "Investigação":
    if alerts.empty:
        st.info("Nenhum alerta com os parâmetros atuais.")
    else:
        indice = st.selectbox("Selecionar alerta", range(len(alerts)), index=min(st.session_state.selected_alert, len(alerts)-1),
                             format_func=lambda i: f"{alerts.iloc[i].severity} · {alerts.iloc[i].rule} · {alerts.iloc[i].source_ip}")
        investigar(indice)
elif page == "Explorar eventos":
    st.metric("Eventos carregados", len(events))
    st.dataframe(events.sort_values("timestamp", ascending=False), hide_index=True, use_container_width=True)
    baixar_csv("Exportar eventos", events, "eventos.csv")
elif page == "Indicadores":
    a, b, c = st.columns(3)
    a.metric("Eventos", len(events))
    b.metric("Falhas", int((events.status == "failure").sum()))
    c.metric("Alertas", len(alerts))
    dados = events.assign(intervalo=events.timestamp.dt.floor("5min")).groupby(["intervalo", "status"]).size().reset_index(name="quantidade")
    fig = px.bar(dados, x="intervalo", y="quantidade", color="status",
                 color_discrete_map={"failure": "#D9A441", "success": "#579BC4"})
    fig.update_layout(template="plotly_dark", xaxis_title="Horário (UTC)", yaxis_title="Eventos", legend_title="Resultado")
    st.plotly_chart(fig, use_container_width=True)
elif page == "Regras":
    st.write(f"**Falhas repetidas (T1110):** {threshold} falhas para mesmo IP e usuário em {window} minutos. Severidade alta.")
    st.write(f"**Sucesso após falhas (T1110, T1078):** sucesso após {threshold} falhas anteriores no mesmo IP e usuário. Severidade crítica.")
    st.write(f"**Possível password spraying (T1110.003):** {users_threshold} usuários distintos com falhas pelo mesmo IP em {window} minutos. Severidade alta.")
    st.write(f"**Horário incomum:** sucesso entre {unusual_start:02d}h e {unusual_end:02d}h em {timezone}. Severidade média.")
    st.caption("Limitações: heurísticas por IP; NAT, proxies e horários de trabalho atípicos podem produzir falsos positivos.")
elif page == "Relatórios":
    resumo = pd.DataFrame([{
        "eventos": len(events), "falhas": int((events.status == "failure").sum()),
        "alertas": len(alerts), "IPs_distintos": events.source_ip.nunique(),
        "limiar_falhas": threshold, "janela_minutos": window,
    }])
    st.dataframe(resumo, hide_index=True, use_container_width=True)
    baixar_csv("Exportar resumo", resumo, "resumo.csv")
    baixar_csv("Exportar alertas", alerts, "alertas.csv")
    baixar_csv("Exportar eventos", events, "eventos.csv")

st.divider()
st.caption("Projeto educacional com dados fictícios. Sem ingestão contínua ou contenção automática.")
