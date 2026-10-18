"""Sentinel SOC — a portfolio dashboard using synthetic or user-provided CSV logs."""
from pathlib import Path
import pandas as pd
import plotly.express as px
import streamlit as st
from sentinel.detector import normalize, detect

st.set_page_config(page_title="Sentinel | Security Operations", page_icon="🛡️", layout="wide")
st.markdown("""<style>
.stApp{background:radial-gradient(ellipse at 80% 0%,#261018 0%,#101114 48%,#090a0c 100%);color:#e8e9ed}
.block-container{padding-top:2rem;max-width:1350px}
h1,h2,h3{letter-spacing:-.035em}h1{font-weight:800!important}
[data-testid="stMetric"]{background:#18191e;border:1px solid #343039;border-radius:14px;padding:20px}
[data-testid="stMetricValue"]{color:#f3f4f6}
.stButton>button[kind="primary"]{background:#c6283e;border:0}
[data-testid="stSidebar"]{background:#121317}
</style>""", unsafe_allow_html=True)

st.caption("SENTINEL  /  SECURITY OPERATIONS  /  v0.1")
st.title("Security operations, made visible.")
st.write("Detecção explicável de eventos de autenticação, com dados de demonstração ou logs CSV.")

sample = Path(__file__).parent / "data" / "sample_auth.csv"
with st.sidebar:
    st.header("Fonte de dados")
    upload = st.file_uploader("Importar eventos CSV", type=["csv"])
    threshold = st.slider("Falhas para alerta", 3, 15, 5)
    window = st.slider("Janela de análise (min)", 1, 60, 10)
    st.info("Os dados são processados na sessão. Não envie logs com informações sensíveis.")
    st.caption("Formato: timestamp, source_ip, username, event_type, status")
try:
    raw = pd.read_csv(upload if upload is not None else sample)
    events = normalize(raw)
    alerts = detect(events, threshold, window)
except (ValueError, pd.errors.ParserError, UnicodeDecodeError, OSError) as exc:
    st.error(f"Não foi possível processar o CSV: {exc}")
    st.stop()

c1,c2,c3,c4 = st.columns(4)
c1.metric("Eventos", f"{len(events):,}")
c2.metric("Falhas", f"{(events.status == 'failure').sum():,}")
c3.metric("Alertas", f"{len(alerts):,}")
c4.metric("IPs distintos", f"{events.source_ip.nunique():,}")
st.divider()
left,right = st.columns([1.6,1])
with left:
    st.subheader("Volume de eventos")
    timeline = events.assign(hour=events.timestamp.dt.floor("h")).groupby(["hour","status"]).size().reset_index(name="count")
    fig = px.bar(timeline,x="hour",y="count",color="status",barmode="stack",color_discrete_map={"failure":"#d83b53","success":"#2da78a"})
    fig.update_layout(template="plotly_dark",paper_bgcolor="rgba(0,0,0,0)",plot_bgcolor="rgba(0,0,0,0)",legend_title_text="Status",xaxis_title="Horário (UTC)",yaxis_title="Eventos",margin=dict(l=0,r=0,t=10,b=0))
    st.plotly_chart(fig,use_container_width=True)
with right:
    st.subheader("Distribuição de status")
    counts = events.status.value_counts().rename_axis("status").reset_index(name="count")
    fig = px.pie(counts,names="status",values="count",hole=.68,color="status",color_discrete_map={"failure":"#d83b53","success":"#2da78a"})
    fig.update_layout(template="plotly_dark",paper_bgcolor="rgba(0,0,0,0)",margin=dict(l=0,r=0,t=10,b=0))
    st.plotly_chart(fig,use_container_width=True)

st.subheader("Alertas de detecção")
if alerts.empty:
    st.success("Nenhum alerta encontrado com os parâmetros atuais.")
else:
    severity = st.multiselect("Filtrar severidade", sorted(alerts.severity.unique()),default=sorted(alerts.severity.unique()))
    view = alerts[alerts.severity.isin(severity)]
    st.dataframe(view,use_container_width=True,hide_index=True)
    st.download_button("Exportar alertas CSV",data=view.to_csv(index=False).encode("utf-8"),file_name="sentinel_alerts.csv",mime="text/csv")
with st.expander("Eventos normalizados"):
    st.dataframe(events,use_container_width=True,hide_index=True)
    st.download_button("Exportar eventos CSV",data=events.to_csv(index=False).encode("utf-8"),file_name="sentinel_events.csv",mime="text/csv")
st.caption("Detecções heurísticas para fins educacionais. Alertas não comprovam comprometimento. MITRE ATT&CK T1110: Brute Force.")
