"""Sentinel SOC — multi-view security operations workbench (synthetic data demo)."""
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from sentinel.detector import detect, normalize

st.set_page_config(page_title="Sentinel SOC | Operations", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
.stApp {background:#0b0e13;color:#e8edf4}
[data-testid="stSidebar"] {background:#10151d;border-right:1px solid #253041}
.block-container {max-width:1500px;padding-top:1.8rem}
h1,h2,h3 {letter-spacing:-.025em}
h1 {font-size:2rem!important}
[data-testid="stMetric"] {background:#151c26;border:1px solid #2a3545;border-radius:10px;padding:16px}
[data-testid="stMetricValue"] {color:#f4f6fa}
div.stButton>button[kind="primary"] {background:#ba344a;border:0}
[data-testid="stDataFrame"] {border:1px solid #273342;border-radius:8px}
</style>
""", unsafe_allow_html=True)

DATA = Path(__file__).parent / "data" / "sample_auth.csv"
PAGES = ["Overview", "Alert queue", "Event explorer", "Investigation", "Detection rules", "Reports"]

with st.sidebar:
    st.markdown("## SENTINEL SOC")
    st.caption("SECURITY OPERATIONS / DEMO")
    page = st.radio("Workspace", PAGES, label_visibility="collapsed")
    st.divider()
    st.subheader("Data source")
    upload = st.file_uploader("Authentication CSV", type=["csv"])
    st.caption("Demo dataset is synthetic. Do not upload sensitive production logs.")
    st.divider()
    st.subheader("Detection settings")
    threshold = st.slider("Failure threshold", 3, 15, 5)
    window = st.slider("Window (minutes)", 1, 60, 10)
    st.caption("All timestamps shown in UTC.")

try:
    events = normalize(pd.read_csv(upload if upload is not None else DATA))
    alerts = detect(events, threshold, window)
except (ValueError, pd.errors.ParserError, UnicodeDecodeError, OSError) as exc:
    st.error(f"Unable to load events: {exc}")
    st.stop()

if "case_notes" not in st.session_state:
    st.session_state.case_notes = {}

def download_csv(label, frame, filename):
    st.download_button(label, frame.to_csv(index=False).encode("utf-8"),
                       file_name=filename, mime="text/csv")

def plot_style(fig):
    fig.update_layout(template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                      plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=0,r=0,t=12,b=0))
    return fig

st.caption(f"WORKSPACE  /  {page.upper()}  /  LOCAL ANALYSIS")
st.title(page)
st.caption("Authentication telemetry · Explainable detections · Synthetic demo data")

if page == "Overview":
    a,b,c,d,e = st.columns(5)
    a.metric("Total events", f"{len(events):,}")
    b.metric("Failed logins", f"{(events.status == 'failure').sum():,}")
    c.metric("Detected alerts", f"{len(alerts):,}")
    d.metric("Unique source IPs", f"{events.source_ip.nunique():,}")
    e.metric("Affected users", f"{alerts.username.nunique() if not alerts.empty else 0:,}")
    st.divider()
    left,right = st.columns([1.8,1])
    with left:
        st.subheader("Authentication activity")
        timeline = events.assign(bucket=events.timestamp.dt.floor("5min")).groupby(["bucket","status"]).size().reset_index(name="events")
        fig = px.bar(timeline,x="bucket",y="events",color="status",barmode="stack",
                     color_discrete_map={"failure":"#d34b62","success":"#2ca58d"})
        fig.update_layout(xaxis_title="Time (UTC)",yaxis_title="Events",legend_title="")
        st.plotly_chart(plot_style(fig),use_container_width=True)
    with right:
        st.subheader("Event outcomes")
        counts = events.status.value_counts().rename_axis("status").reset_index(name="events")
        fig = px.pie(counts,names="status",values="events",hole=.65,
                     color="status",color_discrete_map={"failure":"#d34b62","success":"#2ca58d"})
        st.plotly_chart(plot_style(fig),use_container_width=True)
    left,right = st.columns(2)
    with left:
        st.subheader("Top source IPs")
        st.dataframe(events.source_ip.value_counts().head(10).rename_axis("Source IP").reset_index(name="Events"),
                     hide_index=True,use_container_width=True)
    with right:
        st.subheader("Recent alerts")
        st.dataframe(alerts[["timestamp","severity","rule","username"]].head(8),
                     hide_index=True,use_container_width=True)
elif page == "Alert queue":
    st.write("Review detection findings and filter the queue before exporting.")
    c1,c2,c3 = st.columns(3)
    severity = c1.multiselect("Severity", sorted(alerts.severity.unique()),default=sorted(alerts.severity.unique()))
    rule = c2.multiselect("Detection rule", sorted(alerts.rule.unique()),default=sorted(alerts.rule.unique()))
    search = c3.text_input("Search IP or username")
    view = alerts[alerts.severity.isin(severity) & alerts.rule.isin(rule)].copy()
    if search:
        view = view[view.source_ip.str.contains(search,case=False,regex=False) |
                    view.username.str.contains(search,case=False,regex=False)]
    st.metric("Matching alerts",len(view))
    st.dataframe(view,hide_index=True,use_container_width=True)
    download_csv("Export filtered alerts",view,"sentinel_alerts.csv")
    st.info("An alert is a detection finding, not proof of account compromise.")
elif page == "Event explorer":
    c1,c2,c3 = st.columns(3)
    statuses = c1.multiselect("Status", sorted(events.status.unique()),default=sorted(events.status.unique()))
    users = c2.multiselect("Users", sorted(events.username.unique()))
    ip = c3.text_input("Source IP contains")
    view = events[events.status.isin(statuses)].copy()
    if users:
        view = view[view.username.isin(users)]
    if ip:
        view = view[view.source_ip.str.contains(ip,case=False,regex=False)]
    st.metric("Matching events",len(view))
    st.dataframe(view.sort_values("timestamp",ascending=False),hide_index=True,use_container_width=True)
    download_csv("Export filtered events",view,"sentinel_events.csv")
elif page == "Investigation":
    st.write("Pivot from an alert to its related authentication events. Notes are session-only.")
    if alerts.empty:
        st.info("No alerts detected with current settings.")
    else:
        options = list(alerts.index)
        selected = st.selectbox("Select alert",options,
            format_func=lambda i:f"{alerts.loc[i,'severity']} | {alerts.loc[i,'username']} | {alerts.loc[i,'source_ip']} | {alerts.loc[i,'rule']}")
        finding = alerts.loc[selected]
        a,b,c = st.columns(3)
        a.metric("Severity",finding.severity)
        b.metric("Account",finding.username)
        c.metric("Source IP",finding.source_ip)
        st.write(f"**Detection:** {finding.rule}")
        st.write(f"**Evidence:** {finding.evidence}  |  **MITRE ATT&CK:** {finding.mitre}")
        related = events[(events.username == finding.username) & (events.source_ip == finding.source_ip)]
        st.subheader("Correlated events")
        st.dataframe(related.sort_values("timestamp"),hide_index=True,use_container_width=True)
        key = f"{finding.username}:{finding.source_ip}:{finding.rule}"
        notes = st.text_area("Analyst notes (this browser session only)",value=st.session_state.case_notes.get(key,""))
        if st.button("Save session notes",type="primary"):
            st.session_state.case_notes[key] = notes
            st.success("Notes saved in the current session. They are not persisted.")
        download_csv("Export evidence",related,"sentinel_investigation.csv")
elif page == "Detection rules":
    st.write("Current rules are deterministic and evaluate authentication events grouped by IP and username.")
    st.subheader("Repeated authentication failures")
    st.write(f"Triggers when at least **{threshold}** failures occur within **{window} minutes** for the same source IP and account.")
    st.caption("Severity: High · MITRE ATT&CK T1110")
    st.divider()
    st.subheader("Successful login after repeated failures")
    st.write(f"Triggers when a successful login follows at least **{threshold}** failures within **{window} minutes** for the same source IP and account.")
    st.caption("Severity: Critical · MITRE ATT&CK T1110")
    st.info("Adjust thresholds in the sidebar. Changes recalculate detections immediately; rules are not persisted.")
elif page == "Reports":
    st.write("Export a reproducible snapshot of the currently loaded dataset and detection parameters.")
    a,b,c = st.columns(3)
    a.metric("Events",len(events))
    b.metric("Alerts",len(alerts))
    c.metric("Failure rate",f"{100*(events.status == 'failure').mean():.1f}%" if len(events) else "0%")
    summary = pd.DataFrame([{
        "events":len(events),"failed_logins":int((events.status == "failure").sum()),
        "alerts":len(alerts),"unique_ips":events.source_ip.nunique(),
        "threshold":threshold,"window_minutes":window
    }])
    st.subheader("Summary")
    st.dataframe(summary,hide_index=True,use_container_width=True)
    download_csv("Export summary",summary,"sentinel_summary.csv")
    download_csv("Export alerts",alerts,"sentinel_alerts.csv")
    download_csv("Export events",events,"sentinel_events.csv")

st.divider()
st.caption("Sentinel SOC · Educational portfolio project · No live SIEM ingestion or automated containment.")
