from __future__ import annotations

import hmac
import json
import os
import sys
from pathlib import Path
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
load_dotenv(ROOT / ".env")

from response.blocklist import block_ip, load_blocklist, unblock_ip  # noqa: E402
from response.commands import enqueue_command  # noqa: E402
from response.evidence import append_event, verify_chain  # noqa: E402


def resolve_data_dir() -> Path:
    configured = Path(os.getenv("QSHIELD_DATA_DIR", "data"))
    return configured if configured.is_absolute() else ROOT / configured


DATA_DIR = resolve_data_dir()
DATA_DIR.mkdir(parents=True, exist_ok=True)
EVENTS_FILE = DATA_DIR / "events.jsonl"
ALERTS_FILE = DATA_DIR / "alerts.jsonl"
SESSIONS_FILE = DATA_DIR / "sessions.jsonl"
BLOCKLIST_FILE = DATA_DIR / "blocklist.json"
COMMANDS_FILE = DATA_DIR / "commands.jsonl"
EVIDENCE_FILE = DATA_DIR / "evidence.jsonl"
BENCHMARKS_FILE = DATA_DIR / "benchmarks.json"

st.set_page_config(
    page_title="Q-SHIELD | Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
    :root { --bg:#07111f; --panel:#10243a; --line:#203a51; --cyan:#45d7e7; --muted:#94abc2; }
    html, body, [class*="css"] { font-family:Manrope,sans-serif; }
    .stApp { background:radial-gradient(ellipse at 75% 0%,rgba(25,130,155,.18),transparent 35%),#07111f; color:#f2f7ff; }
    [data-testid="stHeader"] { background:rgba(7,17,31,.82); }
    [data-testid="stMainBlockContainer"] { max-width:1500px; padding-top:1.8rem; padding-bottom:3rem; }
    [data-testid="stSidebar"] { background:linear-gradient(180deg,#0c1c2e,#071321); border-right:1px solid var(--line); }
    [data-testid="stMetric"] { background:linear-gradient(145deg,#122b43,#0c1d30); border:1px solid var(--line); border-radius:15px; padding:16px; min-height:112px; }
    [data-testid="stMetricLabel"] { color:#9bb1c8 !important; font-size:.75rem; font-weight:800; }
    [data-testid="stMetricValue"] { color:#fff !important; font-size:1.85rem; font-weight:850; }
    [data-testid="stDataFrame"] { border:1px solid var(--line); border-radius:12px; overflow:hidden; }
    .stButton > button,.stFormSubmitButton > button { background:linear-gradient(135deg,#117f94,#125d79); color:white; border:1px solid rgba(69,215,231,.3); border-radius:9px; font-weight:800; }
    .stButton > button:hover,.stFormSubmitButton > button:hover { color:white; border-color:var(--cyan); }
    .stTextInput input,.stTextArea textarea { background:#0b1b2c !important; color:white !important; border:1px solid var(--line) !important; border-radius:9px !important; }
    .qs-brand { display:flex; align-items:center; gap:12px; padding:8px 2px 22px; }
    .qs-mark { width:43px; height:43px; display:grid; place-items:center; border-radius:13px; background:linear-gradient(145deg,#62e6ed,#1999b9); color:#06121f; font-size:23px; font-weight:900; }
    .qs-name { color:white; font-size:1.12rem; font-weight:900; letter-spacing:.12em; }
    .qs-caption { color:#8da5bd; font-size:.63rem; letter-spacing:.1em; }
    .qs-kicker { color:var(--cyan); font-size:.68rem; letter-spacing:.15em; font-weight:800; text-transform:uppercase; }
    .qs-title { color:white; font-size:2.1rem; font-weight:900; letter-spacing:-.05em; margin:.35rem 0; }
    .qs-sub { color:var(--muted); font-size:.9rem; }
    .qs-hero { margin:18px 0 20px; padding:25px; border:1px solid rgba(69,215,231,.27); border-radius:18px; background:radial-gradient(circle at 90% 20%,rgba(69,215,231,.18),transparent 30%),linear-gradient(110deg,#102d45,#0d2034); }
    .qs-hero-title { color:white; font-size:1.55rem; font-weight:900; margin:.5rem 0; }
    .qs-hero-copy { color:#a8bdd1; max-width:850px; line-height:1.65; }
    .qs-chip { display:inline-block; margin-top:13px; padding:7px 11px; border:1px solid rgba(69,215,231,.28); border-radius:8px; color:#a2edf1; background:rgba(69,215,231,.1); font-size:.68rem; font-weight:800; }
    .qs-section { color:#edf5ff; font-size:1.05rem; font-weight:850; margin:25px 0 12px; }
    .qs-live { display:inline-block; padding:7px 11px; border-radius:30px; color:#8ce5bd; border:1px solid rgba(75,214,162,.3); background:rgba(75,214,162,.08); font-size:.68rem; font-weight:800; }
    .qs-foot { text-align:center; color:#7189a3; font-size:.68rem; padding-top:28px; }
    </style>
    """,
    unsafe_allow_html=True,
)


def read_jsonl(path: Path) -> tuple[list[dict[str, Any]], int]:
    records: list[dict[str, Any]] = []
    errors = 0
    if not path.exists():
        return records, errors
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    records.append(item)
                else:
                    errors += 1
            except json.JSONDecodeError:
                errors += 1
    return records, errors


def value(item: dict[str, Any], *keys: str, default: Any = "") -> Any:
    for key in keys:
        if item.get(key) not in (None, ""):
            return item[key]
    return default


def alerts_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    rows = [{
        "Time": value(row, "timestamp", "time", "created_at"),
        "Alert": value(
            row, "title", "type", "alert_type", "rule_id",
            "rule", "name", default="Security alert"
        ),
        "Source IP": value(row, "source_ip", "src_ip", "ip", "source"),
        "Severity": str(
            value(row, "severity", "priority", default="LOW")
        ).upper(),
        "Status": value(row, "status", "state", default="Open"),
        "Evidence": value(row, "description", "evidence", "details"),
    } for row in records]

    return pd.DataFrame(
        rows,
        columns=[
            "Time", "Alert", "Source IP",
            "Severity", "Status", "Evidence"
        ]
    )

def sessions_frame(records: list[dict[str, Any]]) -> pd.DataFrame:
    rows = [{
        "Session ID": value(row, "session_id", "id"),
        "User": value(row, "user_id", "username", "user"),
        "Remote IP": value(row, "remote_ip", "source_ip", "ip"),
        "Status": value(row, "status", "state", default="Unknown"),
        "Started": value(row, "started_at", "timestamp", "created_at"),
        "Key fingerprint": value(row, "key_fingerprint", "fingerprint", default="Not provided"),
    } for row in records]
    return pd.DataFrame(rows, columns=["Session ID", "User", "Remote IP", "Status", "Started", "Key fingerprint"])


def page_header(title: str, subtitle: str) -> None:
    left, right = st.columns([5, 1])
    with left:
        st.markdown('<div class="qs-kicker">Q-SHIELD / SECURITY OPERATIONS</div>', unsafe_allow_html=True)
        st.markdown(f'<div class="qs-title">{title}</div><div class="qs-sub">{subtitle}</div>', unsafe_allow_html=True)
    with right:
        st.markdown('<div style="text-align:right;padding-top:18px"><span class="qs-live">● LOCAL CONSOLE</span></div>', unsafe_allow_html=True)


def login() -> bool:
    expected_username = os.getenv("QSHIELD_DASHBOARD_USERNAME", "analyst")
    expected_password = os.getenv("QSHIELD_DASHBOARD_PASSWORD", "")
    if not expected_password or expected_password.startswith("replace-with-"):
        st.error("Configure QSHIELD_DASHBOARD_PASSWORD in your .env file before starting the dashboard.")
        st.code("QSHIELD_DASHBOARD_USERNAME=analyst\nQSHIELD_DASHBOARD_PASSWORD=choose-your-own-strong-password\nQSHIELD_DATA_DIR=data")
        st.stop()
    if st.session_state.get("logged_in", False):
        return True

    st.markdown(
        '<div class="qs-hero"><div class="qs-kicker">SECURITY OPERATIONS CONSOLE</div>'
        '<div class="qs-hero-title">Welcome to Q-SHIELD</div>'
        '<div class="qs-hero-copy">Sign in to review security alerts, monitor secure sessions and coordinate incident response.</div>'
        '<span class="qs-chip">ML-KEM · ML-DSA · AES-256-GCM · IDS</span></div>',
        unsafe_allow_html=True,
    )
    with st.form("login_form"):
        username = st.text_input("Analyst username", value="analyst")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Sign in", width="stretch")
    if submitted:
        user_ok = hmac.compare_digest(username.strip(), expected_username)
        password_ok = hmac.compare_digest(password, expected_password)
        if user_ok and password_ok:
            st.session_state["logged_in"] = True
            st.rerun()
        st.error("Incorrect username or password.")
    st.caption("Local classroom prototype only; this is not production-grade authentication.")
    return False


def overview(events: list[dict[str, Any]], alerts: pd.DataFrame, sessions: pd.DataFrame, blocked: list[dict[str, Any]]) -> None:
    open_count = 0
    critical_count = 0
    if not alerts.empty:
        open_count = int((~alerts["Status"].astype(str).str.lower().isin(["closed", "resolved"])).sum())
        critical_count = int((alerts["Severity"] == "CRITICAL").sum())
    active_count = 0
    if not sessions.empty:
        active_count = int(sessions["Status"].astype(str).str.lower().isin(["active", "connected", "established"]).sum())

    success_count = sum(1 for row in events if "handshake_success" in str(value(row, "event_type", "type")).lower())
    failure_count = sum(1 for row in events if "handshake_fail" in str(value(row, "event_type", "type")).lower())

    st.markdown(
        '<div class="qs-hero"><div class="qs-kicker">POST-QUANTUM DEFENCE · LIVE VISIBILITY</div>'
        '<div class="qs-hero-title">Your security, at a glance.</div>'
        '<div class="qs-hero-copy">Monitor secure communication, inspect network threats and coordinate response actions from one analyst workspace. Data is loaded from local JSONL feeds.</div>'
        '<span class="qs-chip">ML-KEM · ML-DSA · AES-256-GCM · IDS</span></div>',
        unsafe_allow_html=True,
    )

    cards = st.columns(5)
    cards[0].metric("OPEN ALERTS", open_count)
    cards[1].metric("CRITICAL ALERTS", critical_count)
    cards[2].metric("ACTIVE SESSIONS", active_count)
    cards[3].metric("BLOCKED IPs", len(blocked))
    cards[4].metric("HANDSHAKES S / F", f"{success_count} / {failure_count}")

    st.markdown('<div class="qs-section">Network intelligence</div>', unsafe_allow_html=True)
    left, right = st.columns([1.5, 1])
    with left:
        st.markdown("### Network activity")
        timeline = []
        for row in events:
            timestamp = pd.to_datetime(value(row, "timestamp", "time", "created_at"), utc=True, errors="coerce")
            if pd.notna(timestamp):
                timeline.append({"Time": timestamp.floor("min"), "Events": 1})
        if timeline:
            chart_data = pd.DataFrame(timeline).groupby("Time", as_index=False).sum().sort_values("Time")
            chart = alt.Chart(chart_data).mark_area(
                line={"color": "#45d7e7", "strokeWidth": 2}, color="#1b7185", opacity=0.35
            ).encode(
                x=alt.X("Time:T", title=None, axis=alt.Axis(labelColor="#8da5bd", grid=False)),
                y=alt.Y("Events:Q", title="Events per minute", axis=alt.Axis(labelColor="#8da5bd", gridColor="#20384e")),
                tooltip=["Time:T", "Events:Q"],
            ).properties(height=260).configure_view(strokeOpacity=0).configure(background="transparent")
            st.altair_chart(chart, width="stretch")
        else:
            st.info("Waiting for timestamped server events in data/events.jsonl.")

    with right:
        st.markdown("### Alert severity")
        if not alerts.empty:
            order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
            counts = alerts["Severity"].value_counts().reindex(order, fill_value=0).rename_axis("Severity").reset_index(name="Count")
            chart = alt.Chart(counts).mark_bar(cornerRadiusEnd=5).encode(
                x=alt.X("Count:Q", title=None, axis=alt.Axis(labelColor="#8da5bd", gridColor="#20384e")),
                y=alt.Y("Severity:N", sort=order, title=None, axis=alt.Axis(labelColor="#d3e1ef")),
                color=alt.Color("Severity:N", scale=alt.Scale(domain=order, range=["#ff647c", "#ffad66", "#e6d26a", "#4bd6a2"]), legend=None),
                tooltip=["Severity", "Count"],
            ).properties(height=220).configure_view(strokeOpacity=0).configure(background="transparent")
            st.altair_chart(chart, width="stretch")
        else:
            st.info("No IDS alerts available yet.")

    st.markdown('<div class="qs-section">Latest detections</div>', unsafe_allow_html=True)
    if alerts.empty:
        st.info("No alert records found. Run the demo data generator to preview the dashboard.")
    else:
        st.dataframe(alerts.head(8), width="stretch", hide_index=True)


def alerts_page(alerts: pd.DataFrame) -> None:
    page_header("Threat alerts", "Review detections, severity levels and supporting evidence.")
    if alerts.empty:
        st.info("No alerts are available yet.")
        return
    selected = st.selectbox("Filter by severity", ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    filtered = alerts if selected == "All" else alerts[alerts["Severity"] == selected]
    st.metric("MATCHING ALERTS", len(filtered))
    st.dataframe(filtered, width="stretch", hide_index=True, height=500)


def sessions_page(sessions: pd.DataFrame) -> None:
    page_header("Secure sessions", "Review session metadata without exposing key material.")
    if sessions.empty:
        st.info("No session records found in data/sessions.jsonl.")
        return
    active = int(sessions["Status"].astype(str).str.lower().isin(["active", "connected", "established"]).sum())
    col1, col2 = st.columns(2)
    col1.metric("TOTAL SESSIONS", len(sessions))
    col2.metric("ACTIVE / ESTABLISHED", active)
    st.dataframe(sessions, width="stretch", hide_index=True, height=480)


def response_page(sessions: pd.DataFrame, blocked: list[dict[str, Any]]) -> None:
    page_header("Incident response", "Apply simulated IP containment and submit server-side session requests.")
    st.warning("IP blocking here is a simulated blocklist, not an operating-system firewall rule. Kill-session and force-re-key actions are queued; Member 2's server must process and acknowledge them.")
    tab_ip, tab_session = st.tabs(["IP containment", "Session commands"])

    with tab_ip:
        left, right = st.columns(2)
        with left:
            with st.form("ip_action_form"):
                ip = st.text_input("IP address", placeholder="192.0.2.10")
                reason = st.text_input("Reason", value="Suspicious activity detected by IDS")
                action = st.radio("Action", ["Block IP", "Unblock IP"], horizontal=True)
                submitted = st.form_submit_button("Apply action", width="stretch")
            if submitted:
                try:
                    if action == "Block IP":
                        entry = block_ip(ip, reason, path=BLOCKLIST_FILE)
                        append_event("ip_blocked", {"ip": entry["ip"], "reason": entry["reason"]}, actor="dashboard", path=EVIDENCE_FILE)
                        st.success(f"{entry['ip']} added to the simulated blocklist.")
                    else:
                        removed = unblock_ip(ip, path=BLOCKLIST_FILE)
                        if removed:
                            append_event("ip_unblocked", {"ip": ip.strip()}, actor="dashboard", path=EVIDENCE_FILE)
                            st.success("IP removed from the simulated blocklist.")
                        else:
                            st.info("IP was not present in the blocklist.")
                    st.rerun()
                except (ValueError, RuntimeError, OSError) as exc:
                    st.error(str(exc))
        with right:
            st.markdown("### Current simulated blocklist")
            if blocked:
                st.dataframe(pd.DataFrame(blocked), width="stretch", hide_index=True)
            else:
                st.info("No IPs blocked.")

    with tab_session:
        session_ids = [] if sessions.empty else [str(item) for item in sessions["Session ID"].tolist() if str(item).strip()]
        with st.form("session_command_form"):
            if session_ids:
                session_id = st.selectbox("Target session", session_ids)
            else:
                session_id = st.text_input("Target session ID", placeholder="session-001")
            command_label = st.radio("Command", ["Kill session", "Force re-key"], horizontal=True)
            reason = st.text_input("Command reason", value="Analyst-initiated response")
            submitted = st.form_submit_button("Queue server command", width="stretch")
        if submitted:
            try:
                command = "kill_session" if command_label == "Kill session" else "force_rekey"
                item = enqueue_command(command, session_id=session_id, reason=reason, path=COMMANDS_FILE)
                append_event("response_command_queued", {"command": command, "command_id": item["command_id"], "session_id": session_id}, actor="dashboard", path=EVIDENCE_FILE)
                st.success(f"{command_label} request queued for {session_id}.")
                st.info("This is a queued request. Member 2's server must consume and acknowledge it before the action is considered complete.")
            except (ValueError, OSError, RuntimeError) as exc:
                st.error(str(exc))


def evidence_page() -> None:
    page_header("Evidence integrity", "Verify the SHA-256 hash chain for incident response records.")
    valid, message = verify_chain(EVIDENCE_FILE)
    if valid:
        st.success(message)
    else:
        st.error(message)
    records, errors = read_jsonl(EVIDENCE_FILE)
    col1, col2 = st.columns(2)
    col1.metric("EVIDENCE RECORDS", len(records))
    col2.metric("MALFORMED JSON LINES", errors)
    if records:
        frame = pd.DataFrame(records)
        if "sequence" in frame.columns:
            frame = frame.sort_values("sequence", ascending=False)
        st.dataframe(frame, width="stretch", hide_index=True, height=480)
    else:
        st.info("No evidence records yet. Dashboard response actions will append records.")
    st.caption("A hash chain makes modification detectable when checked against a trusted checkpoint. It is not a digital signature or tamper-proof storage.")


def benchmarks_page() -> None:
    page_header("Cryptographic benchmarks", "Display measured algorithm sizes and timings supplied by Member 1.")
    if not BENCHMARKS_FILE.exists():
        st.info("No benchmark file found. Generate real measurements from the project root with: python -m benchmarks.bench_pq_vs_classic --iterations 20 --output data/benchmarks.json")
        st.caption("The benchmark runner measures this machine. Do not copy illustrative or synthetic timings into the dashboard.")
        return
    try:
        data = json.loads(BENCHMARKS_FILE.read_text(encoding="utf-8"))
        rows = data if isinstance(data, list) else data.get("benchmarks", [])
        frame = pd.DataFrame(rows)
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        st.error(f"Could not read benchmark data: {exc}")
        return
    if frame.empty:
        st.info("Benchmark file is empty.")
        return
    st.dataframe(frame, width="stretch", hide_index=True)
    numeric = frame.select_dtypes(include="number").columns.tolist()
    label = next((col for col in ["algorithm", "name", "scheme"] if col in frame.columns), None)
    if numeric and label:
        metric = st.selectbox("Metric to chart", numeric)
        chart = alt.Chart(frame).mark_bar(cornerRadiusEnd=5, color="#45d7e7").encode(
            x=alt.X(f"{metric}:Q", title=metric),
            y=alt.Y(f"{label}:N", sort="-x", title=None),
            tooltip=[label, metric],
        ).properties(height=max(180, 42 * len(frame))).configure_view(strokeOpacity=0).configure(background="transparent")
        st.altair_chart(chart, width="stretch")


# -------------------- APPLICATION ENTRY --------------------
if not login():
    st.stop()

with st.sidebar:
    st.markdown(
        '<div class="qs-brand"><div class="qs-mark">盾</div><div>'
        '<div class="qs-name">Q-SHIELD</div><div class="qs-caption">QUANTUM SECURITY CONSOLE</div>'
        '</div></div>',
        unsafe_allow_html=True,
    )
    st.caption("WORKSPACE")
    selected_page = st.radio(
        "Navigate",
        ["Overview", "Alerts", "Sessions", "Response", "Evidence", "Benchmarks"],
        label_visibility="collapsed",
    )
    st.divider()
    st.caption("DATA DIRECTORY")
    st.code(str(DATA_DIR), language=None)
    if st.button("Sign out", width="stretch"):
        st.session_state["logged_in"] = False
        st.rerun()


events, events_errors = read_jsonl(EVENTS_FILE)
alert_records, alerts_errors = read_jsonl(ALERTS_FILE)
session_records, sessions_errors = read_jsonl(SESSIONS_FILE)
alerts_data = alerts_frame(alert_records)
sessions_data = sessions_frame(session_records)
blocklist_data = load_blocklist(BLOCKLIST_FILE)
blocked_entries = blocklist_data.get("blocked_ips", [])

if selected_page == "Overview":
    page_header("Security overview", "A unified view of secure communications, detections and response posture.")
    overview(events, alerts_data, sessions_data, blocked_entries)
elif selected_page == "Alerts":
    alerts_page(alerts_data)
elif selected_page == "Sessions":
    sessions_page(sessions_data)
elif selected_page == "Response":
    response_page(sessions_data, blocked_entries)
elif selected_page == "Evidence":
    evidence_page()
elif selected_page == "Benchmarks":
    benchmarks_page()

if events_errors or alerts_errors or sessions_errors:
    st.warning(f"Malformed JSONL records skipped: events={events_errors}, alerts={alerts_errors}, sessions={sessions_errors}.")

st.markdown('<div class="qs-foot">Q-SHIELD STUDENT PROTOTYPE · SYNTHETIC DATA · AUTHORISED LAB USE ONLY</div>', unsafe_allow_html=True)
