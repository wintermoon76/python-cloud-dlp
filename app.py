
import sqlite3
from io import BytesIO
from pathlib import Path

import pandas as pd
import streamlit as st
from pypdf import PdfReader
from docx import Document

from dlp.audit import DB_PATH
from dlp.pipeline import scan_text
from dlp.hybrid_storage import save_file_hybrid

st.set_page_config(
    page_title="Sentinel DLP | Security Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------- THEME ----------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
html, body, [class*="css"] {font-family: Inter, sans-serif;}
.stApp {background:#f4f7fb;color:#17243a;}
header[data-testid="stHeader"] {background:transparent;}
.block-container {padding:1.5rem 2.4rem 2rem;max-width:1500px;}
section[data-testid="stSidebar"] {display:none;}
.hero {background:linear-gradient(115deg,#101f3d,#173c70);
padding:26px 30px;border-radius:18px;color:white;margin-bottom:22px;}
.hero h1 {font-size:29px;margin:0 0 8px;color:white;}
.hero p {color:#d4e1f5;margin:0;font-size:14px;}
.metric {background:white;border:1px solid #e4eaf3;border-radius:15px;
padding:19px 20px;min-height:122px;}
.metric-label {color:#66758b;font-size:12px;font-weight:600;
text-transform:uppercase;letter-spacing:.6px;}
.metric-value {font-size:30px;font-weight:800;color:#142748;margin:8px 0 4px;}
.metric-foot {font-size:12px;color:#728198;}
.panel {background:white;border:1px solid #e4eaf3;border-radius:15px;
padding:20px 22px;margin-bottom:16px;}
.section-title {font-size:18px;font-weight:750;color:#182b49;margin-bottom:5px;}
.section-sub {font-size:13px;color:#718098;margin-bottom:15px;}
div[data-testid="stButton"] button {border-radius:9px;font-weight:650;
min-height:42px;}
div[data-testid="stFileUploader"] {background:#f8faff;border:1px dashed #b8c9e3;
border-radius:12px;padding:12px;}
div[data-testid="stRadio"] > div {gap:8px;}
footer {visibility:hidden;}

/* Clear, readable navigation */
div[data-testid="stRadio"] label,
div[data-testid="stRadio"] p {
    color: #263955 !important;
    font-weight: 600 !important;
}

/* Consistent light form controls */
div[data-baseweb="select"] > div,
div[data-baseweb="input"] > div,
div[data-baseweb="textarea"] > div {
    background: #ffffff !important;
    border-color: #d7e1ef !important;
    color: #17243a !important;
    border-radius: 10px !important;
}

div[data-baseweb="select"] *,
div[data-baseweb="input"] input {
    color: #17243a !important;
}

/* Softer buttons */
div[data-testid="stButton"] button,
div[data-testid="stDownloadButton"] button {
    border-radius: 10px !important;
    font-weight: 650 !important;
    transition: all 0.15s ease;
}

/* Cleaner tables */
div[data-testid="stDataFrame"] {
    border: 1px solid #dfe7f2;
    border-radius: 12px;
    overflow: hidden;
}

/* Tighter spacing */
div.block-container {
    padding-top: 1.4rem;
    padding-bottom: 1.5rem;
}

/* Consistent headings */
h1  {
    color: #FFFFFF !important;
    letter-spacing: -0.4px;
}
h2, h3
{
  font-size: 29px;
    margin: 0 0 8px;
    color: #93C5FD;
}
</style>
""", unsafe_allow_html=True)

# ---------- HELPERS ----------
def extract_text(upload):
    name = upload.name.lower()
    raw = upload.getvalue()

    if name.endswith(".pdf"):
        reader = PdfReader(BytesIO(raw))
        return "\n".join(page.extract_text() or "" for page in reader.pages)

    if name.endswith(".docx"):
        doc = Document(BytesIO(raw))
        return "\n".join(p.text for p in doc.paragraphs)

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("This file format is not supported for text extraction.")

def load_audit():
    db = Path(DB_PATH)
    if not db.exists():
        return pd.DataFrame(), "Audit database has not been created yet."

    try:
        with sqlite3.connect(str(db)) as conn:
            tables = pd.read_sql_query(
                "SELECT name FROM sqlite_master WHERE type='table'", conn
            )["name"].tolist()

            if not tables:
                return pd.DataFrame(), "No audit tables found."

            preferred = [
                t for t in tables
                if "audit" in t.lower() or "log" in t.lower()
            ]
            table = preferred[0] if preferred else tables[0]
            safe_table = table.replace('"', '""')
            df = pd.read_sql_query(
                f'SELECT * FROM "{safe_table}" ORDER BY rowid DESC LIMIT 1000',
                conn,
            )
            return df, None
    except Exception as exc:
        return pd.DataFrame(), str(exc)

def find_col(df, words):
    for col in df.columns:
        if any(word in str(col).lower() for word in words):
            return col
    return None

def show_metric(label, value, foot):
    st.markdown(
        f'<div class="metric"><div class="metric-label">{label}</div>'
        f'<div class="metric-value">{value}</div>'
        f'<div class="metric-foot">{foot}</div></div>',
        unsafe_allow_html=True,
    )

# ---------- NAVIGATION ----------
st.markdown("""
<div class="hero">
  <h1>🛡️ Sentinel DLP</h1>
  <p>Cloud Data Loss Prevention · Data security, risk visibility and audit intelligence</p>
</div>
""", unsafe_allow_html=True)

page = st.radio(
    "Navigation",
    ["Overview", "File Scanner", "Audit Explorer"],
    horizontal=True,
    label_visibility="collapsed",
)

audit_df, audit_error = load_audit()

# ---------- OVERVIEW ----------
if page == "Overview":
    st.markdown("## Security overview")
    st.caption("A unified view of scanning activity and storage audit events.")

    total = len(audit_df)
    status_col = find_col(audit_df, ["status", "action", "event", "operation"])
    risk_col = find_col(audit_df, ["risk", "severity", "level"])
    file_col = find_col(audit_df, ["filename", "file_name", "file"])
    time_col = find_col(audit_df, ["timestamp", "created_at", "time", "date"])

    if status_col:
        statuses = audit_df[status_col].fillna("").astype(str).str.lower()
        blocked = int(statuses.str.contains("block|reject|denied|fail|error").sum())
        cloud = int(statuses.str.contains("azure|cloud|stored").sum())
    else:
        blocked, cloud = 0, 0

    if risk_col:
        risks = audit_df[risk_col].fillna("").astype(str).str.lower()
        high = int(risks.str.contains("high|critical").sum())
    else:
        high = 0

    cols = st.columns(4)
    with cols[0]:
        show_metric("Audit events", f"{total:,}", "Recorded in the audit database")
    with cols[1]:
        show_metric("High-risk events", f"{high:,}", "Based on available risk labels")
    with cols[2]:
        show_metric("Flagged / failed", f"{blocked:,}", "Based on event labels")
    with cols[3]:
        show_metric("Cloud / storage events", f"{cloud:,}", "Based on event labels")

    st.write("")
    left, right = st.columns([1.4, 1])

    with left:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">Recent activity</div>',
                    unsafe_allow_html=True)
        st.markdown('<div class="section-sub">Latest available audit records</div>',
                    unsafe_allow_html=True)
        if not audit_df.empty:
            st.dataframe(audit_df.head(8), use_container_width=True, hide_index=True)
        else:
            st.info(audit_error or "No audit records yet. Scan a file to begin.")
        st.markdown("</div>", unsafe_allow_html=True)

    with right:
        st.markdown('<div class="panel">', unsafe_allow_html=True)
        st.markdown('<div class="section-title">Event distribution</div>',
                    unsafe_allow_html=True)
        st.markdown('<div class="section-sub">Classification from recorded event labels</div>',
                    unsafe_allow_html=True)
        if status_col and not audit_df.empty:
            counts = audit_df[status_col].fillna("Unknown").astype(str).value_counts()
            st.bar_chart(counts)
        else:
            st.write("Event distribution will appear when audit records are available.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.caption("Metrics are derived from available audit columns; they are not live cloud-provider telemetry.")

# ---------- FILE SCANNER ----------

elif page == "File Scanner":
    st.markdown("## File scanner")
    st.caption("Inspect supported documents for sensitive data before storage.")

    with st.container(border=True):
        st.markdown("**Upload a document**")
        uploaded = st.file_uploader(
            "Supported formats: TXT, CSV, JSON, LOG, PDF and DOCX",
            type=["txt", "csv", "json", "log", "pdf", "docx"],
        )
        action = st.selectbox(
            "Storage action",
            ["Scan only", "Scan and store"],
            help="Scan and store sends the original file through your configured hybrid storage backend.",
        )

        if uploaded:
            st.caption(
                f"Selected: {uploaded.name} · "
                f"{len(uploaded.getvalue()) / 1024:.1f} KB"
            )

        run_scan = st.button(
            "Run security scan",
            type="primary",
            use_container_width=True,
        )

    if run_scan:
        if uploaded is None:
            st.warning("Please upload a file first.")

        elif len(uploaded.getvalue()) > 10 * 1024 * 1024:
            st.error("File exceeds the 10 MB upload limit.")

        else:
            try:
                with st.spinner(
                    "Extracting text and scanning for sensitive data..."
                ):
                    extracted = extract_text(uploaded)

                    if not extracted.strip():
                        st.warning(
                            "No extractable text was found in this file."
                        )

                    else:
                        result = scan_text(
                            extracted,
                            filename=uploaded.name,
                        )
                        st.success("Scan completed.")

                        st.markdown("### Scan result")

                        # Present scan results as a security report
                        if isinstance(result, dict):
                            risk = str(
                                result.get(
                                    "risk",
                                    result.get("risk_level", "UNKNOWN"),
                                )
                            ).upper()

                            scan_action = str(
                                result.get("action", "N/A")
                            ).upper()

                            findings = result.get("findings", {})
                            filename = result.get(
                                "filename", uploaded.name
                            )
                            file_hash = result.get(
                                "file_hash", "Not available"
                            )

                            risk_colors = {
                                "LOW": ("#dcfce7", "#166534"),
                                "MEDIUM": ("#fef3c7", "#92400e"),
                                "HIGH": ("#fee2e2", "#991b1b"),
                                "CRITICAL": ("#fee2e2", "#991b1b"),
                            }

                            bg, fg = risk_colors.get(
                                risk,
                                ("#e2e8f0", "#334155"),
                            )

                            st.markdown(
                                """
                                <style>
                                .scan-card {
                                    background: white;
                                    border: 1px solid #dfe7f2;
                                    border-radius: 16px;
                                    padding: 22px;
                                    margin: 12px 0 18px;
                                }
                                .scan-label {
                                    color: #64748b;
                                    font-size: 12px;
                                    font-weight: 700;
                                    text-transform: uppercase;
                                    letter-spacing: .7px;
                                }
                                .scan-value {
                                    color: #172b4d;
                                    font-size: 17px;
                                    font-weight: 650;
                                    margin-top: 7px;
                                    overflow-wrap: anywhere;
                                }
                                </style>
                                """,
                                unsafe_allow_html=True,
                            )

                            st.markdown(
                                f'<div class="scan-card">'
                                f'<span style="background:{bg};color:{fg};'
                                f'padding:7px 12px;border-radius:20px;'
                                f'font-size:13px;font-weight:750;">'
                                f'{risk} RISK</span>'
                                f'<h3 style="margin:18px 0 4px;'
                                f'color:#172b4d;">Security scan report</h3>'
                                f'<p style="color:#64748b;margin:0;">'
                                f'{filename}</p></div>',
                                unsafe_allow_html=True,
                            )

                            c1, c2, c3 = st.columns(3)

                            with c1:
                                st.markdown("**Risk level**")
                                st.markdown(f"### {risk}")

                            with c2:
                                st.markdown("**Policy action**")
                                st.markdown(f"### {scan_action}")

                            with c3:
                                st.markdown(
                                    "**Sensitive-data findings**"
                                )

                                if isinstance(findings, dict):
                                    count = sum(
                                        v
                                        if isinstance(v, int)
                                        else len(v)
                                        if isinstance(v, list)
                                        else 0
                                        for v in findings.values()
                                    )
                                    st.markdown(f"### {count}")

                                elif isinstance(findings, list):
                                    st.markdown(f"### {len(findings)}")

                                else:
                                    st.markdown("### Review")

                            with st.expander(
                                "File details",
                                expanded=False,
                            ):
                                st.write("**Filename:**", filename)
                                st.code(
                                    str(file_hash),
                                    language=None,
                                )

                            with st.expander(
                                "View detailed scan output",
                                expanded=False,
                            ):
                                st.json(result)

                        else:
                            st.info(
                                "Scan completed. Detailed result:"
                            )
                            st.write(result)

                        # Keep the existing storage workflow
                        if action == "Scan and store":
                            try:
                                storage_findings = []
                                storage_risk = "UNKNOWN"

                                if isinstance(result, dict):
                                    storage_findings = result.get(
                                        "findings", []
                                    )
                                    storage_risk = result.get(
                                        "risk",
                                        result.get(
                                            "risk_level", "UNKNOWN"
                                        ),
                                    )

                                saved = save_file_hybrid(
                                    file_bytes=uploaded.getvalue(),
                                    filename=uploaded.name,
                                    action="scan_and_store",
                                    findings=storage_findings,
                                    risk=storage_risk,
                                )

                                st.markdown("### Storage result")

                                if isinstance(
                                    saved,
                                    (
                                        dict,
                                        list,
                                        str,
                                        int,
                                        float,
                                        bool,
                                    ),
                                ):
                                    st.json(saved)
                                else:
                                    st.write(str(saved))

                            except Exception as exc:
                                st.error(
                                    f"Storage operation failed: {exc}"
                                )
                                st.info(
                                    "Check the storage configuration "
                                    "and audit log."
                                )

            except Exception as exc:
                st.error(
                    f"Could not complete the scan: {exc}"
                )
                st.caption(
                    "Check the terminal for the detailed error and "
                    "confirm the file type is supported."
                )

# ---------- AUDIT EXPLORER ----------
elif page == "Audit Explorer":
    st.markdown("## Audit explorer")
    st.caption("Search and filter recorded security and storage events.")

    if audit_error:
        st.warning(f"Audit database note: {audit_error}")

    if audit_df.empty:
        st.info("No audit records are available yet. Run a scan and refresh this page.")
    else:
        filtered = audit_df.copy()
        c1, c2 = st.columns(2)

        with c1:
            search = st.text_input("Search records", placeholder="Filename, event, status...")
        with c2:
            selected_columns = st.multiselect(
                "Columns to display",
                options=list(filtered.columns),
                default=list(filtered.columns),
            )

        if search:
            mask = filtered.astype(str).apply(
                lambda col: col.str.contains(search, case=False, na=False)
            ).any(axis=1)
            filtered = filtered[mask]

        st.markdown(f"**{len(filtered):,} records**")
        st.dataframe(
            filtered[selected_columns] if selected_columns else filtered,
            use_container_width=True,
            hide_index=True,
        )

        csv = filtered.to_csv(index=False).encode("utf-8")
        st.download_button(
            "Export filtered audit records (CSV)",
            data=csv,
            file_name="dlp_audit_export.csv",
            mime="text/csv",
        )

st.markdown("---")
st.caption("Sentinel DLP · Python · Streamlit · SQLite Audit Logging · Azure Blob Storage / Local Fallback")
