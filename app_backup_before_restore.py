
import sqlite3
from io import BytesIO
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
from docx import Document
from pypdf import PdfReader

from dlp.audit import DB_PATH
from dlp.hybrid_storage import save_file_hybrid
from dlp.pipeline import scan_text


# =========================================================
# CONFIGURATION
# =========================================================

MAX_FILE_SIZE_MB = 10
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

AUDIT_COLUMNS = [
    "timestamp",
    "filename",
    "risk",
    "action",
    "destination",
    "status",
]

st.set_page_config(
    page_title="CloudGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# =========================================================
# STYLING
# =========================================================

st.markdown(
    """
    <style>
    .stApp {
        background: #f6f8fc;
        color: #172033;
    }

    [data-testid="stSidebar"],
    [data-testid="stSidebarCollapsedControl"] {
        display: none;
    }

    header[data-testid="stHeader"] {
        background: transparent;
    }

    .block-container {
        max-width: 1500px;
        padding: 1.1rem 2.2rem 3rem;
    }

    .brand {
        color: #172033;
        font-size: 1.5rem;
        font-weight: 850;
        letter-spacing: -0.05em;
    }

    .brand-icon {
        color: #315ee7;
    }

    .brand-caption {
        color: #8792a5;
        font-size: 0.68rem;
        font-weight: 700;
        letter-spacing: 0.1em;
    }

    .nav-divider {
        border: none;
        border-top: 1px solid #e2e8f0;
        margin: 0.7rem 0 1.8rem;
    }

    .page-kicker {
        color: #315ee7;
        font-size: 0.72rem;
        font-weight: 750;
        letter-spacing: 0.12em;
        margin-bottom: 0.35rem;
    }

    .page-title {
        color: #172033 !important;
        font-size: 2rem;
        font-weight: 800;
        letter-spacing: -0.05em;
        line-height: 1.2;
        margin: 0 0 0.45rem;
    }

    .page-description {
        color: #667085 !important;
        font-size: 0.94rem;
        line-height: 1.6;
        margin-bottom: 1.5rem;
    }

    div[data-testid="stMetric"] {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 13px;
        padding: 1rem 1.1rem;
        min-height: 105px;
        box-shadow: 0 2px 8px rgba(20, 35, 70, 0.025);
    }

    div[data-testid="stMetricLabel"] {
        color: #667085 !important;
        font-size: 0.82rem;
    }

    div[data-testid="stMetricValue"] {
        color: #172033 !important;
        font-weight: 800;
    }

    .section-heading {
        color: #172033;
        font-size: 1.12rem;
        font-weight: 750;
        margin: 1.2rem 0 0.25rem;
    }

    .section-description {
        color: #667085;
        font-size: 0.84rem;
        margin-bottom: 0.8rem;
    }

    .upload-panel {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 13px;
        padding: 1rem;
        margin-bottom: 1rem;
    }

    [data-testid="stFileUploader"] {
        background: #ffffff;
        border: 1px dashed #b8c5d8;
        border-radius: 12px;
        padding: 0.7rem;
    }

    [data-testid="stFileUploader"] button {
        color: #172033 !important;
        background: #ffffff !important;
        border: 1px solid #d5dce7 !important;
    }

    div[data-baseweb="select"] > div,
    div[data-baseweb="input"] > div {
        background: #ffffff !important;
        border-color: #d5dce7 !important;
        border-radius: 9px !important;
    }

    div[data-baseweb="select"] *,
    div[data-baseweb="input"] input {
        color: #172033 !important;
    }

    div.stButton > button,
    div.stDownloadButton > button,
    div[data-testid="stFormSubmitButton"] button {
        min-height: 2.65rem;
        border-radius: 9px;
        font-weight: 650;
    }

    div.stButton > button[kind="primary"],
    div[data-testid="stFormSubmitButton"] button[kind="primary"] {
        background: #315ee7 !important;
        border-color: #315ee7 !important;
        color: #ffffff !important;
    }

    div.stButton > button[kind="primary"]:hover,
    div[data-testid="stFormSubmitButton"] button[kind="primary"]:hover {
        background: #244bd0 !important;
        border-color: #244bd0 !important;
    }

    div.stDownloadButton > button {
        background: #ffffff !important;
        color: #244bd0 !important;
        border: 1px solid #cbd7f5 !important;
    }

    div[data-testid="stDataFrame"] {
        border: 1px solid #e2e8f0;
        border-radius: 11px;
        overflow: hidden;
        background: #ffffff;
    }

    @media (max-width: 850px) {
        .block-container {
            padding: 1rem;
        }

        .page-title {
            font-size: 1.65rem;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# =========================================================
# DATABASE ACCESS
# =========================================================

def load_audit_log():
    """
    Read the existing audit database.

    Returns (dataframe, error_message).
    A database error is kept separate from a genuinely empty table.
    """
    if not Path(DB_PATH).exists():
        return (
            pd.DataFrame(columns=AUDIT_COLUMNS),
            f"Audit database not found at: {DB_PATH}",
        )

    try:
        with sqlite3.connect(str(DB_PATH), timeout=5) as connection:
            tables = connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table' AND name = 'audit_log'
                """
            ).fetchall()

            if not tables:
                return (
                    pd.DataFrame(columns=AUDIT_COLUMNS),
                    "The database exists, but the audit_log table is missing.",
                )

            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(audit_log)"
                ).fetchall()
            }

            required = {
                "id",
                "timestamp",
                "filename",
                "risk",
                "action",
                "destination",
                "status",
            }

            missing = required - columns
            if missing:
                return (
                    pd.DataFrame(columns=AUDIT_COLUMNS),
                    "Missing audit database columns: "
                    + ", ".join(sorted(missing)),
                )

            df = pd.read_sql_query(
                """
                SELECT timestamp, filename, risk, action,
                       destination, status
                FROM audit_log
                ORDER BY id DESC
                """,
                connection,
            )

            return df, None

    except (sqlite3.Error, pd.errors.DatabaseError) as exc:
        return (
            pd.DataFrame(columns=AUDIT_COLUMNS),
            f"Could not read audit database: {type(exc).__name__}: {exc}",
        )


def norm_column(df, name):
    if name not in df.columns:
        return pd.Series("", index=df.index, dtype="string")

    return (
        df[name]
        .fillna("")
        .astype(str)
        .str.strip()
        .str.upper()
    )


def calculate_metrics(df):
    """Count audit events, not unique files."""
    if df.empty:
        return {
            "events": 0,
            "scans": 0,
            "high_critical": 0,
            "review_actions": 0,
            "stored": 0,
        }

    risk = norm_column(df, "risk")
    action = norm_column(df, "action")
    status = norm_column(df, "status")

    return {
        "events": len(df),
        "scans": int(status.eq("SCANNED").sum()),
        "high_critical": int(
            risk.isin(["HIGH", "CRITICAL"]).sum()
        ),
        "review_actions": int(
            action.isin(["QUARANTINE", "BLOCK"]).sum()
        ),
        "stored": int(
            status.isin(
                ["STORED_AZURE", "STORED_LOCAL_FALLBACK"]
            ).sum()
        ),
    }


# =========================================================
# FILE EXTRACTION
# =========================================================

def extract_text(uploaded_file):
    """Extract readable text from supported file types."""
    filename = uploaded_file.name.lower()
    file_bytes = uploaded_file.getvalue()

    if filename.endswith(".pdf"):
        reader = PdfReader(BytesIO(file_bytes))
        return "\n".join(
            page.extract_text() or ""
            for page in reader.pages
        )

    if filename.endswith(".docx"):
        document = Document(BytesIO(file_bytes))
        sections = [
            paragraph.text
            for paragraph in document.paragraphs
        ]

        for table in document.tables:
            for row in table.rows:
                sections.append(
                    " | ".join(cell.text for cell in row.cells)
                )

        return "\n".join(sections)

    if filename.endswith(".doc"):
        raise ValueError(
            "Legacy .doc files are not supported. "
            "Save the document as .docx and try again."
        )

    return file_bytes.decode("utf-8-sig")


# =========================================================
# PRESENTATION HELPERS
# =========================================================

def page_heading(kicker, title, description):
    st.markdown(
        f"""
        <div class="page-kicker">{kicker}</div>
        <h1 class="page-title">{title}</h1>
        <p class="page-description">{description}</p>
        """,
        unsafe_allow_html=True,
    )


def risk_badge(risk):
    risk = str(risk).strip().upper()

    palette = {
        "LOW": ("#dcfce7", "#166534"),
        "MEDIUM": ("#fef3c7", "#92400e"),
        "HIGH": ("#ffedd5", "#9a3412"),
        "CRITICAL": ("#fee2e2", "#991b1b"),
    }

    bg, fg = palette.get(risk, ("#e2e8f0", "#334155"))

    st.markdown(
        f"""
        <span style="
            display:inline-block;
            padding:6px 11px;
            border-radius:999px;
            background:{bg};
            color:{fg};
            font-weight:750;
            font-size:0.82rem;
        ">{risk or "UNKNOWN"} RISK</span>
        """,
        unsafe_allow_html=True,
    )


def action_message(action):
    action = str(action).strip().upper()

    if action == "BLOCK":
        st.error("BLOCK — the policy selected the blocked zone.")
    elif action == "QUARANTINE":
        st.warning("QUARANTINE — the file is designated for review.")
    elif action == "FLAG":
        st.warning("FLAG — the file has been flagged for review.")
    elif action == "ALLOW":
        st.success("ALLOW — the policy permits the file.")
    else:
        st.info(f"Policy action: {action or 'UNKNOWN'}")


def make_chart(series, category_name):
    chart_data = (
        series.rename_axis(category_name)
        .rename("Events")
        .reset_index()
    )

    chart = (
        alt.Chart(chart_data)
        .mark_bar(
            color="#4775e8",
            cornerRadiusTopLeft=5,
            cornerRadiusTopRight=5,
        )
        .encode(
            x=alt.X(
                f"{category_name}:N",
                title=None,
                axis=alt.Axis(
                    labelAngle=0,
                    labelColor="#526078",
                    labelLimit=150,
                    ticks=False,
                    domain=False,
                ),
            ),
            y=alt.Y(
                "Events:Q",
                title=None,
                scale=alt.Scale(domainMin=0),
                axis=alt.Axis(
                    labelColor="#7b879a",
                    gridColor="#edf0f5",
                    tickMinStep=1,
                    domain=False,
                ),
            ),
            tooltip=[
                alt.Tooltip(f"{category_name}:N", title=category_name),
                alt.Tooltip("Events:Q", title="Events"),
            ],
        )
        .properties(height=245, background="#ffffff")
        .configure_view(stroke="#ffffff")
        .configure_axis(
            labelFont="Arial",
            labelFontSize=11,
        )
    )

    st.altair_chart(chart, use_container_width=True)


# =========================================================
# TOP NAVIGATION
# =========================================================

nav_left, nav_right = st.columns(
    [1.1, 2.4],
    vertical_alignment="center",
)

with nav_left:
    st.markdown(
        """
        <div class="brand">
            <span class="brand-icon">◈</span> CloudGuard
        </div>
        <div class="brand-caption">DATA LOSS PREVENTION</div>
        """,
        unsafe_allow_html=True,
    )

with nav_right:
    page = st.radio(
        "Navigation",
        ["Overview", "File Scanner", "Audit Explorer"],
        horizontal=True,
        label_visibility="collapsed",
        key="top_navigation",
    )

st.markdown(
    '<hr class="nav-divider">',
    unsafe_allow_html=True,
)

audit_df, audit_error = load_audit_log()
metrics = calculate_metrics(audit_df)


# =========================================================
# SHOW DATABASE ERRORS
# =========================================================

if audit_error:
    st.error(audit_error)


# =========================================================
# OVERVIEW
# =========================================================

if page == "Overview":
    page_heading(
        "OVERVIEW",
        "Security at a glance",
        "Monitor recorded scans, policy decisions, and storage activity.",
    )

    a, b, c, d = st.columns(4)
    a.metric("Audit events", metrics["events"])
    b.metric("Scan events", metrics["scans"])
    c.metric("High / critical events", metrics["high_critical"])
    d.metric("Successful storage events", metrics["stored"])

    st.caption(
        "Metrics count audit events, not unique files. "
        "One file may generate multiple events."
    )

    st.markdown(
        '<div class="section-heading">Activity analytics</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="section-description">Distribution of recorded audit events.</div>',
        unsafe_allow_html=True,
    )

    if audit_df.empty:
        if not audit_error:
            st.info("No audit events have been recorded yet.")
    else:
        risk_order = [
            "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"
        ]
        action_order = [
            "ALLOW", "FLAG", "QUARANTINE", "BLOCK", "UNKNOWN"
        ]

        risk_counts = (
            norm_column(audit_df, "risk")
            .replace("", "UNKNOWN")
            .value_counts()
            .reindex(risk_order, fill_value=0)
        )

        action_counts = (
            norm_column(audit_df, "action")
            .replace("", "UNKNOWN")
            .value_counts()
            .reindex(action_order, fill_value=0)
        )

        left, right = st.columns(2)

        with left:
            st.markdown("**Events by risk level**")
            make_chart(risk_counts, "Risk")

        with right:
            st.markdown("**Events by policy action**")
            make_chart(action_counts, "Action")

        st.markdown(
            '<div class="section-heading">Recent activity</div>',
            unsafe_allow_html=True,
        )

        st.dataframe(
            audit_df.head(8),
            use_container_width=True,
            hide_index=True,
        )

    if st.button("Refresh data"):
        st.rerun()


# =========================================================
# FILE SCANNER
# =========================================================

elif page == "File Scanner":
    page_heading(
        "INSPECTION",
        "Scan a file",
        "Inspect file contents, evaluate DLP policies, and store the original file.",
    )

    st.markdown(
        """
        <div class="upload-panel">
            <strong>Choose a file for inspection</strong>
            <div class="section-description">
                TXT, CSV, JSON, LOG, PDF, DOCX · Maximum 10 MB
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # The uploader and submit button share a form.
    # This gives the scan a single, explicit submission event.
    with st.form("cloudguard_scan_form", clear_on_submit=False):
        uploaded_file = st.file_uploader(
            "Upload file",
            type=["txt", "csv", "json", "log", "pdf", "doc", "docx"],
            max_upload_size=MAX_FILE_SIZE_MB,
            help="Maximum upload size: 10 MB.",
        )

        submitted = st.form_submit_button(
            "Run DLP scan",
            type="primary",
            use_container_width=True,
        )

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()

        c1, c2, c3 = st.columns(3)
        c1.metric("Selected file", uploaded_file.name)
        c2.metric("Size", f"{len(file_bytes) / 1024:.1f} KB")
        c3.metric(
            "Format",
            Path(uploaded_file.name).suffix.upper() or "Unknown",
        )

    if submitted:
        if uploaded_file is None:
            st.warning("Choose a file before running the scan.")

        else:
            file_bytes = uploaded_file.getvalue()

            if len(file_bytes) > MAX_FILE_SIZE_BYTES:
                st.error(
                    f"The file exceeds the {MAX_FILE_SIZE_MB} MB limit."
                )

            else:
                try:
                    with st.spinner("Extracting text and scanning..."):
                        extracted_text = extract_text(uploaded_file)

                        if not extracted_text.strip():
                            st.warning(
                                "No readable text was found. "
                                "Scanned-image PDFs may require OCR."
                            )
                            st.stop()

                        result = scan_text(
                            extracted_text,
                            filename=uploaded_file.name,
                        )

                    # Keep the existing storage module and its API.
                    with st.spinner("Storing the original file..."):
                        storage_result = save_file_hybrid(
                            file_bytes=file_bytes,
                            filename=uploaded_file.name,
                            action=result["action"],
                            findings=result["findings"],
                            risk=result["risk"],
                        )

                    st.session_state["cloudguard_last_scan"] = {
                        "filename": uploaded_file.name,
                        "result": result,
                        "storage_result": storage_result,
                    }
                    st.session_state.pop("cloudguard_scan_error", None)

                except Exception as exc:
                    st.session_state.pop("cloudguard_last_scan", None)
                    st.session_state["cloudguard_scan_error"] = (
                        f"{type(exc).__name__}: {exc}"
                    )

    scan_error = st.session_state.get("cloudguard_scan_error")

    if scan_error:
        st.error(f"Scan or storage failed: {scan_error}")

    last_scan = st.session_state.get("cloudguard_last_scan")

    if last_scan:
        st.divider()
        st.markdown("### Scan result")
        st.caption(f"File: {last_scan['filename']}")

        result = last_scan["result"]
        storage_result = last_scan["storage_result"]

        r1, r2, r3 = st.columns(3)

        with r1:
            st.caption("Risk classification")
            risk_badge(result["risk"])

        r2.metric("Policy decision", result["action"])
        r3.metric(
            "Finding categories",
            len(result["findings"]),
        )

        st.markdown("### Detection findings")
        st.json(result["findings"])

        st.markdown("### Storage outcome")

        s1, s2 = st.columns(2)

        with s1:
            st.caption("Storage provider")
            st.write(
                str(storage_result.get("storage", "Unknown")).upper()
            )

        with s2:
            st.caption("Policy destination")
            st.code(
                str(storage_result.get("destination", "Unknown"))
            )

        st.write(
            "**Fallback used:**",
            storage_result.get("fallback_used", "Unknown"),
        )
        st.write(
            "**Stored location:**",
            storage_result.get("location", "Unknown"),
        )

        with st.expander("SHA-256 content hash"):
            st.code(
                str(storage_result.get("file_hash", "Unavailable"))
            )

        if storage_result.get("fallback_used"):
            st.warning(
                "The storage module reports that local fallback was used."
            )
        else:
            st.success(
                "The storage module reports a successful cloud upload."
            )

        action_message(result["action"])


# =========================================================
# AUDIT EXPLORER
# =========================================================

elif page == "Audit Explorer":
    page_heading(
        "AUDIT & COMPLIANCE",
        "Audit Explorer",
        "Find and export recorded scans, policy decisions, and storage outcomes.",
    )

    if audit_df.empty:
        if not audit_error:
            st.info("No audit events have been recorded yet.")

    else:
        def filter_options(column):
            values = (
                audit_df[column]
                .fillna("UNKNOWN")
                .astype(str)
                .str.strip()
            )
            values = sorted(v for v in values.unique() if v)
            return ["All"] + values

        f1, f2, f3 = st.columns(3)

        with f1:
            selected_risk = st.selectbox(
                "Risk level",
                filter_options("risk"),
                key="audit_risk_filter",
            )

        with f2:
            selected_action = st.selectbox(
                "Policy action",
                filter_options("action"),
                key="audit_action_filter",
            )

        with f3:
            selected_status = st.selectbox(
                "Event status",
                filter_options("status"),
                key="audit_status_filter",
            )

        search = st.text_input(
            "Search filename or destination",
            placeholder="Search audit records...",
            key="audit_search",
        )

        filtered = audit_df.copy()

        if selected_risk != "All":
            filtered = filtered[
                filtered["risk"].fillna("UNKNOWN")
                .astype(str).str.strip().str.casefold()
                == selected_risk.casefold()
            ]

        if selected_action != "All":
            filtered = filtered[
                filtered["action"].fillna("UNKNOWN")
                .astype(str).str.strip().str.casefold()
                == selected_action.casefold()
            ]

        if selected_status != "All":
            filtered = filtered[
                filtered["status"].fillna("UNKNOWN")
                .astype(str).str.strip().str.casefold()
                == selected_status.casefold()
            ]

        if search.strip():
            query = search.strip()

            filename_match = (
                filtered["filename"].fillna("").astype(str)
                .str.contains(query, case=False, na=False, regex=False)
            )
            destination_match = (
                filtered["destination"].fillna("").astype(str)
                .str.contains(query, case=False, na=False, regex=False)
            )

            filtered = filtered[
                filename_match | destination_match
            ]

        st.caption(
            f"Showing {len(filtered)} of {len(audit_df)} audit events"
        )

        st.dataframe(
            filtered,
            use_container_width=True,
            hide_index=True,
        )

        st.download_button(
            "Download CSV",
            data=filtered.to_csv(index=False).encode("utf-8"),
            file_name="cloudguard_audit_log.csv",
            mime="text/csv",
            key="audit_csv_download",
        )
