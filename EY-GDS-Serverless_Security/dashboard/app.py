import streamlit as st
import pandas as pd
import plotly.express as px

from security_engine.engine import (
    run_security_scan,
    summarize_findings,
)


# ---------------------------------------------------------
# PAGE CONFIGURATION
# ---------------------------------------------------------

st.set_page_config(
    page_title="EY GDS Serverless Security",
    page_icon="🛡️",
    layout="wide",
)


# ---------------------------------------------------------
# CUSTOM STYLING
# ---------------------------------------------------------

st.markdown(
    """
    <style>

    .main {
        padding-top: 1rem;
    }

    .dashboard-title {
        font-size: 2.4rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }

    .dashboard-subtitle {
        font-size: 1.05rem;
        opacity: 0.7;
        margin-bottom: 1.5rem;
    }

    .section-title {
        font-size: 1.35rem;
        font-weight: 600;
        margin-top: 1rem;
        margin-bottom: 0.8rem;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------
# HEADER
# ---------------------------------------------------------

st.markdown(
    '<div class="dashboard-title">'
    '🛡️ EY GDS Serverless Security'
    '</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="dashboard-subtitle">'
    'Security posture and threat monitoring dashboard'
    '</div>',
    unsafe_allow_html=True,
)

st.info(
    "Demo mode: the dashboard currently scans sample API, "
    "IAM, and cloud configuration data."
)

# ---------------------------------------------------------
# SAMPLE EVENT
# ---------------------------------------------------------

sample_event = {
    "ip": "192.168.1.100",
    "method": "TRACE",
    "path": "/users",
    "query": "id=1' OR '1'='1",
    "body": "",
    "user_agent": "Mozilla/5.0",
}

# ---------------------------------------------------------
# SAMPLE IAM POLICY
# ---------------------------------------------------------

sample_iam_policy = {
    "Statement": {
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*",
    }
}

# ---------------------------------------------------------
# SAMPLE CLOUD CONFIGURATION
# ---------------------------------------------------------

sample_configuration = {
    "s3_buckets": [
        {
            "name": "public-demo-bucket",
            "public": True,
            "encryption_enabled": False,
        }
    ],
    "lambda_functions": [
        {
            "name": "demo-function",
            "logging_enabled": False,
            "environment_encryption_enabled": False,
        }
    ],
    "api_gateways": [
        {
            "name": "demo-api",
            "authentication": "NONE",
        }
    ],
}


# ---------------------------------------------------------
# SIDEBAR
# ---------------------------------------------------------

with st.sidebar:

    st.header("⚙️ Scan Controls")

    st.write(
        "Run all security scanners against the configured "
        "dependencies, API event, IAM policy, and cloud configuration."
    )

    if st.button(
        "🔍 Run Security Scan",
        type="primary",
        use_container_width=True,
    ):

        with st.spinner("Running security scan..."):

            findings = run_security_scan(
                "requirements.txt",
                sample_event,
                sample_iam_policy,
                sample_configuration,
            )

            summary = summarize_findings(findings)

        st.session_state["findings"] = findings
        st.session_state["summary"] = summary

        st.success("Scan completed successfully.")

    st.divider()

    st.caption("Current scan configuration")

    st.write("📄 requirements.txt")
    st.write("🌐 Sample API event")
    st.write("🔐 Sample IAM policy")
    st.write("⚙️ Sample cloud configuration")

# ---------------------------------------------------------
# NO SCAN STATE
# ---------------------------------------------------------

if "findings" not in st.session_state:

    st.info(
        "👈 Run a security scan from the sidebar to view "
        "your security findings."
    )

    st.stop()


# ---------------------------------------------------------
# LOAD RESULTS
# ---------------------------------------------------------

findings = st.session_state["findings"]
summary = st.session_state["summary"]


# ---------------------------------------------------------
# SECURITY OVERVIEW
# ---------------------------------------------------------

st.markdown(
    '<div class="section-title">'
    '📊 Security Overview'
    '</div>',
    unsafe_allow_html=True,
)

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        "Total Findings",
        summary["total"],
    )

with col2:
    st.metric(
        "🔴 Critical",
        summary["CRITICAL"],
    )

with col3:
    st.metric(
        "🟠 High",
        summary["HIGH"],
    )

with col4:
    st.metric(
        "🟡 Medium",
        summary["MEDIUM"],
    )

with col5:
    st.metric(
        "🟢 Low",
        summary["LOW"],
    )


st.divider()


# ---------------------------------------------------------
# CHART DATA
# ---------------------------------------------------------

severity_data = {
    "Critical": summary["CRITICAL"],
    "High": summary["HIGH"],
    "Medium": summary["MEDIUM"],
    "Low": summary["LOW"],
}

scanner_counts = {}

for finding in findings:

    scanner = finding.scanner

    scanner_counts[scanner] = (
        scanner_counts.get(scanner, 0) + 1
    )

# ---------------------------------------------------------
# SCANNER OVERVIEW
# ---------------------------------------------------------

st.markdown(
    '<div class="section-title">'
    '🔍 Scanner Overview'
    '</div>',
    unsafe_allow_html=True,
)

scanner_names = {
    "attack_detection": "⚔️ Attack Detection",
    "dependency_scanner": "📦 Dependency Scanner",
    "iam_scanner": "🔐 IAM Scanner",
    "config_scanner": "⚙️ Config Scanner",
}

scanner_columns = st.columns(max(len(scanner_counts), 1))

if scanner_counts:

    for column, (scanner, count) in zip(
        scanner_columns,
        scanner_counts.items(),
    ):

        with column:
            display_name = scanner_names.get(
                scanner,
                scanner.replace("_", " ").title(),
            )

            st.metric(
                display_name,
                count,
            )

else:

    st.info("No scanner findings available.")

# ---------------------------------------------------------
# DASHBOARD CHARTS
# ---------------------------------------------------------

chart_col1, chart_col2 = st.columns(2)


# ---------------------------------------------------------
# SEVERITY DISTRIBUTION
# ---------------------------------------------------------

with chart_col1:

    st.markdown(
        '<div class="section-title">'
        'Severity Distribution'
        '</div>',
        unsafe_allow_html=True,
    )

    severity_df = pd.DataFrame(
        {
            "Severity": list(severity_data.keys()),
            "Findings": list(severity_data.values()),
        }
    )

    severity_df = severity_df[
        severity_df["Findings"] > 0
    ]

    if not severity_df.empty:

        fig = px.bar(
            severity_df,
            x="Severity",
            y="Findings",
            text="Findings",
        )

        fig.update_traces(
            textposition="outside"
        )

        fig.update_layout(
            xaxis_title="Severity",
            yaxis_title="Number of Findings",
            xaxis=dict(
                tickangle=0
            ),
            margin=dict(
                l=20,
                r=20,
                t=20,
                b=20,
            ),
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

    else:

        st.info(
            "No findings to display."
        )


# ---------------------------------------------------------
# FINDINGS BY SCANNER
# ---------------------------------------------------------

with chart_col2:

    st.markdown(
        '<div class="section-title">'
        'Findings by Scanner'
        '</div>',
        unsafe_allow_html=True,
    )

    if scanner_counts:

        scanner_df = pd.DataFrame(
            {
                "Scanner": list(scanner_counts.keys()),
                "Findings": list(scanner_counts.values()),
            }
        )

        fig = px.bar(
            scanner_df,
            x="Scanner",
            y="Findings",
            text="Findings",
        )

        fig.update_traces(
            textposition="outside"
        )

        fig.update_layout(
            xaxis_title="Scanner",
            yaxis_title="Number of Findings",
            xaxis=dict(
                tickangle=0
            ),
            margin=dict(
                l=20,
                r=20,
                t=20,
                b=20,
            ),
        )

        st.plotly_chart(
            fig,
            use_container_width=True,
        )

    else:

        st.info(
            "No scanner findings to display."
        )


st.divider()


# ---------------------------------------------------------
# FINDING FILTERS
# ---------------------------------------------------------

st.markdown(
    '<div class="section-title">'
    '🚨 Security Findings'
    '</div>',
    unsafe_allow_html=True,
)

filter_col1, filter_col2 = st.columns(2)


# ---------------------------------------------------------
# SEVERITY FILTER
# ---------------------------------------------------------

with filter_col1:

    severity_options = [
        "ALL",
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]

    selected_severity = st.selectbox(
        "Filter by severity",
        severity_options,
    )


# ---------------------------------------------------------
# SCANNER FILTER
# ---------------------------------------------------------

with filter_col2:

    scanner_options = ["ALL"]

    scanner_options.extend(
        sorted(scanner_counts.keys())
    )

    selected_scanner = st.selectbox(
        "Filter by scanner",
        scanner_options,
    )


# ---------------------------------------------------------
# FILTER FINDINGS
# ---------------------------------------------------------

filtered_findings = findings.copy()


if selected_severity != "ALL":

    filtered_findings = [
        finding
        for finding in filtered_findings
        if finding.severity.upper() == selected_severity
    ]


if selected_scanner != "ALL":

    filtered_findings = [
        finding
        for finding in filtered_findings
        if finding.scanner == selected_scanner
    ]


# ---------------------------------------------------------
# FINDINGS TABLE
# ---------------------------------------------------------

if not filtered_findings:

    st.success(
        "No findings match the selected filters."
    )

else:

    table_data = []

    for finding in filtered_findings:

        table_data.append(
            {
                "Severity": finding.severity,
                "Scanner": finding.scanner,
                "Finding": finding.title,
                "Resource": finding.resource,
            }
        )

    findings_df = pd.DataFrame(table_data)

    st.dataframe(
        findings_df,
        use_container_width=True,
        hide_index=True,
    )


# ---------------------------------------------------------
# FINDING DETAILS
# ---------------------------------------------------------

st.markdown(
    '<div class="section-title">'
    '🔎 Finding Details'
    '</div>',
    unsafe_allow_html=True,
)


for index, finding in enumerate(
    filtered_findings,
    start=1,
):

    with st.expander(
        f"{index}. [{finding.severity}] "
        f"{finding.title}"
    ):

        detail_col1, detail_col2 = st.columns(2)

        with detail_col1:

            st.write(
                f"**Scanner:** {finding.scanner}"
            )

            st.write(
                f"**Severity:** {finding.severity}"
            )

            st.write(
                f"**Resource:** {finding.resource}"
            )

        with detail_col2:

            st.write(
                f"**Evidence:** "
                f"{finding.evidence or 'None'}"
            )

        st.write(
            f"**Description:** "
            f"{finding.description}"
        )

        st.write(
            f"**Recommendation:** "
            f"{finding.recommendation}"
        )