import json
import re
from pathlib import Path

import pandas as pd
import streamlit as st


# ======================================================
# DATA FILE
# ======================================================

DATA_FILE = Path(
    "data/processed/final_cti.json"
)

VALIDATION_FILE = Path(
    "data/processed/validation_report.json"
)


# ======================================================
# PAGE CONFIGURATION
# ======================================================

st.set_page_config(
    page_title="OSINT CTI Dashboard",
    page_icon="🛡️",
    layout="wide"
)


# ======================================================
# LOAD DATA
# ======================================================

@st.cache_data
def load_data():

    if not DATA_FILE.exists():
        return []

    with DATA_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


@st.cache_data
def load_validation():

    if not VALIDATION_FILE.exists():
        return {}

    with VALIDATION_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


records = load_data()

validation_report = load_validation()


# ======================================================
# HEADER
# ======================================================

st.title(
    "🛡️ OSINT Cyber Threat Intelligence Dashboard"
)

st.caption(
    "Provenance-Aware Vulnerability Intelligence "
    "and Automated Threat Correlation"
)


# ======================================================
# DATA CHECK
# ======================================================

if not records:

    st.error(
        "No CTI data found. "
        "Run the CTI pipeline first."
    )

    st.stop()


# ======================================================
# BASIC DATA PREPARATION
# ======================================================

total_records = len(records)


# ------------------------------------------------------
# NVD availability
# ------------------------------------------------------

nvd_available = sum(
    1
    for record in records
    if record.get("nvd") is not None
)


# ------------------------------------------------------
# KEV matches
# ------------------------------------------------------

kev_matches = sum(
    1
    for record in records
    if record.get(
        "exploitation_status"
    ) == "KNOWN_EXPLOITED"
)


# ------------------------------------------------------
# Corroboration
# ------------------------------------------------------

corroborated = sum(
    1
    for record in records
    if record.get(
        "provenance",
        {}
    ).get(
        "corroborated",
        False
    )
)


# ------------------------------------------------------
# Confidence scores
# ------------------------------------------------------

confidence_scores = [
    record.get(
        "confidence",
        {}
    ).get(
        "score"
    )
    for record in records
    if record.get(
        "confidence",
        {}
    ).get(
        "score"
    ) is not None
]


average_confidence = (
    sum(confidence_scores)
    / len(confidence_scores)
    if confidence_scores
    else 0
)


# ======================================================
# TOP METRICS
# ======================================================

st.subheader("CTI Overview")


col1, col2, col3, col4, col5 = st.columns(5)


with col1:

    st.metric(
        "Total CVEs",
        total_records
    )


with col2:

    st.metric(
        "NVD Available",
        nvd_available
    )


with col3:

    st.metric(
        "Known Exploited",
        kev_matches
    )


with col4:

    st.metric(
        "Corroborated",
        corroborated
    )


with col5:

    st.metric(
        "Avg Confidence",
        f"{average_confidence:.3f}"
    )


# ======================================================
# EVIDENCE COVERAGE
# ======================================================

st.subheader("Evidence Coverage")


nvd_percentage = (
    nvd_available / total_records * 100
    if total_records
    else 0
)


kev_percentage = (
    kev_matches / total_records * 100
    if total_records
    else 0
)


corroboration_percentage = (
    corroborated / total_records * 100
    if total_records
    else 0
)


coverage_data = pd.DataFrame(
    {
        "Metric": [
            "NVD Coverage",
            "KEV Match Rate",
            "Corroboration Rate"
        ],
        "Percentage": [
            nvd_percentage,
            kev_percentage,
            corroboration_percentage
        ]
    }
)


st.bar_chart(
    coverage_data.set_index("Metric")
)


# ======================================================
# DATA QUALITY
# ======================================================

st.subheader("Data Quality")


# ------------------------------------------------------
# Quality counters
# ------------------------------------------------------

complete_records = 0

valid_cve_count = 0

cvss_available_count = 0

valid_cvss_count = 0

confidence_available_count = 0

provenance_available_count = 0

kev_status_valid_count = 0


# ------------------------------------------------------
# Check every record
# ------------------------------------------------------

for record in records:

    cve_id = record.get(
        "cve_id",
        ""
    )


    nvd = record.get(
        "nvd"
    )

    if not isinstance(nvd, dict):
        nvd = {}


    confidence = record.get(
        "confidence",
        {}
    )

    if not isinstance(confidence, dict):
        confidence = {}


    provenance = record.get(
        "provenance",
        {}
    )

    if not isinstance(provenance, dict):
        provenance = {}


    # --------------------------------------------------
    # CVE validation
    # --------------------------------------------------

    cve_pattern = r"^CVE-\d{4}-\d{4,7}$"

    if re.match(
        cve_pattern,
        str(cve_id).strip().upper()
    ):

        valid_cve_count += 1


    # --------------------------------------------------
    # NVD / CVSS validation
    # --------------------------------------------------

    cvss_score = nvd.get(
        "cvss_score"
    )

    if cvss_score is not None:

        cvss_available_count += 1

        try:

            cvss_value = float(
                cvss_score
            )

            if 0 <= cvss_value <= 10:

                valid_cvss_count += 1

        except (
            TypeError,
            ValueError
        ):

            pass


    # --------------------------------------------------
    # Confidence validation
    # --------------------------------------------------

    confidence_score = confidence.get(
        "score"
    )

    if confidence_score is not None:

        try:

            confidence_value = float(
                confidence_score
            )

            if 0 <= confidence_value <= 1:

                confidence_available_count += 1

        except (
            TypeError,
            ValueError
        ):

            pass


    # --------------------------------------------------
    # Provenance validation
    # --------------------------------------------------

    source_count = provenance.get(
        "source_count",
        0
    )

    if source_count > 0:

        provenance_available_count += 1


    # --------------------------------------------------
    # KEV status validation
    # --------------------------------------------------

    exploitation_status = record.get(
        "exploitation_status",
        "UNKNOWN"
    )

    valid_kev_statuses = [
        "KNOWN_EXPLOITED",
        "NOT_IN_KEV",
        "UNKNOWN"
    ]

    if exploitation_status in valid_kev_statuses:

        kev_status_valid_count += 1


    # --------------------------------------------------
    # Complete record
    # --------------------------------------------------

    if (
        nvd
        and confidence.get("score") is not None
        and provenance.get("source_count", 0) > 0
        and cve_id
    ):

        complete_records += 1


# ======================================================
# DATA QUALITY RATES
# ======================================================

complete_record_rate = (
    complete_records
    / total_records
    * 100
    if total_records
    else 0
)


valid_cve_rate = (
    valid_cve_count
    / total_records
    * 100
    if total_records
    else 0
)


cvss_availability_rate = (
    cvss_available_count
    / total_records
    * 100
    if total_records
    else 0
)


valid_cvss_rate = (
    valid_cvss_count
    / cvss_available_count
    * 100
    if cvss_available_count
    else 0
)


confidence_rate = (
    confidence_available_count
    / total_records
    * 100
    if total_records
    else 0
)


provenance_rate = (
    provenance_available_count
    / total_records
    * 100
    if total_records
    else 0
)


kev_status_rate = (
    kev_status_valid_count
    / total_records
    * 100
    if total_records
    else 0
)


# ======================================================
# DATA QUALITY METRICS
# ======================================================

quality_col1, quality_col2, quality_col3 = st.columns(3)


with quality_col1:

    st.metric(
        "Complete CTI Records",
        f"{complete_record_rate:.2f}%"
    )


with quality_col2:

    st.metric(
        "Valid CVE IDs",
        f"{valid_cve_rate:.2f}%"
    )


with quality_col3:

    st.metric(
        "Confidence Valid",
        f"{confidence_rate:.2f}%"
    )


quality_col4, quality_col5, quality_col6 = st.columns(3)


with quality_col4:

    st.metric(
        "CVSS Available",
        f"{cvss_availability_rate:.2f}%"
    )


with quality_col5:

    st.metric(
        "CVSS Values Valid",
        f"{valid_cvss_rate:.2f}%"
    )


with quality_col6:

    st.metric(
        "Provenance Available",
        f"{provenance_rate:.2f}%"
    )


# ======================================================
# DATA QUALITY TABLE
# ======================================================

quality_data = pd.DataFrame(
    {
        "Quality Check": [
            "Complete CTI Records",
            "Valid CVE IDs",
            "CVSS Available",
            "Valid CVSS Values",
            "Confidence Score Valid",
            "Provenance Available",
            "Valid KEV Status"
        ],
        "Valid Records": [
            complete_records,
            valid_cve_count,
            cvss_available_count,
            valid_cvss_count,
            confidence_available_count,
            provenance_available_count,
            kev_status_valid_count
        ],
        "Total Records": [
            total_records,
            total_records,
            total_records,
            cvss_available_count,
            total_records,
            total_records,
            total_records
        ],
        "Rate (%)": [
            round(
                complete_record_rate,
                2
            ),
            round(
                valid_cve_rate,
                2
            ),
            round(
                cvss_availability_rate,
                2
            ),
            round(
                valid_cvss_rate,
                2
            ),
            round(
                confidence_rate,
                2
            ),
            round(
                provenance_rate,
                2
            ),
            round(
                kev_status_rate,
                2
            )
        ]
    }
)


st.dataframe(
    quality_data,
    use_container_width=True,
    hide_index=True
)


st.caption(
    "Data quality metrics describe the completeness and "
    "validity of the collected CTI records. "
    "They do not represent threat severity."
)


# ======================================================
# AUTOMATED VALIDATION
# ======================================================

st.subheader("Automated Data Validation")

validation_summary = validation_report.get(
    "validation_summary",
    {}
)

overall_status = validation_summary.get(
    "overall_status",
    "NOT_RUN"
)

validation_rate = validation_summary.get(
    "validation_rate",
    0
)

passed_records = validation_summary.get(
    "passed_records",
    0
)

failed_records = validation_summary.get(
    "failed_records",
    0
)

duplicate_cves = validation_summary.get(
    "duplicate_cves",
    []
)

warning_count = validation_summary.get(
    "warning_count",
    0
)


# ------------------------------------------------------
# Validation metrics
# ------------------------------------------------------

validation_col1, validation_col2, validation_col3, validation_col4 = (
    st.columns(4)
)

with validation_col1:

    st.metric(
        "Validation Status",
        overall_status
    )

with validation_col2:

    st.metric(
        "Validation Rate",
        f"{validation_rate:.2f}%"
    )

with validation_col3:

    st.metric(
        "Failed Records",
        failed_records
    )

with validation_col4:

    st.metric(
        "Warnings",
        warning_count
    )


# ------------------------------------------------------
# Status message
# ------------------------------------------------------

if overall_status == "PASS":

    st.success(
        "All automated CTI validation checks passed."
    )

elif overall_status == "FAIL":

    st.error(
        "One or more automated CTI validation checks failed."
    )

else:

    st.warning(
        "Validation report has not been generated yet."
    )


# ------------------------------------------------------
# Duplicate information
# ------------------------------------------------------

if duplicate_cves:

    st.warning(
        "Duplicate CVEs detected:"
    )

    for cve in duplicate_cves:

        st.write(
            f"- {cve}"
        )


# ------------------------------------------------------
# Validation checks
# ------------------------------------------------------

checks = validation_report.get(
    "checks",
    []
)

if checks:

    with st.expander(
        "Validation Checks Performed"
    ):

        for check in checks:

            st.write(
                f"✓ {check}"
            )


# ======================================================
# CREATE TABLE DATA
# ======================================================

table_rows = []


for record in records:

    cve_id = record.get(
        "cve_id",
        "UNKNOWN"
    )


    nvd = record.get(
        "nvd"
    )

    if not isinstance(nvd, dict):
        nvd = {}


    kev = record.get(
        "kev",
        {}
    )

    if not isinstance(kev, dict):
        kev = {}


    provenance = record.get(
        "provenance",
        {}
    )

    if not isinstance(provenance, dict):
        provenance = {}


    confidence = record.get(
        "confidence",
        {}
    )

    if not isinstance(confidence, dict):
        confidence = {}


    risk = record.get(
        "risk",
        {}
    )

    if not isinstance(risk, dict):
        risk = {}


    table_rows.append(
        {
            "CVE": cve_id,

            "CVSS": nvd.get(
                "cvss_score"
            ),

            "Severity": nvd.get(
                "severity"
            ),

            "Exploitation": record.get(
                "exploitation_status",
                "UNKNOWN"
            ),

            "KEV": kev.get(
                "known_exploited",
                False
            ),

            "Sources": provenance.get(
                "source_count",
                0
            ),

            "Corroborated":
                provenance.get(
                    "corroborated",
                    False
                ),

            "Confidence":
                confidence.get(
                    "score"
                ),

            "Confidence Category":
                confidence.get(
                    "category"
                ),

            "Risk":
                risk.get(
                    "risk_level"
                )
        }
    )


df = pd.DataFrame(
    table_rows
)


# ======================================================
# SEARCH AND FILTER
# ======================================================

st.subheader("CTI Records")


search = st.text_input(
    "Search CVE",
    placeholder="Example: CVE-2026-81578"
)


severity_options = [
    "ALL"
] + sorted(
    [
        str(value)
        for value in df["Severity"]
        .dropna()
        .unique()
    ]
)


selected_severity = st.selectbox(
    "Severity Filter",
    severity_options
)


exploitation_options = [
    "ALL",
    "KNOWN_EXPLOITED",
    "NOT_IN_KEV"
]


selected_exploitation = st.selectbox(
    "Exploitation Filter",
    exploitation_options
)


filtered_df = df.copy()


# ------------------------------------------------------
# Search
# ------------------------------------------------------

if search:

    filtered_df = filtered_df[
        filtered_df["CVE"]
        .str.contains(
            search,
            case=False,
            na=False
        )
    ]


# ------------------------------------------------------
# Severity
# ------------------------------------------------------

if selected_severity != "ALL":

    filtered_df = filtered_df[
        filtered_df["Severity"]
        == selected_severity
    ]


# ------------------------------------------------------
# Exploitation
# ------------------------------------------------------

if selected_exploitation != "ALL":

    filtered_df = filtered_df[
        filtered_df["Exploitation"]
        == selected_exploitation
    ]


st.write(
    f"Showing {len(filtered_df)} "
    f"of {total_records} records"
)


st.dataframe(
    filtered_df,
    use_container_width=True,
    hide_index=True
)


# ======================================================
# CVE DETAILS
# ======================================================

st.subheader("CVE Details")


if len(filtered_df) == 0:

    st.warning(
        "No CVEs match the selected filters."
    )

else:

    selected_cve = st.selectbox(
        "Select a CVE",
        filtered_df["CVE"].tolist()
    )


    selected_record = next(
        record
        for record in records
        if record.get(
            "cve_id"
        ) == selected_cve
    )


    # --------------------------------------------------
    # Extract sections
    # --------------------------------------------------

    nvd = selected_record.get(
        "nvd"
    )

    if not isinstance(nvd, dict):
        nvd = {}


    kev = selected_record.get(
        "kev",
        {}
    )

    if not isinstance(kev, dict):
        kev = {}


    cisa = selected_record.get(
        "cisa",
        {}
    )

    if not isinstance(cisa, dict):
        cisa = {}


    provenance = selected_record.get(
        "provenance",
        {}
    )

    if not isinstance(provenance, dict):
        provenance = {}


    confidence = selected_record.get(
        "confidence",
        {}
    )

    if not isinstance(confidence, dict):
        confidence = {}


    risk = selected_record.get(
        "risk",
        {}
    )

    if not isinstance(risk, dict):
        risk = {}


    # --------------------------------------------------
    # Detail metrics
    # --------------------------------------------------

    detail_col1, detail_col2, detail_col3, detail_col4 = (
        st.columns(4)
    )


    with detail_col1:

        st.metric(
            "CVSS",
            nvd.get(
                "cvss_score",
                "N/A"
            )
        )


    with detail_col2:

        st.metric(
            "Severity",
            nvd.get(
                "severity",
                "UNKNOWN"
            )
        )


    with detail_col3:

        st.metric(
            "Confidence",
            confidence.get(
                "score",
                "N/A"
            )
        )


    with detail_col4:

        st.metric(
            "Risk",
            risk.get(
                "risk_level",
                "UNKNOWN"
            )
        )


    # --------------------------------------------------
    # Vulnerability information
    # --------------------------------------------------

    st.markdown(
        "### Vulnerability Information"
    )


    description = nvd.get(
        "description"
    )


    if description:

        st.write(description)

    else:

        st.info(
            "NVD description unavailable."
        )


    # --------------------------------------------------
    # CISA
    # --------------------------------------------------

    st.markdown(
        "### CISA Advisory"
    )


    advisory_title = cisa.get(
        "advisory_title"
    )


    advisory_url = cisa.get(
        "advisory_url"
    )


    if advisory_title:

        st.write(advisory_title)


    if advisory_url:

        st.link_button(
            "Open CISA Advisory",
            advisory_url
        )

    else:

        st.info(
            "CISA advisory URL unavailable."
        )


    # --------------------------------------------------
    # KEV
    # --------------------------------------------------

    st.markdown(
        "### Exploitation Evidence"
    )


    if kev.get(
        "known_exploited",
        False
    ):

        st.error(
            "KNOWN EXPLOITED — "
            "CVE is present in CISA KEV."
        )


        kev_col1, kev_col2 = st.columns(2)


        with kev_col1:

            st.write(
                "**Vendor/Project:**",
                kev.get(
                    "vendor_project",
                    "N/A"
                )
            )


            st.write(
                "**Product:**",
                kev.get(
                    "product",
                    "N/A"
                )
            )


            st.write(
                "**Date Added:**",
                kev.get(
                    "date_added",
                    "N/A"
                )
            )


        with kev_col2:

            st.write(
                "**Required Action:**",
                kev.get(
                    "required_action",
                    "N/A"
                )
            )


            st.write(
                "**Due Date:**",
                kev.get(
                    "due_date",
                    "N/A"
                )
            )


        if kev.get(
            "short_description"
        ):

            st.write(
                kev.get(
                    "short_description"
                )
            )


    else:

        st.info(
            "This CVE is not currently "
            "listed in the CISA KEV dataset."
        )


    # --------------------------------------------------
    # Provenance
    # --------------------------------------------------

    st.markdown(
        "### Provenance"
    )


    source_count = provenance.get(
        "source_count",
        0
    )


    corroborated_status = provenance.get(
        "corroborated",
        False
    )


    st.write(
        f"**Source count:** {source_count}"
    )


    st.write(
        f"**Corroborated:** "
        f"{corroborated_status}"
    )


    sources = provenance.get(
        "sources",
        []
    )


    for source in sources:

        with st.expander(
            source.get(
                "name",
                "Unknown Source"
            )
        ):

            st.write(
                "**Type:**",
                source.get(
                    "type",
                    "N/A"
                )
            )


            st.write(
                "**Evidence:**",
                source.get(
                    "evidence",
                    "N/A"
                )
            )


            source_url = source.get(
                "url"
            )


            if source_url:

                st.link_button(
                    "Open Source",
                    source_url
                )


    # --------------------------------------------------
    # Confidence
    # --------------------------------------------------

    st.markdown(
        "### Confidence Assessment"
    )


    confidence_score = confidence.get(
        "score"
    )


    confidence_category = confidence.get(
        "category",
        "UNKNOWN"
    )


    st.write(
        f"**Confidence Score:** "
        f"{confidence_score}"
    )


    st.write(
        f"**Confidence Category:** "
        f"{confidence_category}"
    )


    confidence_reasons = confidence.get(
        "reasons",
        []
    )


    if confidence_reasons:

        st.write(
            "**Reasons:**"
        )


        for reason in confidence_reasons:

            st.write(
                f"- {reason}"
            )


    # --------------------------------------------------
    # NVD References
    # --------------------------------------------------

    st.markdown(
        "### NVD References"
    )


    references = nvd.get(
        "references",
        []
    )


    if references:

        for reference in references:

            st.write(
                f"- {reference}"
            )

    else:

        st.info(
            "No NVD references available."
        )


# ======================================================
# FOOTER
# ======================================================

st.divider()


st.caption(
    "OSINT CTI Research Project | "
    "Provenance-Aware Cyber Threat Intelligence"
)
