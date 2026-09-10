import json
from pathlib import Path

import pandas as pd
import streamlit as st


DATA_FILE = Path(
    "data/processed/historical_metrics.json"
)


st.set_page_config(
    page_title="CTI Historical Analysis",
    page_icon="📈",
    layout="wide"
)


st.title(
    "📈 CTI Historical Trend Analysis"
)

st.caption(
    "Time-based analysis of historical CTI "
    "collection snapshots"
)


if not DATA_FILE.exists():

    st.error(
        "Historical metrics file not found."
    )

    st.info(
        "Run: python src/trend_analysis.py"
    )

    st.stop()


with open(
    DATA_FILE,
    "r",
    encoding="utf-8"
) as file:

    data = json.load(file)


if not data:

    st.warning(
        "No historical metrics available."
    )

    st.stop()


df = pd.DataFrame(data)


df["created_at"] = pd.to_datetime(
    df["created_at"]
)


st.subheader(
    "Historical Collection Metrics"
)


display_columns = [
    "snapshot_id",
    "created_at",
    "total_cves",
    "known_exploited",
    "corroborated_records",
    "nvd_available",
    "average_confidence",
    "nvd_coverage_rate",
    "kev_match_rate",
    "corroboration_rate"
]


st.dataframe(
    df[display_columns],
    use_container_width=True
)


st.subheader(
    "CVEs Observed Over Time"
)

chart_data = df.set_index(
    "created_at"
)[
    ["total_cves"]
]

st.line_chart(
    chart_data
)


st.subheader(
    "Known Exploited Vulnerabilities Over Time"
)

kev_data = df.set_index(
    "created_at"
)[
    ["known_exploited"]
]

st.line_chart(
    kev_data
)


st.subheader(
    "NVD Coverage Over Time"
)

nvd_data = df.set_index(
    "created_at"
)[
    ["nvd_coverage_rate"]
]

st.line_chart(
    nvd_data
)


st.subheader(
    "Corroboration Rate Over Time"
)

corroboration_data = df.set_index(
    "created_at"
)[
    ["corroboration_rate"]
]

st.line_chart(
    corroboration_data
)


st.subheader(
    "Average Confidence Over Time"
)

confidence_data = df.set_index(
    "created_at"
)[
    ["average_confidence"]
]

st.line_chart(
    confidence_data
)


st.divider()

st.caption(
    "Historical observations represent the state "
    "of the project's collected sources at each "
    "snapshot time. They do not represent the "
    "complete global vulnerability landscape."
)
