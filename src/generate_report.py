import json
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent

FINAL_FILE = PROJECT_ROOT / "data/processed/final_cti.json"
VALIDATION_FILE = PROJECT_ROOT / "data/processed/validation_report.json"
METRICS_FILE = PROJECT_ROOT / "data/processed/historical_metrics.json"

REPORT_DIR = PROJECT_ROOT / "reports"
REPORT_FILE = REPORT_DIR / "cti_report.md"


def load_json(path):
    if not path.exists():
        return None

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def percentage(value):
    return f"{value:.2f}%"


def main():

    print("[+] Starting automated CTI report generation")

    final_data = load_json(FINAL_FILE)
    validation = load_json(VALIDATION_FILE)
    historical_metrics = load_json(METRICS_FILE)

    if not final_data:
        print("[!] final_cti.json not found or empty")
        return

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    total_records = len(final_data)

    unique_cves = len(
        set(record.get("cve_id") for record in final_data)
    )

    known_exploited = sum(
        1
        for record in final_data
        if record.get("exploitation_status") == "KNOWN_EXPLOITED"
    )

    corroborated = sum(
        1
        for record in final_data
        if record.get("provenance", {}).get("corroborated") is True
    )

    nvd_available = sum(
        1
        for record in final_data
        if record.get("nvd")
    )

    confidence_scores = []

    for record in final_data:
        score = record.get("confidence", {}).get("score")

        if isinstance(score, (int, float)):
            confidence_scores.append(score)

    if confidence_scores:
        average_confidence = (
            sum(confidence_scores) / len(confidence_scores)
        )
    else:
        average_confidence = 0

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    unknown_count = 0

    for record in final_data:

        severity = str(
            record.get("risk", {}).get(
                "severity",
                "UNKNOWN"
            )
        ).upper()

        if severity == "CRITICAL":
            critical_count += 1

        elif severity == "HIGH":
            high_count += 1

        elif severity == "MEDIUM":
            medium_count += 1

        elif severity == "LOW":
            low_count += 1

        else:
            unknown_count += 1

    if total_records:
        nvd_rate = (
            nvd_available / total_records
        ) * 100

        kev_rate = (
            known_exploited / total_records
        ) * 100

        corroboration_rate = (
            corroborated / total_records
        ) * 100
    else:
        nvd_rate = 0
        kev_rate = 0
        corroboration_rate = 0

    validation_status = "UNKNOWN"
    validation_rate = "N/A"

    if validation:

        validation_summary = validation.get(
            "validation_summary",
            {}
        )

        validation_status = validation_summary.get(
            "overall_status",
            "UNKNOWN"
        )

        validation_rate_value = validation_summary.get(
            "validation_rate"
        )

        if validation_rate_value is not None:
            validation_rate = percentage(
                validation_rate_value
            )

    generated_at = datetime.now(
        timezone.utc
    ).isoformat()

    lines = []

    lines.append("# OSINT Cyber Threat Intelligence Report")
    lines.append("")

    lines.append("## 1. Report Information")
    lines.append("")

    lines.append(
        f"**Generated:** {generated_at}"
    )

    lines.append("")

    lines.append(
        "**Project:** Provenance-Aware OSINT Cyber Threat "
        "Intelligence and Automated Threat Correlation System"
    )

    lines.append("")

    lines.append(
        "**Primary Data Source:** CISA Cybersecurity Advisories"
    )

    lines.append("")

    lines.append(
        "**Enrichment Source:** National Vulnerability "
        "Database (NVD)"
    )

    lines.append("")

    lines.append(
        "**Exploitation Intelligence:** CISA Known Exploited "
        "Vulnerabilities (KEV)"
    )

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 2. Executive Summary")
    lines.append("")

    lines.append(
        "This report was automatically generated from the "
        "processed Cyber Threat Intelligence dataset."
    )

    lines.append("")

    lines.append(
        "The pipeline collects vulnerability information from "
        "CISA, extracts CVE identifiers, enriches vulnerability "
        "records using NVD, correlates vulnerabilities with the "
        "CISA KEV catalog, tracks source provenance, calculates "
        "explainable confidence scores, validates the final "
        "dataset, and evaluates data quality."
    )

    lines.append("")

    lines.append(
        f"The current dataset contains **{unique_cves} unique CVEs** "
        f"across **{total_records} records**."
    )

    lines.append("")

    lines.append(
        f"A total of **{known_exploited} vulnerabilities** are "
        "currently identified as known exploited vulnerabilities "
        "through the CISA KEV catalog."
    )

    lines.append("")

    lines.append(
        f"A total of **{corroborated} records** contain evidence "
        "from multiple sources."
    )

    lines.append("")

    lines.append(
        f"The average project confidence score is "
        f"**{average_confidence:.3f}**."
    )

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 3. Dataset Statistics")
    lines.append("")

    lines.append("| Metric | Value |")
    lines.append("|---|---:|")
    lines.append(f"| Total Records | {total_records} |")
    lines.append(f"| Unique CVEs | {unique_cves} |")
    lines.append(f"| NVD Available | {nvd_available} |")
    lines.append(f"| NVD Coverage | {percentage(nvd_rate)} |")
    lines.append(
        f"| Known Exploited | {known_exploited} |"
    )
    lines.append(
        f"| KEV Match Rate | {percentage(kev_rate)} |"
    )
    lines.append(
        f"| Corroborated Records | {corroborated} |"
    )
    lines.append(
        f"| Corroboration Rate | "
        f"{percentage(corroboration_rate)} |"
    )
    lines.append(
        f"| Average Confidence | "
        f"{average_confidence:.3f} |"
    )

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 4. Vulnerability Severity Distribution")
    lines.append("")

    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    lines.append(f"| Critical | {critical_count} |")
    lines.append(f"| High | {high_count} |")
    lines.append(f"| Medium | {medium_count} |")
    lines.append(f"| Low | {low_count} |")
    lines.append(f"| Unknown | {unknown_count} |")

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 5. Data Validation")
    lines.append("")

    lines.append(
        "The final CTI dataset is automatically validated "
        "before evaluation and reporting."
    )

    lines.append("")

    lines.append(
        f"**Validation Status:** {validation_status}"
    )

    lines.append("")

    lines.append(
        f"**Validation Rate:** {validation_rate}"
    )

    lines.append("")

    lines.append("The validation stage checks:")

    lines.append("")
    lines.append("- CVE identifier format")
    lines.append("- CVSS values")
    lines.append("- provenance information")
    lines.append("- confidence score")
    lines.append("- confidence category")
    lines.append("- exploitation status")
    lines.append("- risk information")
    lines.append("- pipeline metadata")
    lines.append("- duplicate CVE identifiers")

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 6. Confidence Model")
    lines.append("")

    lines.append(
        "The project uses an explainable heuristic confidence model."
    )

    lines.append("")

    lines.append("The model considers:")

    lines.append("")
    lines.append("- multiple-source corroboration")
    lines.append("- CISA evidence")
    lines.append("- NVD evidence")
    lines.append("- evidence completeness")
    lines.append("- valid CVE identification")

    lines.append("")

    lines.append(
        "The confidence score is a project-defined heuristic "
        "score. It must not be interpreted as a statistical "
        "probability."
    )

    lines.append("")

    lines.append(
        f"**Average Confidence:** {average_confidence:.3f}"
    )

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 7. Provenance and Evidence Correlation")
    lines.append("")

    lines.append(
        "The provenance layer records the sources supporting "
        "each CTI record."
    )

    lines.append("")

    lines.append("The primary sources currently used are:")

    lines.append("")
    lines.append("1. CISA Cybersecurity Advisories")
    lines.append("2. National Vulnerability Database")
    lines.append("3. CISA Known Exploited Vulnerabilities")

    lines.append("")

    lines.append(
        "Records supported by multiple sources are marked "
        "as corroborated."
    )

    lines.append("")

    lines.append(
        f"**Corroborated Records:** {corroborated}"
    )

    lines.append("")

    lines.append(
        f"**Corroboration Rate:** "
        f"{percentage(corroboration_rate)}"
    )

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 8. Exploitation Intelligence")
    lines.append("")

    lines.append(
        "The CISA KEV catalog is used to identify "
        "vulnerabilities with known exploitation."
    )

    lines.append("")

    lines.append(
        f"**Known Exploited Vulnerabilities:** "
        f"{known_exploited}"
    )

    lines.append("")

    lines.append(
        f"**KEV Match Rate:** {percentage(kev_rate)}"
    )

    lines.append("")

    lines.append(
        "KEV status is treated as an exploitation-intelligence "
        "signal and is not used as a replacement for CVSS severity."
    )

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 9. Historical Analysis")
    lines.append("")

    lines.append(
        "The project maintains historical snapshots of the "
        "CTI dataset."
    )

    lines.append("")

    lines.append(
        "Historical snapshots allow analysis of changes in:"
    )

    lines.append("")
    lines.append("- CVE volume")
    lines.append("- known exploited vulnerabilities")
    lines.append("- NVD coverage")
    lines.append("- corroboration rate")
    lines.append("- confidence scores")

    lines.append("")

    lines.append(
        "These snapshots support reproducibility and future "
        "time-series analysis."
    )

    lines.append("")

    if historical_metrics:

        lines.append("## 10. Historical Metrics")
        lines.append("")

        lines.append(
            "Historical metrics are generated by the trend "
            "analysis stage."
        )

        lines.append("")

        if isinstance(historical_metrics, list):

            lines.append(
                "| Snapshot | CVEs | KEV | Corroborated | "
                "NVD Coverage | Confidence |"
            )

            lines.append(
                "|---|---:|---:|---:|---:|---:|"
            )

            for metric in historical_metrics:

                snapshot = metric.get(
                    "snapshot_id",
                    "UNKNOWN"
                )

                cves = metric.get(
                    "total_cves",
                    0
                )

                kev = metric.get(
                    "known_exploited",
                    0
                )

                corr = metric.get(
                    "corroborated_records",
                    0
                )

                nvd = metric.get(
                    "nvd_coverage_rate",
                    0
                )

                confidence = metric.get(
                    "average_confidence",
                    0
                )

                lines.append(
                    f"| {snapshot} | {cves} | {kev} | "
                    f"{corr} | {nvd:.2f}% | "
                    f"{confidence:.3f} |"
                )

        lines.append("")

    lines.append("---")
    lines.append("")

    lines.append("## 11. Research Significance")
    lines.append("")

    lines.append(
        "The project demonstrates an automated "
        "provenance-aware CTI processing pipeline combining "
        "vulnerability identification, vulnerability enrichment, "
        "exploitation intelligence, source corroboration, "
        "confidence scoring, validation, and historical analysis."
    )

    lines.append("")

    lines.append(
        "The system is designed to support reproducible CTI "
        "research rather than relying on a single vulnerability "
        "database."
    )

    lines.append("")

    lines.append(
        "The main research direction is the correlation of "
        "evidence from multiple authoritative sources and the "
        "use of explainable confidence scoring to represent "
        "evidence strength."
    )

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 12. Limitations")
    lines.append("")

    lines.append(
        "The current system has several limitations:"
    )

    lines.append("")

    lines.append(
        "1. The confidence score is heuristic rather than "
        "statistically calibrated."
    )

    lines.append(
        "2. CVSS severity does not represent complete "
        "real-world risk."
    )

    lines.append(
        "3. The current source set is limited primarily to "
        "CISA and NVD, with CISA KEV used for exploitation "
        "intelligence."
    )

    lines.append(
        "4. Historical analysis depends on the number and "
        "frequency of collected snapshots."
    )

    lines.append(
        "5. External API availability and rate limiting can "
        "affect enrichment."
    )

    lines.append(
        "6. The current correlation model does not yet perform "
        "advanced semantic or graph-based threat correlation."
    )

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 13. Future Work")
    lines.append("")

    lines.append("- additional CTI sources")
    lines.append("- STIX/TAXII integration")
    lines.append("- threat actor correlation")
    lines.append("- malware intelligence")
    lines.append("- IOC extraction")
    lines.append("- graph-based relationship analysis")
    lines.append("- automated alert generation")
    lines.append("- statistical confidence calibration")
    lines.append("- machine-learning-assisted correlation")
    lines.append("- larger historical datasets")
    lines.append("- advanced temporal analysis")

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 14. Reproducibility")
    lines.append("")

    lines.append(
        "The report is generated automatically from the "
        "project's processed data."
    )

    lines.append("")

    lines.append(
        "The complete pipeline can be executed using:"
    )

    lines.append("")

    lines.append("```bash")
    lines.append("python src/run_pipeline.py")
    lines.append("```")

    lines.append("")

    lines.append(
        "The generated report is:"
    )

    lines.append("")

    lines.append("```text")
    lines.append("reports/cti_report.md")
    lines.append("```")

    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## 15. Conclusion")
    lines.append("")

    lines.append(
        "The automated reporting layer converts the processed "
        "CTI dataset into a reproducible research-oriented "
        "intelligence report."
    )

    lines.append("")

    lines.append(
        "This provides a complete path from raw OSINT collection "
        "to structured CTI processing, evidence correlation, "
        "validation, evaluation, historical analysis, and "
        "final reporting."
    )

    lines.append("")

    lines.append("**End of Report**")
    lines.append("")

    report = "\n".join(lines)

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:
        file.write(report)

    print("[+] CTI report generated")
    print(f"[+] Saved: {REPORT_FILE}")


if __name__ == "__main__":
    main()
