import json
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = PROJECT_ROOT / "data/processed/final_cti.json"
OUTPUT_FILE = PROJECT_ROOT / "data/processed/correlation_cti.json"


def calculate_correlation(record):

    cve_id = record.get("cve_id", "UNKNOWN")

    nvd = record.get("nvd") or {}
    kev = record.get("kev") or {}
    provenance = record.get("provenance") or {}
    confidence = record.get("confidence") or {}
    risk = record.get("risk") or {}

    score = 0
    reasons = []

    # ---------------------------------------------------------
    # 1. Source corroboration
    # ---------------------------------------------------------

    source_count = provenance.get("source_count", 0)

    if source_count >= 2:
        score += 30

        reasons.append(
            "Multiple independent CTI sources corroborate the record."
        )

    elif source_count == 1:
        score += 15

        reasons.append(
            "The record is supported by one CTI source."
        )

    else:
        reasons.append(
            "No source corroboration is available."
        )

    # ---------------------------------------------------------
    # 2. CISA evidence
    # ---------------------------------------------------------

    cisa = record.get("cisa") or {}

    if cisa.get("advisory_url"):
        score += 20

        reasons.append(
            "CISA advisory evidence is available."
        )

    # ---------------------------------------------------------
    # 3. NVD evidence
    # ---------------------------------------------------------

    if nvd:
        score += 15

        reasons.append(
            "NVD vulnerability enrichment is available."
        )

    # ---------------------------------------------------------
    # 4. KEV exploitation evidence
    # ---------------------------------------------------------

    exploitation_status = record.get(
        "exploitation_status",
        "UNKNOWN"
    )

    if exploitation_status == "KNOWN_EXPLOITED":

        score += 30

        reasons.append(
            "The vulnerability is listed in the CISA KEV catalog."
        )

    elif exploitation_status == "NOT_IN_KEV":

        reasons.append(
            "The vulnerability is not currently listed in CISA KEV."
        )

    else:

        reasons.append(
            "KEV exploitation status is unavailable."
        )

    # ---------------------------------------------------------
    # 5. CVSS severity
    # ---------------------------------------------------------

    cvss_score = risk.get("cvss_score")

    if isinstance(cvss_score, (int, float)):

        if cvss_score >= 9.0:

            score += 10

            reasons.append(
                "The vulnerability has a Critical CVSS score."
            )

        elif cvss_score >= 7.0:

            score += 7

            reasons.append(
                "The vulnerability has a High CVSS score."
            )

        elif cvss_score >= 4.0:

            score += 4

            reasons.append(
                "The vulnerability has a Medium CVSS score."
            )

        else:

            score += 2

            reasons.append(
                "The vulnerability has a Low CVSS score."
            )

    else:

        reasons.append(
            "CVSS score is unavailable."
        )

    # ---------------------------------------------------------
    # 6. Confidence evidence
    # ---------------------------------------------------------

    confidence_score = confidence.get("score")

    if isinstance(confidence_score, (int, float)):

        if confidence_score >= 0.80:

            score += 10

            reasons.append(
                "The CTI record has high confidence."
            )

        elif confidence_score >= 0.60:

            score += 7

            reasons.append(
                "The CTI record has medium confidence."
            )

        elif confidence_score >= 0.40:

            score += 4

            reasons.append(
                "The CTI record has low confidence."
            )

        else:

            score += 2

            reasons.append(
                "The CTI record has very low confidence."
            )

    # ---------------------------------------------------------
    # Normalize score
    # ---------------------------------------------------------

    if score >= 80:

        correlation_level = "VERY_HIGH"

    elif score >= 60:

        correlation_level = "HIGH"

    elif score >= 40:

        correlation_level = "MEDIUM"

    elif score >= 20:

        correlation_level = "LOW"

    else:

        correlation_level = "VERY_LOW"

    # ---------------------------------------------------------
    # Build result
    # ---------------------------------------------------------

    return {
        "cve_id": cve_id,
        "correlation_score": score,
        "correlation_level": correlation_level,
        "correlation_reasons": reasons,
        "signals": {
            "source_count": source_count,
            "cisa_evidence": bool(cisa.get("advisory_url")),
            "nvd_evidence": bool(nvd),
            "kev_exploitation": exploitation_status,
            "cvss_score": cvss_score,
            "confidence_score": confidence_score
        },
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat()
    }


def main():

    print("[+] Starting threat correlation analysis")

    if not INPUT_FILE.exists():

        print(
            "[!] final_cti.json not found"
        )

        return

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        records = json.load(file)

    correlation_records = []

    for record in records:

        result = calculate_correlation(record)

        correlation_records.append(result)

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            correlation_records,
            file,
            indent=2
        )

    very_high = sum(
        1
        for record in correlation_records
        if record["correlation_level"] == "VERY_HIGH"
    )

    high = sum(
        1
        for record in correlation_records
        if record["correlation_level"] == "HIGH"
    )

    medium = sum(
        1
        for record in correlation_records
        if record["correlation_level"] == "MEDIUM"
    )

    low = sum(
        1
        for record in correlation_records
        if record["correlation_level"] == "LOW"
    )

    very_low = sum(
        1
        for record in correlation_records
        if record["correlation_level"] == "VERY_LOW"
    )

    print("[+] Threat correlation complete")
    print(
        f"[+] Total records: {len(correlation_records)}"
    )

    print(
        f"[+] VERY_HIGH: {very_high}"
    )

    print(
        f"[+] HIGH: {high}"
    )

    print(
        f"[+] MEDIUM: {medium}"
    )

    print(
        f"[+] LOW: {low}"
    )

    print(
        f"[+] VERY_LOW: {very_low}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
