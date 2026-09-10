import json
from pathlib import Path


INPUT_FILE = Path(
    "data/processed/kev_cti.json"
)

OUTPUT_FILE = Path(
    "data/processed/final_cti.json"
)


def calculate_priority(record):

    confidence = record.get(
        "confidence_score",
        0
    )

    kev = record.get(
        "kev",
        {}
    )

    known_exploited = kev.get(
        "known_exploited",
        False
    )

    # --------------------------------------------------
    # CVSS
    # --------------------------------------------------

    cvss_score = None

    # Current project data does not necessarily
    # contain CVSS directly in this layer.
    # Therefore safely check for it.

    nvd = record.get(
        "nvd",
        {}
    )

    if isinstance(nvd, dict):

        cvss_score = nvd.get(
            "cvss_score"
        )

    # --------------------------------------------------
    # Priority calculation
    # --------------------------------------------------

    score = confidence * 100

    reasons = []

    # KEV is strong exploitation evidence.
    if known_exploited:

        score += 30

        reasons.append(
            "CISA KEV confirms known exploitation"
        )

    else:

        reasons.append(
            "CVE is not currently present in CISA KEV"
        )

    # CVSS contribution
    if isinstance(
        cvss_score,
        (int, float)
    ):

        cvss_component = (
            float(cvss_score) / 10
        ) * 20

        score += cvss_component

        reasons.append(
            f"CVSS score available: "
            f"{cvss_score}"
        )

    else:

        reasons.append(
            "CVSS score unavailable"
        )

    # --------------------------------------------------
    # Normalize
    # --------------------------------------------------

    score = min(
        round(score, 2),
        150
    )

    # --------------------------------------------------
    # Priority category
    # --------------------------------------------------

    if known_exploited and score >= 100:

        priority = "CRITICAL_PRIORITY"

    elif known_exploited:

        priority = "HIGH_PRIORITY"

    elif score >= 80:

        priority = "HIGH"

    elif score >= 60:

        priority = "MEDIUM"

    else:

        priority = "LOW"

    return score, priority, reasons


def main():

    if not INPUT_FILE.exists():

        print(
            f"[!] File not found: "
            f"{INPUT_FILE}"
        )

        return

    with INPUT_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        records = json.load(file)

    print(
        f"[+] Records loaded: "
        f"{len(records)}"
    )

    output = []

    for record in records:

        score, priority, reasons = (
            calculate_priority(record)
        )

        result = record.copy()

        result["risk_priority_score"] = score

        result["risk_priority"] = priority

        result["risk_priority_reasons"] = reasons

        output.append(result)

        print(
            f"[+] {record.get('cve_id')}: "
            f"{priority} "
            f"({score})"
        )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=4,
            ensure_ascii=False
        )

    print()
    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
