import json

INPUT_FILE = "data/processed/enriched_cti.json"
OUTPUT_FILE = "data/processed/risk_analysis.json"


def classify_risk(score):
    """
    Classify CVSS scores using the standard CVSS severity ranges.
    """

    if score is None:
        return "UNKNOWN"

    if score >= 9.0:
        return "CRITICAL"

    if score >= 7.0:
        return "HIGH"

    if score >= 4.0:
        return "MEDIUM"

    return "LOW"


def analyze_record(record):

    cve_id = record.get("cve_id")

    nvd = record.get("nvd")

    if not nvd:

        return {
            "cve_id": cve_id,
            "nvd_available": False,
            "cvss_score": None,
            "severity": None,
            "risk_level": "UNKNOWN",
            "enrichment_status": record.get(
                "enrichment_status"
            )
        }

    score = nvd.get("cvss_score")

    risk_level = classify_risk(score)

    return {
        "cve_id": cve_id,
        "nvd_available": True,
        "cvss_score": score,
        "severity": nvd.get("severity"),
        "risk_level": risk_level,
        "published": nvd.get("published"),
        "last_modified": nvd.get(
            "last_modified"
        ),
        "cisa_advisory": record.get(
            "cisa",
            {}
        ).get("advisory_title"),
        "advisory_url": record.get(
            "cisa",
            {}
        ).get("advisory_url"),
        "enrichment_status": record.get(
            "enrichment_status"
        )
    }


def main():

    print("[+] Loading enriched CTI data")

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        records = json.load(file)

    results = []

    for record in records:

        analyzed = analyze_record(record)

        results.append(analyzed)

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            results,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(
        f"[+] Records analyzed: {len(results)}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
