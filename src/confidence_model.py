import json
from pathlib import Path
from datetime import datetime, timezone


INPUT_FILE = Path("data/processed/provenance_cti.json")
OUTPUT_FILE = Path("data/processed/confidence_cti.json")


def load_data():
    """Load provenance records."""

    if not INPUT_FILE.exists():
        print(f"[!] File not found: {INPUT_FILE}")
        return []

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def calculate_confidence(record):
    """
    Calculate an explainable CTI confidence score.

    This is a project-defined heuristic model,
    not a statistical probability.
    """

    sources = record.get("sources", [])
    source_count = len(sources)

    score = 0.0
    reasons = []

    # --------------------------------------------------
    # Factor 1: Source corroboration
    # --------------------------------------------------

    if source_count >= 2:
        score += 0.40
        reasons.append(
            "Multiple sources corroborate the CTI record"
        )

    elif source_count == 1:
        score += 0.20
        reasons.append(
            "CTI record is supported by one source"
        )

    else:
        reasons.append(
            "No supporting source was identified"
        )

    # --------------------------------------------------
    # Factor 2: CISA evidence
    # --------------------------------------------------

    cisa_present = any(
        source.get("name") == "CISA"
        for source in sources
    )

    if cisa_present:
        score += 0.25
        reasons.append(
            "CISA advisory evidence is available"
        )

    # --------------------------------------------------
    # Factor 3: NVD evidence
    # --------------------------------------------------

    nvd_present = any(
        source.get("name") == "NVD"
        for source in sources
    )

    if nvd_present:
        score += 0.20
        reasons.append(
            "NVD vulnerability record is available"
        )

    # --------------------------------------------------
    # Factor 4: Evidence completeness
    # --------------------------------------------------

    evidence_available = all(
        source.get("evidence")
        for source in sources
    )

    if sources and evidence_available:
        score += 0.10
        reasons.append(
            "Source evidence descriptions are available"
        )

    # --------------------------------------------------
    # Factor 5: CVE identifier validity
    # --------------------------------------------------

    cve_id = record.get("cve_id", "")

    if cve_id.startswith("CVE-"):
        score += 0.05
        reasons.append(
            "Valid CVE identifier is present"
        )

    # --------------------------------------------------
    # Limit score to 1.0
    # --------------------------------------------------

    score = min(score, 1.0)

    # --------------------------------------------------
    # Confidence category
    # --------------------------------------------------

    if score >= 0.80:
        category = "HIGH"

    elif score >= 0.60:
        category = "MEDIUM"

    elif score >= 0.40:
        category = "LOW"

    else:
        category = "VERY_LOW"

    return round(score, 3), category, reasons


def main():

    print("[+] Loading provenance data")

    records = load_data()

    if not records:
        print("[!] No records available")
        return

    print(f"[+] Records loaded: {len(records)}")

    output_records = []

    for record in records:

        cve_id = record.get("cve_id", "UNKNOWN")

        score, category, reasons = calculate_confidence(record)

        result = {
            "cve_id": cve_id,

            "sources": record.get(
                "sources",
                []
            ),

            "source_count": record.get(
                "source_count",
                0
            ),

            "corroborated": record.get(
                "corroborated",
                False
            ),

            "confidence_score": score,

            "confidence_category": category,

            "confidence_reasons": reasons,

            "generated_at": datetime.now(
                timezone.utc
            ).isoformat()
        }

        output_records.append(result)

        print(
            f"[+] {cve_id}: "
            f"{score:.3f} ({category})"
        )

    # --------------------------------------------------
    # Save results
    # --------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output_records,
            file,
            indent=4,
            ensure_ascii=False
        )

    print()
    print(
        f"[+] Confidence records: "
        f"{len(output_records)}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
