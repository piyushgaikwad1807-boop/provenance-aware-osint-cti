import json
from datetime import datetime, timezone

INPUT_FILE = "data/processed/enriched_cti.json"
OUTPUT_FILE = "data/processed/provenance_cti.json"


def build_provenance(record):

    cve_id = record.get("cve_id")

    cisa = record.get("cisa", {})
    nvd = record.get("nvd")

    sources = []

    # ---------------------------------------
    # CISA evidence
    # ---------------------------------------

    cisa_url = cisa.get("advisory_url")

    if cisa_url:

        sources.append({
            "name": "CISA",
            "type": "government_advisory",
            "url": cisa_url,
            "evidence": (
                f"CVE {cve_id} identified in "
                "CISA advisory"
            )
        })

    # ---------------------------------------
    # NVD evidence
    # ---------------------------------------

    if nvd:

        nvd_url = (
            f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        )

        sources.append({
            "name": "NVD",
            "type": "vulnerability_database",
            "url": nvd_url,
            "evidence": (
                f"NVD record available for "
                f"{cve_id}"
            )
        })

    # ---------------------------------------
    # Source count
    # ---------------------------------------

    source_count = len(sources)

    # ---------------------------------------
    # Corroboration
    # ---------------------------------------

    corroborated = source_count >= 2

    # ---------------------------------------
    # Confidence
    # ---------------------------------------

    if source_count >= 2:
        confidence = 0.90

    elif source_count == 1:
        confidence = 0.70

    else:
        confidence = 0.30

    # ---------------------------------------
    # Build final record
    # ---------------------------------------

    return {
        "cve_id": cve_id,
        "sources": sources,
        "source_count": source_count,
        "corroborated": corroborated,
        "confidence": confidence,
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat()
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

        provenance = build_provenance(
            record
        )

        results.append(provenance)

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
        f"[+] Records processed: {len(results)}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
