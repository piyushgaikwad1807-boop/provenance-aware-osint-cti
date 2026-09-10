import json
from collections import Counter
from pathlib import Path


INPUT_FILE = Path("data/processed/provenance_cti.json")


def load_data():
    if not INPUT_FILE.exists():
        print(f"[!] File not found: {INPUT_FILE}")
        return []

    with INPUT_FILE.open("r", encoding="utf-8") as file:
        return json.load(file)


def main():
    print("[+] Loading provenance CTI data")

    records = load_data()

    if not records:
        print("[!] No provenance records found")
        return

    total = len(records)

    # --------------------------------------------------
    # Basic statistics
    # --------------------------------------------------

    unique_cves = len(
        set(record.get("cve_id") for record in records)
    )

    corroborated = sum(
        1
        for record in records
        if record.get("corroborated") is True
    )

    single_source = sum(
        1
        for record in records
        if record.get("source_count", 0) == 1
    )

    no_source = sum(
        1
        for record in records
        if record.get("source_count", 0) == 0
    )

    # --------------------------------------------------
    # Source statistics
    # --------------------------------------------------

    source_counter = Counter()

    for record in records:
        for source in record.get("sources", []):
            source_name = source.get("name", "Unknown")
            source_counter[source_name] += 1

    # --------------------------------------------------
    # Confidence statistics
    # --------------------------------------------------

    confidence_values = [
        record.get("confidence", 0)
        for record in records
    ]

    average_confidence = (
        sum(confidence_values) / len(confidence_values)
        if confidence_values
        else 0
    )

    high_confidence = sum(
        1
        for value in confidence_values
        if value >= 0.90
    )

    medium_confidence = sum(
        1
        for value in confidence_values
        if 0.70 <= value < 0.90
    )

    low_confidence = sum(
        1
        for value in confidence_values
        if value < 0.70
    )

    # --------------------------------------------------
    # Corroboration rate
    # --------------------------------------------------

    if total > 0:
        corroboration_rate = (
            corroborated / total
        ) * 100
    else:
        corroboration_rate = 0

    # --------------------------------------------------
    # Source coverage
    # --------------------------------------------------

    cisa_records = source_counter.get("CISA", 0)
    nvd_records = source_counter.get("NVD", 0)

    cisa_coverage = (
        cisa_records / total * 100
        if total > 0
        else 0
    )

    nvd_coverage = (
        nvd_records / total * 100
        if total > 0
        else 0
    )

    # --------------------------------------------------
    # Print report
    # --------------------------------------------------

    print()
    print("=" * 55)
    print("PROVENANCE AND EVIDENCE SUMMARY")
    print("=" * 55)

    print()
    print("DATASET")
    print("-" * 55)
    print(f"Total CTI records       : {total}")
    print(f"Unique CVEs             : {unique_cves}")

    print()
    print("SOURCE COVERAGE")
    print("-" * 55)

    for source, count in source_counter.items():
        percentage = (
            count / total * 100
            if total > 0
            else 0
        )

        print(
            f"{source:<24}: "
            f"{count} ({percentage:.2f}%)"
        )

    print()
    print("CISA COVERAGE")
    print("-" * 55)
    print(
        f"CISA records            : "
        f"{cisa_records}"
    )
    print(
        f"CISA coverage           : "
        f"{cisa_coverage:.2f}%"
    )

    print()
    print("NVD COVERAGE")
    print("-" * 55)
    print(
        f"NVD records             : "
        f"{nvd_records}"
    )
    print(
        f"NVD coverage            : "
        f"{nvd_coverage:.2f}%"
    )

    print()
    print("CORROBORATION")
    print("-" * 55)
    print(
        f"Corroborated records    : "
        f"{corroborated}"
    )
    print(
        f"Single-source records   : "
        f"{single_source}"
    )
    print(
        f"No-source records       : "
        f"{no_source}"
    )
    print(
        f"Corroboration rate      : "
        f"{corroboration_rate:.2f}%"
    )

    print()
    print("CONFIDENCE")
    print("-" * 55)
    print(
        f"Average confidence     : "
        f"{average_confidence:.3f}"
    )
    print(
        f"High confidence        : "
        f"{high_confidence}"
    )
    print(
        f"Medium confidence      : "
        f"{medium_confidence}"
    )
    print(
        f"Low confidence         : "
        f"{low_confidence}"
    )

    print()
    print("CONFIDENCE DISTRIBUTION")
    print("-" * 55)

    confidence_counter = Counter(
        round(value, 2)
        for value in confidence_values
    )

    for confidence, count in sorted(
        confidence_counter.items(),
        reverse=True
    ):
        print(
            f"{confidence:.2f}                  : "
            f"{count}"
        )

    print()
    print("=" * 55)
    print("PROVENANCE SUMMARY COMPLETE")
    print("=" * 55)


if __name__ == "__main__":
    main()
