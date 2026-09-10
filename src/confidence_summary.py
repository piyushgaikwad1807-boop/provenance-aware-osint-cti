import json
from pathlib import Path
from collections import Counter


INPUT_FILE = Path(
    "data/processed/confidence_cti.json"
)


def main():

    if not INPUT_FILE.exists():
        print(f"[!] File not found: {INPUT_FILE}")
        return

    with INPUT_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        records = json.load(file)

    if not records:
        print("[!] No records found")
        return

    total = len(records)

    # --------------------------------------------------
    # Confidence categories
    # --------------------------------------------------

    category_counter = Counter(
        record.get(
            "confidence_category",
            "UNKNOWN"
        )
        for record in records
    )

    # --------------------------------------------------
    # Scores
    # --------------------------------------------------

    scores = [
        record.get(
            "confidence_score",
            0
        )
        for record in records
    ]

    average_score = (
        sum(scores) / len(scores)
        if scores
        else 0
    )

    highest_score = max(scores)
    lowest_score = min(scores)

    # --------------------------------------------------
    # Corroboration
    # --------------------------------------------------

    corroborated = sum(
        1
        for record in records
        if record.get("corroborated") is True
    )

    corroboration_rate = (
        corroborated / total * 100
        if total > 0
        else 0
    )

    # --------------------------------------------------
    # Source statistics
    # --------------------------------------------------

    cisa_records = sum(
        1
        for record in records
        if any(
            source.get("name") == "CISA"
            for source in record.get(
                "sources",
                []
            )
        )
    )

    nvd_records = sum(
        1
        for record in records
        if any(
            source.get("name") == "NVD"
            for source in record.get(
                "sources",
                []
            )
        )
    )

    # --------------------------------------------------
    # Print report
    # --------------------------------------------------

    print()
    print("=" * 60)
    print("DAY 9 - CONFIDENCE MODEL SUMMARY")
    print("=" * 60)

    print()
    print("DATASET")
    print("-" * 60)
    print(f"Total records          : {total}")
    print(f"CISA-supported records : {cisa_records}")
    print(f"NVD-supported records  : {nvd_records}")

    print()
    print("CORROBORATION")
    print("-" * 60)
    print(
        f"Corroborated records   : "
        f"{corroborated}"
    )
    print(
        f"Corroboration rate     : "
        f"{corroboration_rate:.2f}%"
    )

    print()
    print("CONFIDENCE")
    print("-" * 60)
    print(
        f"Average score          : "
        f"{average_score:.3f}"
    )
    print(
        f"Highest score          : "
        f"{highest_score:.3f}"
    )
    print(
        f"Lowest score           : "
        f"{lowest_score:.3f}"
    )

    print()
    print("CONFIDENCE CATEGORIES")
    print("-" * 60)

    for category in [
        "HIGH",
        "MEDIUM",
        "LOW",
        "VERY_LOW",
        "UNKNOWN"
    ]:

        count = category_counter.get(
            category,
            0
        )

        print(
            f"{category:<12}: {count}"
        )

    print()
    print("=" * 60)
    print("CONFIDENCE ANALYSIS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
