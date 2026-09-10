import json
from pathlib import Path
from collections import Counter


INPUT_FILE = Path(
    "data/processed/kev_cti.json"
)


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

    if not records:

        print("[!] No records found")
        return

    total = len(records)

    known_exploited = sum(
        1
        for record in records
        if record.get(
            "exploitation_status"
        ) == "KNOWN_EXPLOITED"
    )

    not_in_kev = sum(
        1
        for record in records
        if record.get(
            "exploitation_status"
        ) == "NOT_IN_KEV"
    )

    categories = Counter(
        record.get(
            "exploitation_status",
            "UNKNOWN"
        )
        for record in records
    )

    percentage = (
        known_exploited / total * 100
        if total > 0
        else 0
    )

    print()
    print("=" * 60)
    print("DAY 10 - CISA KEV SUMMARY")
    print("=" * 60)

    print()
    print("DATASET")
    print("-" * 60)
    print(
        f"Total CTI records       : "
        f"{total}"
    )

    print()
    print("EXPLOITATION STATUS")
    print("-" * 60)
    print(
        f"Known exploited         : "
        f"{known_exploited}"
    )

    print(
        f"Not currently in KEV    : "
        f"{not_in_kev}"
    )

    print(
        f"KEV match rate          : "
        f"{percentage:.2f}%"
    )

    print()
    print("STATUS DISTRIBUTION")
    print("-" * 60)

    for status, count in categories.items():

        print(
            f"{status:<24}: "
            f"{count}"
        )

    print()
    print("=" * 60)
    print("KEV ANALYSIS COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
