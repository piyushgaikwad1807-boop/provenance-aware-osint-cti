import json
from pathlib import Path
from collections import Counter


INPUT_FILE = Path(
    "data/processed/final_cti.json"
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

    # --------------------------------------------------
    # Severity
    # --------------------------------------------------

    severity_counter = Counter(
        record.get(
            "risk",
            {}
        ).get(
            "severity",
            "UNKNOWN"
        )
        for record in records
    )

    # --------------------------------------------------
    # Risk
    # --------------------------------------------------

    risk_counter = Counter(
        record.get(
            "risk",
            {}
        ).get(
            "risk_level",
            "UNKNOWN"
        )
        for record in records
    )

    # --------------------------------------------------
    # Confidence
    # --------------------------------------------------

    confidence_counter = Counter(
        record.get(
            "confidence",
            {}
        ).get(
            "category",
            "UNKNOWN"
        )
        for record in records
    )

    # --------------------------------------------------
    # Exploitation
    # --------------------------------------------------

    exploitation_counter = Counter(
        record.get(
            "exploitation_status",
            "UNKNOWN"
        )
        for record in records
    )

    # --------------------------------------------------
    # Corroboration
    # --------------------------------------------------

    corroborated = sum(
        1
        for record in records
        if record.get(
            "provenance",
            {}
        ).get(
            "corroborated",
            False
        )
    )

    corroboration_rate = (
        corroborated / total * 100
        if total > 0
        else 0
    )

    # --------------------------------------------------
    # NVD
    # --------------------------------------------------

    nvd_available = sum(
        1
        for record in records
        if record.get("nvd") is not None
    )

    nvd_rate = (
        nvd_available / total * 100
        if total > 0
        else 0
    )

    # --------------------------------------------------
    # Print
    # --------------------------------------------------

    print()
    print("=" * 65)
    print("DAY 11 - FINAL CTI DATASET SUMMARY")
    print("=" * 65)

    print()
    print("DATASET")
    print("-" * 65)

    print(
        f"Total CTI records       : "
        f"{total}"
    )

    print(
        f"NVD records available   : "
        f"{nvd_available} "
        f"({nvd_rate:.2f}%)"
    )

    print()
    print("CORROBORATION")
    print("-" * 65)

    print(
        f"Corroborated records    : "
        f"{corroborated}"
    )

    print(
        f"Corroboration rate      : "
        f"{corroboration_rate:.2f}%"
    )

    print()
    print("EXPLOITATION STATUS")
    print("-" * 65)

    for status, count in (
        exploitation_counter.items()
    ):

        print(
            f"{status:<24}: "
            f"{count}"
        )

    print()
    print("CVSS SEVERITY")
    print("-" * 65)

    for severity, count in (
        severity_counter.items()
    ):

        print(
            f"{severity:<24}: "
            f"{count}"
        )

    print()
    print("RISK LEVEL")
    print("-" * 65)

    for risk, count in (
        risk_counter.items()
    ):

        print(
            f"{risk:<24}: "
            f"{count}"
        )

    print()
    print("CONFIDENCE")
    print("-" * 65)

    for category, count in (
        confidence_counter.items()
    ):

        print(
            f"{category:<24}: "
            f"{count}"
        )

    print()
    print("=" * 65)
    print("FINAL CTI ANALYSIS COMPLETE")
    print("=" * 65)


if __name__ == "__main__":
    main()
