import json
from collections import Counter

INPUT_FILE = "data/processed/risk_analysis.json"


def main():

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        records = json.load(file)

    risk_counts = Counter(
        record["risk_level"]
        for record in records
    )

    severity_counts = Counter(
        record["severity"]
        for record in records
        if record["severity"]
    )

    print("=" * 60)
    print("CTI RISK SUMMARY")
    print("=" * 60)

    print(
        f"Total records: {len(records)}"
    )

    print()
    print("Risk levels:")

    for level in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "UNKNOWN"
    ]:

        print(
            f"- {level}: "
            f"{risk_counts.get(level, 0)}"
        )

    print()
    print("NVD severity:")

    for severity, count in sorted(
        severity_counts.items()
    ):

        print(
            f"- {severity}: {count}"
        )


if __name__ == "__main__":
    main()
