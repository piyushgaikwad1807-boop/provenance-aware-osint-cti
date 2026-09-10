import json
from collections import Counter

INPUT_FILE = "data/processed/normalized_cti.json"


def main():

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        records = json.load(file)

    sources = Counter(
        record["source"]
        for record in records
    )

    print("=" * 50)
    print("CTI DATASET SUMMARY")
    print("=" * 50)

    print("Total CTI records:", len(records))
    print("Unique CVEs:", len(
        set(record["cve_id"] for record in records)
    ))

    print()
    print("Sources:")

    for source, count in sources.items():
        print(f"- {source}: {count}")


if __name__ == "__main__":
    main()
