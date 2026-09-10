import json

INPUT_FILE = "data/processed/normalized_cti.json"


def main():

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        records = json.load(file)

    seen = set()
    duplicates = []

    for record in records:

        cve = record["cve_id"]

        if cve in seen:
            duplicates.append(cve)
        else:
            seen.add(cve)

    print("[+] Total records:", len(records))
    print("[+] Unique CVEs:", len(seen))
    print("[+] Duplicate records:", len(duplicates))

    if duplicates:

        print()
        print("Duplicate CVEs:")

        for cve in sorted(set(duplicates)):
            print("-", cve)


if __name__ == "__main__":
    main()
