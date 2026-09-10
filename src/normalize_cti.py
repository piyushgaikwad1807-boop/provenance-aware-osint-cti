import json
import re

INPUT_FILE = "data/processed/cti_records.json"
OUTPUT_FILE = "data/processed/normalized_cti.json"

CVE_PATTERN = r"^CVE-\d{4}-\d{4,7}$"


def normalize_cve(cve):
    return cve.strip().upper()


def validate_cve(cve):
    return bool(re.match(CVE_PATTERN, cve))


def main():

    print("[+] Loading CTI records")

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        records = json.load(file)

    normalized = []
    invalid = 0

    for record in records:

        cve = normalize_cve(
            record["cve_id"]
        )

        if not validate_cve(cve):
            invalid += 1
            continue

        record["cve_id"] = cve

        normalized.append(record)

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            normalized,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(f"[+] Input records: {len(records)}")
    print(f"[+] Valid records: {len(normalized)}")
    print(f"[+] Invalid records: {invalid}")
    print(f"[+] Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
