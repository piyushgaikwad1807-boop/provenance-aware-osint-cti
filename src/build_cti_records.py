import json
import re

INPUT_FILE = "data/raw/cisa_advisories_full.json"
OUTPUT_FILE = "data/processed/cti_records.json"

CVE_PATTERN = r"CVE-\d{4}-\d{4,7}"


def extract_cves(text):
    matches = re.findall(
        CVE_PATTERN,
        text,
        re.IGNORECASE
    )

    return sorted(set(
        cve.upper()
        for cve in matches
    ))


def build_records(advisories):

    records = []

    for advisory in advisories:

        cves = extract_cves(
            advisory["content"]
        )

        for cve in cves:

            record = {
                "cve_id": cve,
                "source": "CISA",
                "advisory_title": advisory["title"],
                "advisory_url": advisory["url"],
                "collected_at": advisory["collected_at"],
                "evidence": f"CVE identifier found in CISA advisory: {cve}",
                "confidence": 1.0
            }

            records.append(record)

    return records


def main():

    print("[+] Loading CISA advisory data")

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        advisories = json.load(file)

    print(
        f"[+] Advisories loaded: {len(advisories)}"
    )

    records = build_records(advisories)

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            records,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(
        f"[+] CTI records created: {len(records)}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
