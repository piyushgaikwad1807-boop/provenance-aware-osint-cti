import json
import re

INPUT_FILE = "data/raw/cisa_advisories_full.json"

with open(INPUT_FILE, "r", encoding="utf-8") as file:
    advisories = json.load(file)

pattern = r"CVE-\d{4}-\d{4,7}"

total_cves = 0

for advisory in advisories:

    cves = re.findall(
        pattern,
        advisory["content"],
        re.IGNORECASE
    )

    unique_cves = sorted(set(cves))

    print("=" * 70)
    print(advisory["title"])
    print("=" * 70)

    if unique_cves:

        for cve in unique_cves:
            print("-", cve)

        total_cves += len(unique_cves)

    else:
        print("No CVE found")

print()
print("[+] Total CVEs found:", total_cves)
