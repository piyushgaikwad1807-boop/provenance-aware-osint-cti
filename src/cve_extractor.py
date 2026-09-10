import json
import re

FILE = "data/raw/cisa_advisories.json"

with open(FILE, "r", encoding="utf-8") as file:
    data = json.load(file)

text = " ".join(data["titles"])

pattern = r"CVE-\d{4}-\d{4,7}"

cves = re.findall(pattern, text)

print("Source:", data["source"])
print("CVEs found:", len(cves))
print()

for cve in cves:
    print("-", cve)
