import json

FILE = "data/raw/cisa_advisories.json"

with open(FILE, "r", encoding="utf-8") as file:
    data = json.load(file)

titles = data["titles"]

print("Source:", data["source"])
print()

print("Potential vulnerability-related intelligence:")
print("-----------------------------------------------")

for title in titles:
    if "Vulnerability" in title or "Vulnerabilities" in title:
        print("-", title)
