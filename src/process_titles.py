import json

INPUT_FILE = "data/raw/cisa_advisories.json"
OUTPUT_FILE = "data/processed/relevant_titles.json"

with open(INPUT_FILE, "r", encoding="utf-8") as file:
    data = json.load(file)

relevant_titles = []

for title in data["titles"]:
    if (
        "Vulnerability" in title
        or "Vulnerabilities" in title
        or "Malware" in title
        or "Threat" in title
    ):
        relevant_titles.append(title)

result = {
    "source": data["source"],
    "collected_at": data["collected_at"],
    "relevant_titles": relevant_titles
}

with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
    json.dump(result, file, indent=4)

print("[+] Processing complete")
print("[+] Relevant titles:", len(relevant_titles))
print("[+] Saved:", OUTPUT_FILE)
