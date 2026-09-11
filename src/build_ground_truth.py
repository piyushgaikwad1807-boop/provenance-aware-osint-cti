import json
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = PROJECT_ROOT / "data/processed/final_cti.json"
OUTPUT_FILE = PROJECT_ROOT / "data/processed/ground_truth.json"


def load_json(path):
    if not path.exists():
        return None

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def create_label(record):
    """
    Create a benchmark label from strong exploitation evidence.

    Positive:
        CVE is listed in CISA KEV.

    Negative:
        CVE is not currently listed in CISA KEV.

    This is a proxy benchmark label, not absolute ground truth.
    """

    exploitation_status = record.get(
        "exploitation_status",
        "UNKNOWN"
    )

    if exploitation_status == "KNOWN_EXPLOITED":
        return 1, "KNOWN_EXPLOITED"

    if exploitation_status == "NOT_IN_KEV":
        return 0, "NOT_IN_KEV"

    return None, "UNKNOWN"


def main():

    print("[+] Building benchmark dataset")

    records = load_json(INPUT_FILE)

    if not records:
        print("[!] final_cti.json not found or empty")
        return

    benchmark = []

    for record in records:

        cve_id = record.get("cve_id", "UNKNOWN")

        label, label_reason = create_label(record)

        benchmark.append({
            "cve_id": cve_id,
            "ground_truth_label": label,
            "ground_truth_reason": label_reason,
            "label_definition": (
                "1 indicates known exploitation evidence through "
                "CISA KEV; 0 indicates the CVE is not currently "
                "listed in CISA KEV."
            ),
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat()
        })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(benchmark, file, indent=2)

    labeled = [
        record for record in benchmark
        if record["ground_truth_label"] is not None
    ]

    positive = [
        record for record in labeled
        if record["ground_truth_label"] == 1
    ]

    negative = [
        record for record in labeled
        if record["ground_truth_label"] == 0
    ]

    print("[+] Benchmark dataset created")
    print(f"[+] Total records: {len(benchmark)}")
    print(f"[+] Labeled records: {len(labeled)}")
    print(f"[+] Positive labels: {len(positive)}")
    print(f"[+] Negative labels: {len(negative)}")
    print(f"[+] Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
