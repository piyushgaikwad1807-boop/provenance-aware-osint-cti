import json
from datetime import datetime, timezone
from pathlib import Path


FINAL_DATA_FILE = Path("data/processed/final_cti.json")
EVALUATION_FILE = Path("data/processed/evaluation_report.json")

HISTORY_DIR = Path("data/history")


def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def main():

    print("[+] Starting CTI snapshot creation")

    if not FINAL_DATA_FILE.exists():
        print(f"[!] Missing file: {FINAL_DATA_FILE}")
        return

    HISTORY_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    data = load_json(FINAL_DATA_FILE)

    evaluation = {}

    if EVALUATION_FILE.exists():
        evaluation_data = load_json(EVALUATION_FILE)
        evaluation = evaluation_data.get(
            "evaluation_summary",
            {}
        )

    timestamp = datetime.now(timezone.utc)

    snapshot_id = timestamp.strftime(
        "%Y%m%d_%H%M%S"
    )

    snapshot = {
        "snapshot_id": snapshot_id,
        "created_at": timestamp.isoformat(),

        "dataset": {
            "total_records": len(data),
            "records": data
        },

        "evaluation": evaluation
    }

    output_file = HISTORY_DIR / (
        f"cti_snapshot_{snapshot_id}.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            snapshot,
            file,
            indent=2,
            ensure_ascii=False
        )

    print()
    print("[+] Snapshot created")
    print(f"[+] Records: {len(data)}")
    print(f"[+] Snapshot ID: {snapshot_id}")
    print(f"[+] Saved: {output_file}")


if __name__ == "__main__":
    main()
