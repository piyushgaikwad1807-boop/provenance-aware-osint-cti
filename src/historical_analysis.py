import json
from pathlib import Path


HISTORY_DIR = Path("data/history")


def load_json(file_path):

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def calculate_metrics(snapshot):

    records = snapshot.get(
        "dataset",
        {}
    ).get(
        "records",
        []
    )

    total = len(records)

    known_exploited = 0
    corroborated = 0
    nvd_available = 0

    confidence_scores = []

    for record in records:

        if record.get(
            "exploitation_status"
        ) == "KNOWN_EXPLOITED":

            known_exploited += 1

        provenance = record.get(
            "provenance",
            {}
        )

        if provenance.get(
            "corroborated"
        ) is True:

            corroborated += 1

        nvd = record.get("nvd")

        if isinstance(nvd, dict) and nvd:

            nvd_available += 1

        confidence = record.get(
            "confidence",
            {}
        )

        score = confidence.get(
            "score"
        )

        if isinstance(
            score,
            (int, float)
        ):

            confidence_scores.append(score)

    if confidence_scores:

        average_confidence = round(
            sum(confidence_scores)
            / len(confidence_scores),
            3
        )

    else:

        average_confidence = 0

    return {
        "total_records": total,
        "known_exploited": known_exploited,
        "corroborated_records": corroborated,
        "nvd_available": nvd_available,
        "average_confidence": average_confidence
    }


def main():

    print("[+] Starting historical CTI analysis")

    if not HISTORY_DIR.exists():

        print(
            f"[!] Missing directory: "
            f"{HISTORY_DIR}"
        )

        return

    snapshot_files = sorted(
        HISTORY_DIR.glob(
            "cti_snapshot_*.json"
        )
    )

    if not snapshot_files:

        print("[!] No snapshots found")

        return

    print()
    print(
        f"[+] Snapshots found: "
        f"{len(snapshot_files)}"
    )

    print()

    for snapshot_file in snapshot_files:

        snapshot = load_json(
            snapshot_file
        )

        snapshot_id = snapshot.get(
            "snapshot_id",
            "UNKNOWN"
        )

        created_at = snapshot.get(
            "created_at",
            "UNKNOWN"
        )

        metrics = calculate_metrics(
            snapshot
        )

        print(
            f"Snapshot: {snapshot_id}"
        )

        print(
            f"Created: {created_at}"
        )

        print(
            f"Total CVEs: "
            f"{metrics['total_records']}"
        )

        print(
            f"Known exploited: "
            f"{metrics['known_exploited']}"
        )

        print(
            f"Corroborated: "
            f"{metrics['corroborated_records']}"
        )

        print(
            f"NVD available: "
            f"{metrics['nvd_available']}"
        )

        print(
            f"Average confidence: "
            f"{metrics['average_confidence']}"
        )

        print("-" * 50)


if __name__ == "__main__":
    main()
