import json
from pathlib import Path


HISTORY_DIR = Path("data/history")
OUTPUT_FILE = Path(
    "data/processed/historical_metrics.json"
)


def load_json(file_path):

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def calculate_percentage(part, total):

    if total == 0:
        return 0.0

    return round(
        (part / total) * 100,
        2
    )


def analyze_snapshot(snapshot):

    records = snapshot.get(
        "dataset",
        {}
    ).get(
        "records",
        []
    )

    total_records = len(records)

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

        if isinstance(
            nvd,
            dict
        ) and nvd:

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

            confidence_scores.append(
                score
            )

    if confidence_scores:

        average_confidence = round(
            sum(confidence_scores)
            / len(confidence_scores),
            3
        )

    else:

        average_confidence = 0.0

    return {
        "snapshot_id": snapshot.get(
            "snapshot_id",
            "UNKNOWN"
        ),

        "created_at": snapshot.get(
            "created_at",
            "UNKNOWN"
        ),

        "total_cves": total_records,

        "known_exploited": known_exploited,

        "corroborated_records": corroborated,

        "nvd_available": nvd_available,

        "average_confidence":
            average_confidence,

        "nvd_coverage_rate":
            calculate_percentage(
                nvd_available,
                total_records
            ),

        "kev_match_rate":
            calculate_percentage(
                known_exploited,
                total_records
            ),

        "corroboration_rate":
            calculate_percentage(
                corroborated,
                total_records
            )
    }


def main():

    print("[+] Starting CTI trend analysis")

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

        print(
            "[!] No historical snapshots found"
        )

        return

    metrics = []

    for snapshot_file in snapshot_files:

        print(
            f"[+] Processing: "
            f"{snapshot_file.name}"
        )

        snapshot = load_json(
            snapshot_file
        )

        result = analyze_snapshot(
            snapshot
        )

        metrics.append(result)

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            metrics,
            file,
            indent=2,
            ensure_ascii=False
        )

    print()
    print("[+] Trend analysis complete")
    print(
        f"[+] Snapshots analyzed: "
        f"{len(metrics)}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )

    print()
    print("Historical Metrics")
    print("=" * 60)

    for item in metrics:

        print(
            f"Snapshot: "
            f"{item['snapshot_id']}"
        )

        print(
            f"Total CVEs: "
            f"{item['total_cves']}"
        )

        print(
            f"Known exploited: "
            f"{item['known_exploited']}"
        )

        print(
            f"Corroborated: "
            f"{item['corroborated_records']}"
        )

        print(
            f"NVD coverage: "
            f"{item['nvd_coverage_rate']}%"
        )

        print(
            f"KEV match rate: "
            f"{item['kev_match_rate']}%"
        )

        print(
            f"Corroboration rate: "
            f"{item['corroboration_rate']}%"
        )

        print(
            f"Average confidence: "
            f"{item['average_confidence']}"
        )

        print("-" * 60)


if __name__ == "__main__":
    main()
