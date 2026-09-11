import json
from pathlib import Path
from collections import Counter, defaultdict
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent

CORRELATION_FILE = (
    PROJECT_ROOT / "data/processed/correlation_cti.json"
)

OUTPUT_FILE = (
    PROJECT_ROOT / "data/processed/correlation_evaluation.json"
)


def load_json(path):
    if not path.exists():
        return None

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def average(values):
    if not values:
        return 0

    return sum(values) / len(values)


def percentage(part, total):
    if total == 0:
        return 0

    return (part / total) * 100


def main():

    print("[+] Starting correlation model evaluation")

    records = load_json(CORRELATION_FILE)

    if not records:
        print("[!] correlation_cti.json not found or empty")
        return

    total_records = len(records)

    scores = []

    correlation_levels = []

    kev_scores = []

    non_kev_scores = []

    corroborated_scores = []

    non_corroborated_scores = []

    confidence_groups = defaultdict(list)

    for record in records:

        score = record.get(
            "correlation_score"
        )

        level = record.get(
            "correlation_level",
            "UNKNOWN"
        )

        signals = record.get(
            "signals",
            {}
        )

        if isinstance(score, (int, float)):
            scores.append(score)

        correlation_levels.append(level)

        exploitation_status = signals.get(
            "kev_exploitation",
            "UNKNOWN"
        )

        if exploitation_status == "KNOWN_EXPLOITED":
            if isinstance(score, (int, float)):
                kev_scores.append(score)

        elif exploitation_status == "NOT_IN_KEV":
            if isinstance(score, (int, float)):
                non_kev_scores.append(score)

        source_count = signals.get(
            "source_count",
            0
        )

        if source_count >= 2:

            if isinstance(score, (int, float)):
                corroborated_scores.append(score)

        else:

            if isinstance(score, (int, float)):
                non_corroborated_scores.append(score)

        confidence_score = signals.get(
            "confidence_score"
        )

        if isinstance(confidence_score, (int, float)):

            if confidence_score >= 0.80:
                category = "HIGH"

            elif confidence_score >= 0.60:
                category = "MEDIUM"

            elif confidence_score >= 0.40:
                category = "LOW"

            else:
                category = "VERY_LOW"

            confidence_groups[category].append(
                score
            )

    level_counts = Counter(
        correlation_levels
    )

    evaluation = {
        "evaluation_metadata": {
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "method": (
                "Descriptive evaluation of the "
                "prototype correlation model"
            )
        },

        "overall_metrics": {
            "total_records": total_records,
            "average_score": round(
                average(scores),
                3
            ),
            "highest_score": (
                max(scores) if scores else 0
            ),
            "lowest_score": (
                min(scores) if scores else 0
            )
        },

        "correlation_level_distribution": {
            "VERY_HIGH": level_counts.get(
                "VERY_HIGH",
                0
            ),
            "HIGH": level_counts.get(
                "HIGH",
                0
            ),
            "MEDIUM": level_counts.get(
                "MEDIUM",
                0
            ),
            "LOW": level_counts.get(
                "LOW",
                0
            ),
            "VERY_LOW": level_counts.get(
                "VERY_LOW",
                0
            )
        },

        "exploitation_analysis": {
            "known_exploited_records": len(
                kev_scores
            ),
            "not_in_kev_records": len(
                non_kev_scores
            ),
            "average_known_exploited_score": round(
                average(kev_scores),
                3
            ),
            "average_not_in_kev_score": round(
                average(non_kev_scores),
                3
            )
        },

        "corroboration_analysis": {
            "corroborated_records": len(
                corroborated_scores
            ),
            "non_corroborated_records": len(
                non_corroborated_scores
            ),
            "average_corroborated_score": round(
                average(corroborated_scores),
                3
            ),
            "average_non_corroborated_score": round(
                average(non_corroborated_scores),
                3
            )
        },

        "confidence_analysis": {},

        "research_metrics": {
            "kev_match_rate": round(
                percentage(
                    len(kev_scores),
                    total_records
                ),
                2
            ),
            "corroboration_rate": round(
                percentage(
                    len(corroborated_scores),
                    total_records
                ),
                2
            )
        }
    }

    for category, category_scores in confidence_groups.items():

        evaluation["confidence_analysis"][
            category
        ] = {
            "record_count": len(
                category_scores
            ),
            "average_correlation_score": round(
                average(category_scores),
                3
            )
        }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            evaluation,
            file,
            indent=2
        )

    print("[+] Correlation evaluation complete")

    print(
        f"[+] Total records: {total_records}"
    )

    print(
        f"[+] Average score: "
        f"{average(scores):.3f}"
    )

    print(
        f"[+] Highest score: "
        f"{max(scores) if scores else 0}"
    )

    print(
        f"[+] Lowest score: "
        f"{min(scores) if scores else 0}"
    )

    print(
        "[+] Correlation levels:"
    )

    for level in [
        "VERY_HIGH",
        "HIGH",
        "MEDIUM",
        "LOW",
        "VERY_LOW"
    ]:

        print(
            f"    {level}: "
            f"{level_counts.get(level, 0)}"
        )

    print(
        "[+] Exploitation analysis:"
    )

    print(
        f"    Known exploited: "
        f"{len(kev_scores)}"
    )

    print(
        f"    Not in KEV: "
        f"{len(non_kev_scores)}"
    )

    print(
        "[+] Corroboration analysis:"
    )

    print(
        f"    Corroborated: "
        f"{len(corroborated_scores)}"
    )

    print(
        f"    Non-corroborated: "
        f"{len(non_corroborated_scores)}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
