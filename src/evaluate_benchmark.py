import json
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent

GROUND_TRUTH_FILE = (
    PROJECT_ROOT / "data/processed/ground_truth.json"
)

CORRELATION_FILE = (
    PROJECT_ROOT / "data/processed/improved_correlation_cti.json"
)

OUTPUT_FILE = (
    PROJECT_ROOT / "data/processed/benchmark_evaluation.json"
)


def load_json(path):

    if not path.exists():
        return None

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def predicted_label(record):

    correlation = record.get("correlation") or {}

    level = correlation.get("level", "VERY_LOW")

    if level in ["VERY_HIGH", "HIGH"]:
        return 1

    return 0


def calculate_metrics(tp, tn, fp, fn):

    total = tp + tn + fp + fn

    accuracy = (
        (tp + tn) / total
        if total
        else 0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0
    )

    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0
    )

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4)
    }


def main():

    print("[+] Starting benchmark evaluation")

    ground_truth = load_json(GROUND_TRUTH_FILE)
    correlation = load_json(CORRELATION_FILE)

    if not ground_truth:
        print("[!] ground_truth.json not found or empty")
        return

    if not correlation:
        print(
            "[!] improved_correlation_cti.json "
            "not found or empty"
        )
        return

    truth_by_cve = {
        record.get("cve_id"): record
        for record in ground_truth
    }

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    evaluated_records = []
    skipped_records = []

    for record in correlation:

        cve_id = record.get("cve_id")

        truth_record = truth_by_cve.get(cve_id)

        if not truth_record:
            skipped_records.append(cve_id)
            continue

        actual = truth_record.get(
            "ground_truth_label"
        )

        if actual is None:
            skipped_records.append(cve_id)
            continue

        predicted = predicted_label(record)

        if predicted == 1 and actual == 1:
            tp += 1

        elif predicted == 0 and actual == 0:
            tn += 1

        elif predicted == 1 and actual == 0:
            fp += 1

        elif predicted == 0 and actual == 1:
            fn += 1

        evaluated_records.append({
            "cve_id": cve_id,
            "actual_label": actual,
            "predicted_label": predicted,
            "correlation_score": (
                record.get("correlation", {})
                .get("score")
            ),
            "correlation_level": (
                record.get("correlation", {})
                .get("level")
            )
        })

    metrics = calculate_metrics(
        tp,
        tn,
        fp,
        fn
    )

    evaluation = {

        "evaluation_metadata": {
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "method": (
                "Benchmark evaluation using CISA KEV "
                "membership as a proxy exploitation label."
            ),

            "prediction_rule": (
                "VERY_HIGH and HIGH correlation levels "
                "are classified as positive."
            )
        },

        "dataset": {
            "total_ground_truth_records": len(ground_truth),
            "evaluated_records": len(evaluated_records),
            "skipped_records": len(skipped_records)
        },

        "confusion_matrix": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn
        },

        "classification_metrics": metrics,

        "evaluated_records": evaluated_records,

        "skipped_cves": skipped_records,

        "limitations": [
            "CISA KEV membership is used as a proxy label.",
            "Not being listed in KEV does not prove that a vulnerability has never been exploited.",
            "The benchmark is not an independent expert-labelled ground-truth dataset.",
            "The current correlation model uses heuristic weights.",
            "The evaluation does not establish real-world predictive accuracy."
        ]
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(
            evaluation,
            file,
            indent=2
        )

    print("[+] Benchmark evaluation complete")
    print(
        f"[+] Evaluated records: "
        f"{len(evaluated_records)}"
    )

    print("[+] Confusion matrix:")
    print(f"    TP: {tp}")
    print(f"    TN: {tn}")
    print(f"    FP: {fp}")
    print(f"    FN: {fn}")

    print("[+] Metrics:")
    print(
        f"    Accuracy: "
        f"{metrics['accuracy']:.4f}"
    )

    print(
        f"    Precision: "
        f"{metrics['precision']:.4f}"
    )

    print(
        f"    Recall: "
        f"{metrics['recall']:.4f}"
    )

    print(
        f"    F1 Score: "
        f"{metrics['f1_score']:.4f}"
    )

    print(f"[+] Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
