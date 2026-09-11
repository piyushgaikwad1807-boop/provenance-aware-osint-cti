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
    PROJECT_ROOT / "data/processed/threshold_analysis.json"
)


THRESHOLDS = [
    20,
    30,
    40,
    50,
    60,
    70,
    80
]


def load_json(path):

    if not path.exists():
        return None

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


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


def evaluate_threshold(
    correlation_records,
    truth_by_cve,
    threshold
):

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    evaluated = 0

    for record in correlation_records:

        cve_id = record.get("cve_id")

        truth_record = truth_by_cve.get(cve_id)

        if not truth_record:
            continue

        actual = truth_record.get(
            "ground_truth_label"
        )

        if actual is None:
            continue

        correlation = record.get("correlation") or {}

        score = correlation.get("score")

        if not isinstance(score, (int, float)):
            continue

        predicted = 1 if score >= threshold else 0

        evaluated += 1

        if predicted == 1 and actual == 1:
            tp += 1

        elif predicted == 0 and actual == 0:
            tn += 1

        elif predicted == 1 and actual == 0:
            fp += 1

        elif predicted == 0 and actual == 1:
            fn += 1

    metrics = calculate_metrics(
        tp,
        tn,
        fp,
        fn
    )

    return {
        "threshold": threshold,

        "confusion_matrix": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn
        },

        "metrics": metrics,

        "evaluated_records": evaluated
    }


def main():

    print("[+] Starting threshold sensitivity analysis")

    ground_truth = load_json(GROUND_TRUTH_FILE)

    correlation = load_json(CORRELATION_FILE)

    if not ground_truth:

        print(
            "[!] ground_truth.json "
            "not found or empty"
        )

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

    results = []

    for threshold in THRESHOLDS:

        result = evaluate_threshold(
            correlation,
            truth_by_cve,
            threshold
        )

        results.append(result)

        metrics = result["metrics"]

        print(
            f"[+] Threshold {threshold}: "
            f"Precision={metrics['precision']:.4f}, "
            f"Recall={metrics['recall']:.4f}, "
            f"F1={metrics['f1_score']:.4f}"
        )

    valid_results = [
        result
        for result in results
        if result["evaluated_records"] > 0
    ]

    if valid_results:

        best_result = max(
            valid_results,
            key=lambda result:
                result["metrics"]["f1_score"]
        )

        best_threshold = best_result["threshold"]

    else:

        best_result = None
        best_threshold = None

    output = {

        "analysis_metadata": {

            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "method": (
                "Threshold sensitivity analysis "
                "using proxy exploitation labels."
            ),

            "thresholds_tested": THRESHOLDS
        },

        "threshold_results": results,

        "best_threshold": {

            "threshold": best_threshold,

            "selection_metric": "F1 Score",

            "reason": (
                "Threshold with the highest F1 score "
                "among evaluated thresholds."
            )
        },

        "limitations": [

            "The benchmark uses CISA KEV membership "
            "as a proxy exploitation label.",

            "Absence from KEV does not prove absence "
            "of exploitation.",

            "The correlation model uses heuristic "
            "weights.",

            "The dataset is small and may not generalize "
            "to broader vulnerability populations.",

            "Threshold optimization on the same dataset "
            "can overfit the benchmark."
        ]
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=2
        )

    print("[+] Threshold analysis complete")

    if best_result:

        print(
            f"[+] Best threshold: "
            f"{best_threshold}"
        )

        print(
            f"[+] Best F1 score: "
            f"{best_result['metrics']['f1_score']:.4f}"
        )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
