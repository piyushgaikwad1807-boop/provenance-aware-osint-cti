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
    PROJECT_ROOT / "data/processed/train_validation_results.json"
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


TRAIN_RATIO = 0.70


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
        2 * precision * recall /
        (precision + recall)
        if (precision + recall)
        else 0
    )

    return {
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4)
    }


def evaluate_records(records, threshold):

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    for record in records:

        actual = record["actual_label"]
        score = record["correlation_score"]

        predicted = (
            1
            if score >= threshold
            else 0
        )

        if predicted == 1 and actual == 1:
            tp += 1

        elif predicted == 0 and actual == 0:
            tn += 1

        elif predicted == 1 and actual == 0:
            fp += 1

        elif predicted == 0 and actual == 1:
            fn += 1

    return {
        "confusion_matrix": {
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn
        },
        "metrics": calculate_metrics(
            tp,
            tn,
            fp,
            fn
        )
    }


def main():

    print("[+] Starting train/validation experiment")

    ground_truth = load_json(
        GROUND_TRUTH_FILE
    )

    correlation = load_json(
        CORRELATION_FILE
    )

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

    combined = []

    for record in correlation:

        cve_id = record.get("cve_id")

        truth_record = truth_by_cve.get(
            cve_id
        )

        if not truth_record:
            continue

        actual = truth_record.get(
            "ground_truth_label"
        )

        if actual is None:
            continue

        correlation_data = (
            record.get("correlation") or {}
        )

        score = correlation_data.get(
            "score"
        )

        if not isinstance(
            score,
            (int, float)
        ):
            continue

        combined.append({
            "cve_id": cve_id,
            "actual_label": actual,
            "correlation_score": score
        })

    if len(combined) < 2:

        print(
            "[!] Not enough labeled records "
            "for train/validation experiment"
        )

        return

    # ---------------------------------------------------------
    # Deterministic ordering
    # ---------------------------------------------------------

    combined = sorted(
        combined,
        key=lambda record: record["cve_id"]
    )

    split_index = int(
        len(combined) * TRAIN_RATIO
    )

    if split_index < 1:
        split_index = 1

    if split_index >= len(combined):
        split_index = len(combined) - 1

    training_records = combined[
        :split_index
    ]

    validation_records = combined[
        split_index:
    ]

    print(
        f"[+] Total labeled records: "
        f"{len(combined)}"
    )

    print(
        f"[+] Training records: "
        f"{len(training_records)}"
    )

    print(
        f"[+] Validation records: "
        f"{len(validation_records)}"
    )

    # ---------------------------------------------------------
    # Find best threshold on training data
    # ---------------------------------------------------------

    training_results = []

    for threshold in THRESHOLDS:

        result = evaluate_records(
            training_records,
            threshold
        )

        training_results.append({
            "threshold": threshold,
            **result
        })

    best_training_result = max(
        training_results,
        key=lambda result:
            result["metrics"]["f1_score"]
    )

    best_threshold = (
        best_training_result["threshold"]
    )

    print(
        f"[+] Selected threshold from "
        f"training data: {best_threshold}"
    )

    print(
        f"[+] Training F1: "
        f"{best_training_result['metrics']['f1_score']:.4f}"
    )

    # ---------------------------------------------------------
    # Evaluate selected threshold on validation data
    # ---------------------------------------------------------

    validation_result = evaluate_records(
        validation_records,
        best_threshold
    )

    validation_metrics = (
        validation_result["metrics"]
    )

    print(
        f"[+] Validation accuracy: "
        f"{validation_metrics['accuracy']:.4f}"
    )

    print(
        f"[+] Validation precision: "
        f"{validation_metrics['precision']:.4f}"
    )

    print(
        f"[+] Validation recall: "
        f"{validation_metrics['recall']:.4f}"
    )

    print(
        f"[+] Validation F1: "
        f"{validation_metrics['f1_score']:.4f}"
    )

    output = {

        "experiment_metadata": {

            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "method": (
                "Deterministic train/validation-style "
                "threshold experiment."
            ),

            "training_ratio": TRAIN_RATIO,

            "validation_ratio": (
                1 - TRAIN_RATIO
            ),

            "thresholds_tested": THRESHOLDS
        },

        "dataset": {

            "total_labeled_records": len(
                combined
            ),

            "training_records": len(
                training_records
            ),

            "validation_records": len(
                validation_records
            )
        },

        "training": {

            "threshold_results":
                training_results,

            "selected_threshold":
                best_threshold,

            "selected_training_metrics":
                best_training_result["metrics"]
        },

        "validation": {

            "threshold_used":
                best_threshold,

            "confusion_matrix":
                validation_result[
                    "confusion_matrix"
                ],

            "metrics":
                validation_metrics
        },

        "limitations": [

            "The dataset is currently very small.",

            "The train/validation split is deterministic "
            "and is not a substitute for cross-validation.",

            "The benchmark uses CISA KEV membership "
            "as a proxy exploitation label.",

            "Threshold selection and validation are "
            "still based on a limited benchmark.",

            "The experiment does not establish "
            "general real-world predictive accuracy."
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

    print(
        "[+] Train/validation experiment complete"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
