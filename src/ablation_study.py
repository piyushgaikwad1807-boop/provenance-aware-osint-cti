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
    PROJECT_ROOT / "data/processed/ablation_results.json"
)


SIGNALS = [
    "cisa_evidence",
    "nvd_evidence",
    "kev_exploitation",
    "source_corroboration",
    "cvss_severity",
    "evidence_confidence"
]


THRESHOLD = 50


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


def calculate_model_score(
    signals,
    removed_signal=None
):

    score = 0

    for signal_name, signal_data in signals.items():

        if signal_name == removed_signal:
            continue

        score += signal_data.get(
            "weight",
            0
        )

    return score


def evaluate_model(
    records,
    truth_by_cve,
    removed_signal=None
):

    tp = 0
    tn = 0
    fp = 0
    fn = 0

    evaluated = 0

    for record in records:

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

        signals = record.get(
            "signals"
        ) or {}

        score = calculate_model_score(
            signals,
            removed_signal
        )

        predicted = (
            1
            if score >= THRESHOLD
            else 0
        )

        evaluated += 1

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
        ),
        "evaluated_records": evaluated
    }


def main():

    print("[+] Starting ablation study")

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

    # ---------------------------------------------------------
    # Full model
    # ---------------------------------------------------------

    full_result = evaluate_model(
        correlation,
        truth_by_cve
    )

    results = [
        {
            "experiment": "FULL_MODEL",
            "removed_signal": None,
            "score_scale": "Original weighted score",
            **full_result
        }
    ]

    print(
        "[+] Full model F1: "
        f"{full_result['metrics']['f1_score']:.4f}"
    )

    # ---------------------------------------------------------
    # Remove one signal at a time
    # ---------------------------------------------------------

    for signal in SIGNALS:

        result = evaluate_model(
            correlation,
            truth_by_cve,
            removed_signal=signal
        )

        results.append({
            "experiment": (
                f"REMOVE_{signal.upper()}"
            ),
            "removed_signal": signal,
            "score_scale": (
                "Score after removing "
                "the selected signal"
            ),
            **result
        })

        print(
            f"[+] Remove {signal}: "
            f"F1="
            f"{result['metrics']['f1_score']:.4f}"
        )

    # ---------------------------------------------------------
    # Calculate F1 impact
    # ---------------------------------------------------------

    baseline_f1 = (
        full_result["metrics"]["f1_score"]
    )

    for result in results:

        result_f1 = (
            result["metrics"]["f1_score"]
        )

        result["f1_change"] = round(
            result_f1 - baseline_f1,
            4
        )

    # ---------------------------------------------------------
    # Identify largest performance impact
    # ---------------------------------------------------------

    removal_results = [
        result
        for result in results
        if result["removed_signal"] is not None
    ]

    if removal_results:

        most_important = min(
            removal_results,
            key=lambda result:
                result["f1_change"]
        )

        least_important = max(
            removal_results,
            key=lambda result:
                result["f1_change"]
        )

    else:

        most_important = None
        least_important = None

    output = {

        "analysis_metadata": {

            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),

            "method": (
                "One-factor-at-a-time ablation study "
                "of the heuristic CTI correlation model."
            ),

            "threshold": THRESHOLD,

            "signals_tested": SIGNALS
        },

        "results": results,

        "interpretation": {

            "most_performance_sensitive_signal": (
                most_important["removed_signal"]
                if most_important
                else None
            ),

            "largest_f1_change": (
                most_important["f1_change"]
                if most_important
                else None
            ),

            "least_performance_sensitive_signal": (
                least_important["removed_signal"]
                if least_important
                else None
            )
        },

        "limitations": [

            "The ablation study uses the same benchmark "
            "dataset for all experiments.",

            "The benchmark uses CISA KEV membership "
            "as a proxy exploitation label.",

            "The dataset is small.",

            "The selected threshold is fixed at 50 for "
            "comparability between experiments.",

            "The model weights are heuristic.",

            "Signals may be correlated with each other.",

            "Removing one signal does not prove that the "
            "signal is causally responsible for performance."
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

    print("[+] Ablation study complete")

    if most_important:

        print(
            "[+] Most performance-sensitive signal: "
            f"{most_important['removed_signal']}"
        )

        print(
            "[+] F1 change: "
            f"{most_important['f1_change']:.4f}"
        )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
