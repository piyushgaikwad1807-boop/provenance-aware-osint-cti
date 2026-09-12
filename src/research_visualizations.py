import json
from pathlib import Path

import matplotlib.pyplot as plt


BASE_DIR = Path(__file__).resolve().parent.parent

PROCESSED_DIR = BASE_DIR / "data" / "processed"
REPORT_DIR = BASE_DIR / "reports" / "figures"

FINAL_CTI_FILE = PROCESSED_DIR / "final_cti.json"
CORRELATION_FILE = PROCESSED_DIR / "improved_correlation_cti.json"
BENCHMARK_FILE = PROCESSED_DIR / "benchmark_evaluation.json"
THRESHOLD_FILE = PROCESSED_DIR / "threshold_analysis.json"
ABLATION_FILE = PROCESSED_DIR / "ablation_results.json"

REPORT_DIR.mkdir(parents=True, exist_ok=True)


def load_json(path):
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def save_figure(filename):
    path = REPORT_DIR / filename
    plt.tight_layout()
    plt.savefig(path, dpi=300, bbox_inches="tight")
    plt.close()
    print(f"[+] Saved: {path}")


def create_correlation_score_distribution(correlation_data):
    scores = [
        record.get("correlation_score")
        for record in correlation_data
        if isinstance(record.get("correlation_score"), (int, float))
    ]

    if not scores:
        return

    plt.figure(figsize=(8, 5))
    plt.hist(scores, bins=8, edgecolor="black")

    plt.title("Distribution of CTI Correlation Scores")
    plt.xlabel("Correlation Score")
    plt.ylabel("Number of CVE Records")
    plt.grid(axis="y", alpha=0.3)

    save_figure("correlation_score_distribution.png")


def create_correlation_levels(correlation_data):
    levels = {}

    for record in correlation_data:
        level = record.get("correlation_level", "UNKNOWN")
        levels[level] = levels.get(level, 0) + 1

    if not levels:
        return

    labels = list(levels.keys())
    values = list(levels.values())

    plt.figure(figsize=(8, 5))
    plt.bar(labels, values, edgecolor="black")

    plt.title("CTI Correlation Level Distribution")
    plt.xlabel("Correlation Level")
    plt.ylabel("Number of CVE Records")
    plt.xticks(rotation=30)
    plt.grid(axis="y", alpha=0.3)

    save_figure("correlation_level_distribution.png")


def create_exploitation_distribution(final_data):
    statuses = {}

    for record in final_data:
        status = record.get(
            "exploitation_status",
            "UNKNOWN"
        )

        statuses[status] = statuses.get(status, 0) + 1

    labels = list(statuses.keys())
    values = list(statuses.values())

    plt.figure(figsize=(8, 5))
    plt.bar(labels, values, edgecolor="black")

    plt.title("CTI Exploitation Status")
    plt.xlabel("Exploitation Status")
    plt.ylabel("Number of CVE Records")
    plt.xticks(rotation=20)
    plt.grid(axis="y", alpha=0.3)

    save_figure("exploitation_status.png")


def create_threshold_performance(threshold_data):
    results = threshold_data.get("threshold_results", [])

    if not results:
        return

    thresholds = []
    accuracy = []
    precision = []
    recall = []
    f1 = []

    for result in results:
        thresholds.append(result.get("threshold"))
        accuracy.append(result.get("accuracy", 0))
        precision.append(result.get("precision", 0))
        recall.append(result.get("recall", 0))
        f1.append(result.get("f1", 0))

    plt.figure(figsize=(8, 5))

    plt.plot(thresholds, accuracy, marker="o", label="Accuracy")
    plt.plot(thresholds, precision, marker="o", label="Precision")
    plt.plot(thresholds, recall, marker="o", label="Recall")
    plt.plot(thresholds, f1, marker="o", label="F1 Score")

    plt.title("Correlation Threshold Performance")
    plt.xlabel("Correlation Score Threshold")
    plt.ylabel("Metric Value")
    plt.ylim(0, 1.05)
    plt.legend()
    plt.grid(True, alpha=0.3)

    save_figure("threshold_performance.png")


def create_ablation_results(ablation_data):
    experiments = ablation_data.get("experiments", [])

    if not experiments:
        return

    labels = []
    f1_scores = []

    for experiment in experiments:
        signal = experiment.get("removed_signal")

        if signal is None:
            continue

        labels.append(signal.replace("_", " ").title())
        f1_scores.append(experiment.get("f1", 0))

    if not labels:
        return

    plt.figure(figsize=(10, 5))
    plt.bar(labels, f1_scores, edgecolor="black")

    plt.title("Ablation Study: F1 Score After Signal Removal")
    plt.xlabel("Removed Signal")
    plt.ylabel("F1 Score")
    plt.ylim(0, 1.05)
    plt.xticks(rotation=35)
    plt.grid(axis="y", alpha=0.3)

    save_figure("ablation_f1_scores.png")


def create_correlation_vs_exploitation(correlation_data, final_data):
    final_lookup = {
        record.get("cve_id"): record
        for record in final_data
    }

    exploited = []
    not_in_kev = []

    for record in correlation_data:
        cve_id = record.get("cve_id")
        score = record.get("correlation_score")

        if not isinstance(score, (int, float)):
            continue

        final_record = final_lookup.get(cve_id, {})

        status = final_record.get(
            "exploitation_status",
            "UNKNOWN"
        )

        if status == "KNOWN_EXPLOITED":
            exploited.append(score)

        elif status == "NOT_IN_KEV":
            not_in_kev.append(score)

    if not exploited and not not_in_kev:
        return

    plt.figure(figsize=(8, 5))

    groups = []
    values = []

    if exploited:
        groups.append("Known Exploited")
        values.append(exploited)

    if not_in_kev:
        groups.append("Not in KEV")
        values.append(not_in_kev)

    plt.boxplot(values, labels=groups)

    plt.title("Correlation Scores by Exploitation Status")
    plt.xlabel("Exploitation Group")
    plt.ylabel("Correlation Score")
    plt.grid(axis="y", alpha=0.3)

    save_figure("correlation_by_exploitation.png")


def create_benchmark_metrics(benchmark_data):
    metrics = [
        "accuracy",
        "precision",
        "recall",
        "f1"
    ]

    values = [
        benchmark_data.get(metric, 0)
        for metric in metrics
    ]

    labels = [
        "Accuracy",
        "Precision",
        "Recall",
        "F1 Score"
    ]

    plt.figure(figsize=(8, 5))
    plt.bar(labels, values, edgecolor="black")

    plt.title("Correlation Model Benchmark Performance")
    plt.xlabel("Evaluation Metric")
    plt.ylabel("Score")
    plt.ylim(0, 1.05)
    plt.grid(axis="y", alpha=0.3)

    save_figure("benchmark_performance.png")


def main():
    print("[+] Starting research visualization generation")

    final_data = load_json(FINAL_CTI_FILE)
    correlation_data = load_json(CORRELATION_FILE)
    benchmark_data = load_json(BENCHMARK_FILE)
    threshold_data = load_json(THRESHOLD_FILE)
    ablation_data = load_json(ABLATION_FILE)

    create_correlation_score_distribution(
        correlation_data
    )

    create_correlation_levels(
        correlation_data
    )

    create_exploitation_distribution(
        final_data
    )

    create_threshold_performance(
        threshold_data
    )

    create_ablation_results(
        ablation_data
    )

    create_correlation_vs_exploitation(
        correlation_data,
        final_data
    )

    create_benchmark_metrics(
        benchmark_data
    )

    print("[+] Research visualization generation complete")
    print(f"[+] Figures saved in: {REPORT_DIR}")


if __name__ == "__main__":
    main()
