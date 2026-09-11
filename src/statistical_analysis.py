import json
import math
import statistics
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

CORRELATION_FILE = BASE_DIR / "data" / "processed" / "improved_correlation_cti.json"
FINAL_CTI_FILE = BASE_DIR / "data" / "processed" / "final_cti.json"
OUTPUT_FILE = BASE_DIR / "data" / "processed" / "statistical_analysis.json"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def percentile(values, percentile_value):
    """
    Calculate percentile using linear interpolation.
    """
    if not values:
        return None

    values = sorted(values)

    if len(values) == 1:
        return values[0]

    position = (len(values) - 1) * percentile_value
    lower = math.floor(position)
    upper = math.ceil(position)

    if lower == upper:
        return values[lower]

    weight = position - lower

    return values[lower] + (values[upper] - values[lower]) * weight


def descriptive_statistics(values):
    if not values:
        return {
            "count": 0,
            "mean": None,
            "median": None,
            "minimum": None,
            "maximum": None,
            "standard_deviation": None,
            "q1": None,
            "q3": None,
            "iqr": None
        }

    mean_value = statistics.mean(values)

    if len(values) > 1:
        std_value = statistics.stdev(values)
    else:
        std_value = 0.0

    q1 = percentile(values, 0.25)
    q3 = percentile(values, 0.75)

    return {
        "count": len(values),
        "mean": round(mean_value, 4),
        "median": round(statistics.median(values), 4),
        "minimum": round(min(values), 4),
        "maximum": round(max(values), 4),
        "standard_deviation": round(std_value, 4),
        "q1": round(q1, 4),
        "q3": round(q3, 4),
        "iqr": round(q3 - q1, 4)
    }


def cohens_d(group_a, group_b):
    """
    Calculate Cohen's d when both groups contain
    enough observations for pooled standard deviation.
    """

    if len(group_a) < 2 or len(group_b) < 2:
        return None

    mean_a = statistics.mean(group_a)
    mean_b = statistics.mean(group_b)

    variance_a = statistics.variance(group_a)
    variance_b = statistics.variance(group_b)

    pooled_variance = (
        ((len(group_a) - 1) * variance_a)
        + ((len(group_b) - 1) * variance_b)
    ) / (len(group_a) + len(group_b) - 2)

    if pooled_variance == 0:
        return 0.0

    pooled_std = math.sqrt(pooled_variance)

    return round((mean_a - mean_b) / pooled_std, 4)


def analyze_correlation_scores(correlation_data):
    scores = []

    for record in correlation_data:
        score = record.get("correlation_score")

        if isinstance(score, (int, float)):
            scores.append(float(score))

    return descriptive_statistics(scores)


def analyze_groups(correlation_data, final_data):
    final_lookup = {
        record.get("cve_id"): record
        for record in final_data
    }

    kev_scores = []
    non_kev_scores = []

    corroborated_scores = []
    non_corroborated_scores = []

    for record in correlation_data:
        cve_id = record.get("cve_id")
        score = record.get("correlation_score")

        if not isinstance(score, (int, float)):
            continue

        score = float(score)

        final_record = final_lookup.get(cve_id, {})

        exploitation_status = final_record.get(
            "exploitation_status",
            "UNKNOWN"
        )

        provenance = final_record.get("provenance", {})

        corroborated = provenance.get("corroborated", False)

        if exploitation_status == "KNOWN_EXPLOITED":
            kev_scores.append(score)

        elif exploitation_status == "NOT_IN_KEV":
            non_kev_scores.append(score)

        if corroborated is True:
            corroborated_scores.append(score)

        elif corroborated is False:
            non_corroborated_scores.append(score)

    kev_stats = descriptive_statistics(kev_scores)
    non_kev_stats = descriptive_statistics(non_kev_scores)

    corroborated_stats = descriptive_statistics(corroborated_scores)
    non_corroborated_stats = descriptive_statistics(
        non_corroborated_scores
    )

    return {
        "known_exploited": kev_stats,
        "not_in_kev": non_kev_stats,
        "known_exploited_vs_not_in_kev": {
            "cohens_d": cohens_d(
                kev_scores,
                non_kev_scores
            )
        },
        "corroborated": corroborated_stats,
        "not_corroborated": non_corroborated_stats,
        "corroborated_vs_not_corroborated": {
            "cohens_d": cohens_d(
                corroborated_scores,
                non_corroborated_scores
            )
        }
    }


def analyze_cvss(final_data):
    cvss_scores = []

    for record in final_data:
        nvd = record.get("nvd")

        if not isinstance(nvd, dict):
            continue

        cvss = nvd.get("cvss_score")

        if isinstance(cvss, (int, float)):
            cvss_scores.append(float(cvss))

    return descriptive_statistics(cvss_scores)


def analyze_confidence(final_data):
    confidence_scores = []

    for record in final_data:
        confidence = record.get("confidence", {})

        score = confidence.get("score")

        if isinstance(score, (int, float)):
            confidence_scores.append(float(score))

    return descriptive_statistics(confidence_scores)


def main():
    print("[+] Starting statistical analysis")

    correlation_data = load_json(CORRELATION_FILE)
    final_data = load_json(FINAL_CTI_FILE)

    correlation_stats = analyze_correlation_scores(
        correlation_data
    )

    group_stats = analyze_groups(
        correlation_data,
        final_data
    )

    cvss_stats = analyze_cvss(final_data)

    confidence_stats = analyze_confidence(final_data)

    results = {
        "analysis": "Exploratory statistical analysis",
        "dataset": {
            "correlation_records": len(correlation_data),
            "final_cti_records": len(final_data)
        },
        "correlation_score_statistics": correlation_stats,
        "group_comparisons": group_stats,
        "cvss_statistics": cvss_stats,
        "confidence_statistics": confidence_stats,
        "methodology": {
            "descriptive_statistics": [
                "mean",
                "median",
                "minimum",
                "maximum",
                "standard_deviation",
                "q1",
                "q3",
                "iqr"
            ],
            "effect_size": "Cohen's d",
            "purpose": "Exploratory analysis of score distributions"
        },
        "limitations": [
            "The dataset is small.",
            "CISA KEV membership is used as a proxy exploitation label.",
            "The correlation model uses heuristic weights.",
            "Statistical results should not be interpreted as proof of generalization.",
            "Cohen's d may be unstable for very small groups.",
            "The analysis is exploratory rather than confirmatory."
        ]
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("[+] Statistical analysis complete")
    print(f"[+] Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
