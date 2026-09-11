import json
from pathlib import Path
from datetime import datetime, timezone


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = PROJECT_ROOT / "data/processed/final_cti.json"
OUTPUT_FILE = PROJECT_ROOT / "data/processed/improved_correlation_cti.json"


def load_json(path):
    if not path.exists():
        return None

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def calculate_signals(record):
    cisa = record.get("cisa") or {}
    nvd = record.get("nvd") or {}
    kev = record.get("kev") or {}
    provenance = record.get("provenance") or {}
    confidence = record.get("confidence") or {}
    risk = record.get("risk") or {}

    signals = {}

    # ---------------------------------------------------------
    # Signal 1: CISA evidence
    # ---------------------------------------------------------

    signals["cisa_evidence"] = {
        "present": bool(cisa.get("advisory_url")),
        "weight": 20 if cisa.get("advisory_url") else 0
    }

    # ---------------------------------------------------------
    # Signal 2: NVD evidence
    # ---------------------------------------------------------

    signals["nvd_evidence"] = {
        "present": bool(nvd),
        "weight": 15 if nvd else 0
    }

    # ---------------------------------------------------------
    # Signal 3: KEV exploitation evidence
    # ---------------------------------------------------------

    exploitation_status = record.get(
        "exploitation_status",
        "UNKNOWN"
    )

    kev_present = exploitation_status == "KNOWN_EXPLOITED"

    signals["kev_exploitation"] = {
        "status": exploitation_status,
        "present": kev_present,
        "weight": 30 if kev_present else 0
    }

    # ---------------------------------------------------------
    # Signal 4: Source corroboration
    # ---------------------------------------------------------

    source_count = provenance.get("source_count", 0)

    if source_count >= 2:
        corroboration_weight = 20
    elif source_count == 1:
        corroboration_weight = 10
    else:
        corroboration_weight = 0

    signals["source_corroboration"] = {
        "source_count": source_count,
        "weight": corroboration_weight
    }

    # ---------------------------------------------------------
    # Signal 5: CVSS severity
    # ---------------------------------------------------------

    cvss_score = risk.get("cvss_score")

    if isinstance(cvss_score, (int, float)):

        if cvss_score >= 9.0:
            cvss_weight = 10
            cvss_category = "CRITICAL"

        elif cvss_score >= 7.0:
            cvss_weight = 8
            cvss_category = "HIGH"

        elif cvss_score >= 4.0:
            cvss_weight = 5
            cvss_category = "MEDIUM"

        else:
            cvss_weight = 2
            cvss_category = "LOW"

    else:
        cvss_weight = 0
        cvss_category = "UNKNOWN"

    signals["cvss_severity"] = {
        "score": cvss_score,
        "category": cvss_category,
        "weight": cvss_weight
    }

    # ---------------------------------------------------------
    # Signal 6: Evidence confidence
    # ---------------------------------------------------------

    confidence_score = confidence.get("score")

    if isinstance(confidence_score, (int, float)):

        if confidence_score >= 0.80:
            confidence_weight = 5
            confidence_category = "HIGH"

        elif confidence_score >= 0.60:
            confidence_weight = 4
            confidence_category = "MEDIUM"

        elif confidence_score >= 0.40:
            confidence_weight = 2
            confidence_category = "LOW"

        else:
            confidence_weight = 1
            confidence_category = "VERY_LOW"

    else:
        confidence_weight = 0
        confidence_category = "UNKNOWN"

    signals["evidence_confidence"] = {
        "score": confidence_score,
        "category": confidence_category,
        "weight": confidence_weight
    }

    return signals


def calculate_total_score(signals):
    total = 0

    for signal in signals.values():
        total += signal.get("weight", 0)

    return total


def classify_score(score):

    if score >= 80:
        return "VERY_HIGH"

    elif score >= 60:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    elif score >= 20:
        return "LOW"

    return "VERY_LOW"


def generate_explanation(signals):

    explanations = []

    if signals["cisa_evidence"]["present"]:
        explanations.append(
            "CISA advisory evidence is available."
        )

    if signals["nvd_evidence"]["present"]:
        explanations.append(
            "NVD vulnerability enrichment is available."
        )

    if signals["kev_exploitation"]["present"]:
        explanations.append(
            "The CVE is listed in the CISA KEV catalog."
        )

    source_count = signals["source_corroboration"]["source_count"]

    if source_count >= 2:
        explanations.append(
            "The record is supported by multiple CTI sources."
        )

    elif source_count == 1:
        explanations.append(
            "The record is supported by one CTI source."
        )

    else:
        explanations.append(
            "No source corroboration is available."
        )

    cvss_category = signals["cvss_severity"]["category"]

    if cvss_category != "UNKNOWN":
        explanations.append(
            f"CVSS severity is classified as {cvss_category}."
        )

    confidence_category = signals["evidence_confidence"]["category"]

    if confidence_category != "UNKNOWN":
        explanations.append(
            f"Evidence confidence is classified as "
            f"{confidence_category}."
        )

    return explanations


def build_record(record):

    cve_id = record.get("cve_id", "UNKNOWN")

    signals = calculate_signals(record)

    total_score = calculate_total_score(signals)

    correlation_level = classify_score(total_score)

    explanations = generate_explanation(signals)

    return {
        "cve_id": cve_id,

        "correlation": {
            "score": total_score,
            "maximum_score": 100,
            "level": correlation_level,
            "explanations": explanations
        },

        "signals": signals,

        "model": {
            "name": "Explainable Signal-Based CTI Correlation Model",
            "version": "2.0",
            "type": "Heuristic weighted scoring"
        },

        "generated_at": datetime.now(
            timezone.utc
        ).isoformat()
    }


def main():

    print("[+] Starting improved threat correlation")

    records = load_json(INPUT_FILE)

    if not records:
        print("[!] final_cti.json not found or empty")
        return

    results = []

    for record in records:
        results.append(build_record(record))

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=2)

    print("[+] Improved correlation complete")
    print(f"[+] Total records: {len(results)}")
    print(f"[+] Saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
