import json
import re
from pathlib import Path


DATA_FILE = Path("data/processed/final_cti.json")
VALIDATION_FILE = Path("data/processed/validation_report.json")
REPORT_FILE = Path("data/processed/evaluation_report.json")


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")

VALID_KEV_STATUSES = {
    "KNOWN_EXPLOITED",
    "NOT_IN_KEV",
    "UNKNOWN"
}


def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def is_valid_cve(cve_id):
    if not isinstance(cve_id, str):
        return False

    return bool(CVE_PATTERN.fullmatch(cve_id.strip().upper()))


def calculate_percentage(part, total):
    if total == 0:
        return 0.0

    return round((part / total) * 100, 2)


def main():

    print("[+] Starting CTI evaluation")

    if not DATA_FILE.exists():
        print(f"[!] Missing file: {DATA_FILE}")
        return

    data = load_json(DATA_FILE)

    if not isinstance(data, list):
        print("[!] Final CTI dataset is not a list")
        return

    total_records = len(data)

    unique_cves = set()

    valid_cve_count = 0
    nvd_available_count = 0
    cvss_available_count = 0
    provenance_available_count = 0
    corroborated_count = 0
    confidence_available_count = 0
    kev_known_exploited_count = 0
    kev_status_available_count = 0

    complete_records = 0

    for record in data:

        cve_id = record.get("cve_id")

        if isinstance(cve_id, str):
            normalized_cve = cve_id.strip().upper()
            unique_cves.add(normalized_cve)

            if is_valid_cve(normalized_cve):
                valid_cve_count += 1

        nvd = record.get("nvd")

        if isinstance(nvd, dict) and nvd:
            nvd_available_count += 1

            cvss_score = nvd.get("cvss_score")

            if isinstance(cvss_score, (int, float)):
                if 0 <= cvss_score <= 10:
                    cvss_available_count += 1

        provenance = record.get("provenance")

        if isinstance(provenance, dict):

            sources = provenance.get("sources", [])

            if isinstance(sources, list) and len(sources) > 0:
                provenance_available_count += 1

            if provenance.get("corroborated") is True:
                corroborated_count += 1

        confidence = record.get("confidence")

        if isinstance(confidence, dict):

            score = confidence.get("score")

            if isinstance(score, (int, float)):
                if 0 <= score <= 1:
                    confidence_available_count += 1

        exploitation_status = record.get("exploitation_status")

        if exploitation_status in VALID_KEV_STATUSES:
            kev_status_available_count += 1

        if exploitation_status == "KNOWN_EXPLOITED":
            kev_known_exploited_count += 1

        if (
            is_valid_cve(cve_id)
            and isinstance(nvd, dict)
            and nvd
            and isinstance(provenance, dict)
            and isinstance(confidence, dict)
            and exploitation_status in VALID_KEV_STATUSES
        ):
            complete_records += 1

    duplicate_count = total_records - len(unique_cves)

    validation_status = "NOT_AVAILABLE"

    validation_rate = None

    if VALIDATION_FILE.exists():

        validation_data = load_json(VALIDATION_FILE)

        summary = validation_data.get("validation_summary", {})

        validation_status = summary.get(
            "overall_status",
            "UNKNOWN"
        )

        validation_rate = summary.get(
            "validation_rate"
        )

    report = {
        "evaluation_summary": {
            "total_records": total_records,
            "unique_cves": len(unique_cves),
            "duplicate_records": duplicate_count,

            "valid_cves": valid_cve_count,
            "valid_cve_rate": calculate_percentage(
                valid_cve_count,
                total_records
            ),

            "nvd_available": nvd_available_count,
            "nvd_coverage_rate": calculate_percentage(
                nvd_available_count,
                total_records
            ),

            "cvss_available": cvss_available_count,
            "cvss_coverage_rate": calculate_percentage(
                cvss_available_count,
                total_records
            ),

            "provenance_available": provenance_available_count,
            "provenance_coverage_rate": calculate_percentage(
                provenance_available_count,
                total_records
            ),

            "corroborated_records": corroborated_count,
            "corroboration_rate": calculate_percentage(
                corroborated_count,
                total_records
            ),

            "confidence_available": confidence_available_count,
            "confidence_coverage_rate": calculate_percentage(
                confidence_available_count,
                total_records
            ),

            "known_exploited": kev_known_exploited_count,
            "kev_match_rate": calculate_percentage(
                kev_known_exploited_count,
                total_records
            ),

            "kev_status_available": kev_status_available_count,
            "kev_status_coverage_rate": calculate_percentage(
                kev_status_available_count,
                total_records
            ),

            "complete_records": complete_records,
            "data_completeness_rate": calculate_percentage(
                complete_records,
                total_records
            ),

            "validation_status": validation_status,
            "validation_rate": validation_rate
        }
    }

    REPORT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with open(
        REPORT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False
        )

    summary = report["evaluation_summary"]

    print()
    print("[+] Evaluation complete")
    print()
    print(f"Total records: {summary['total_records']}")
    print(f"Unique CVEs: {summary['unique_cves']}")
    print(f"Duplicate records: {summary['duplicate_records']}")
    print(f"Valid CVEs: {summary['valid_cves']}")
    print(f"NVD coverage: {summary['nvd_coverage_rate']}%")
    print(f"CVSS coverage: {summary['cvss_coverage_rate']}%")
    print(
        f"Provenance coverage: "
        f"{summary['provenance_coverage_rate']}%"
    )
    print(
        f"Corroboration rate: "
        f"{summary['corroboration_rate']}%"
    )
    print(
        f"Confidence coverage: "
        f"{summary['confidence_coverage_rate']}%"
    )
    print(
        f"Known exploited: "
        f"{summary['known_exploited']}"
    )
    print(
        f"KEV match rate: "
        f"{summary['kev_match_rate']}%"
    )
    print(
        f"Data completeness: "
        f"{summary['data_completeness_rate']}%"
    )
    print(
        f"Validation status: "
        f"{summary['validation_status']}"
    )

    if summary["validation_rate"] is not None:
        print(
            f"Validation rate: "
            f"{summary['validation_rate']}"
        )

    print()
    print(f"[+] Saved: {REPORT_FILE}")


if __name__ == "__main__":
    main()
