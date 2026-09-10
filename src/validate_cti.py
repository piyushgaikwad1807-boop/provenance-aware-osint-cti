import json
import re
from pathlib import Path


# ======================================================
# FILE PATHS
# ======================================================

DATA_FILE = Path(
    "data/processed/final_cti.json"
)

REPORT_FILE = Path(
    "data/processed/validation_report.json"
)


# ======================================================
# VALID VALUES
# ======================================================

VALID_KEV_STATUSES = {
    "KNOWN_EXPLOITED",
    "NOT_IN_KEV",
    "UNKNOWN"
}

VALID_CONFIDENCE_CATEGORIES = {
    "HIGH",
    "MEDIUM",
    "LOW",
    "VERY_LOW",
    "UNKNOWN"
}


# ======================================================
# CVE VALIDATION
# ======================================================

def is_valid_cve(cve_id):

    pattern = r"^CVE-\d{4}-\d{4,7}$"

    return bool(
        re.match(
            pattern,
            str(cve_id).strip().upper()
        )
    )


# ======================================================
# LOAD DATA
# ======================================================

def load_data():

    if not DATA_FILE.exists():

        print(
            "[!] final_cti.json not found"
        )

        return []

    with DATA_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ======================================================
# VALIDATE RECORD
# ======================================================

def validate_record(record, index):

    errors = []
    warnings = []


    # --------------------------------------------------
    # Required CVE ID
    # --------------------------------------------------

    cve_id = record.get(
        "cve_id"
    )

    if not cve_id:

        errors.append(
            "Missing CVE identifier"
        )

    elif not is_valid_cve(cve_id):

        errors.append(
            f"Invalid CVE format: {cve_id}"
        )


    # --------------------------------------------------
    # NVD validation
    # --------------------------------------------------

    nvd = record.get(
        "nvd"
    )

    if nvd is None:

        warnings.append(
            "NVD data unavailable"
        )

    elif not isinstance(nvd, dict):

        errors.append(
            "NVD field is not an object"
        )

    else:

        cvss_score = nvd.get(
            "cvss_score"
        )

        if cvss_score is not None:

            try:

                cvss_value = float(
                    cvss_score
                )

                if not (
                    0 <= cvss_value <= 10
                ):

                    errors.append(
                        f"Invalid CVSS score: "
                        f"{cvss_value}"
                    )

            except (
                TypeError,
                ValueError
            ):

                errors.append(
                    "CVSS score is not numeric"
                )

        else:

            warnings.append(
                "CVSS score unavailable"
            )


    # --------------------------------------------------
    # Provenance validation
    # --------------------------------------------------

    provenance = record.get(
        "provenance"
    )

    if not isinstance(
        provenance,
        dict
    ):

        errors.append(
            "Missing or invalid provenance"
        )

    else:

        source_count = provenance.get(
            "source_count"
        )

        if source_count is None:

            errors.append(
                "Provenance source_count missing"
            )

        elif not isinstance(
            source_count,
            int
        ):

            errors.append(
                "Provenance source_count "
                "is not an integer"
            )

        elif source_count < 0:

            errors.append(
                "Provenance source_count "
                "cannot be negative"
            )

        sources = provenance.get(
            "sources",
            []
        )

        if not isinstance(
            sources,
            list
        ):

            errors.append(
                "Provenance sources "
                "must be a list"
            )


    # --------------------------------------------------
    # Confidence validation
    # --------------------------------------------------

    confidence = record.get(
        "confidence"
    )

    if not isinstance(
        confidence,
        dict
    ):

        errors.append(
            "Missing or invalid confidence"
        )

    else:

        score = confidence.get(
            "score"
        )

        if score is None:

            errors.append(
                "Confidence score missing"
            )

        else:

            try:

                score_value = float(
                    score
                )

                if not (
                    0 <= score_value <= 1
                ):

                    errors.append(
                        "Confidence score must "
                        "be between 0 and 1"
                    )

            except (
                TypeError,
                ValueError
            ):

                errors.append(
                    "Confidence score "
                    "is not numeric"
                )


        category = confidence.get(
            "category",
            "UNKNOWN"
        )

        if category not in (
            VALID_CONFIDENCE_CATEGORIES
        ):

            errors.append(
                f"Invalid confidence category: "
                f"{category}"
            )


    # --------------------------------------------------
    # KEV / exploitation validation
    # --------------------------------------------------

    exploitation_status = record.get(
        "exploitation_status",
        "UNKNOWN"
    )

    if exploitation_status not in (
        VALID_KEV_STATUSES
    ):

        errors.append(
            f"Invalid exploitation status: "
            f"{exploitation_status}"
        )


    # --------------------------------------------------
    # Risk validation
    # --------------------------------------------------

    risk = record.get(
        "risk"
    )

    if not isinstance(
        risk,
        dict
    ):

        warnings.append(
            "Risk information unavailable"
        )


    # --------------------------------------------------
    # Pipeline validation
    # --------------------------------------------------

    pipeline = record.get(
        "pipeline"
    )

    if not isinstance(
        pipeline,
        dict
    ):

        warnings.append(
            "Pipeline metadata unavailable"
        )


    # ==================================================
    # RESULT
    # ==================================================

    status = (
        "PASS"
        if not errors
        else "FAIL"
    )


    return {
        "record_index": index,
        "cve_id": cve_id,
        "status": status,
        "errors": errors,
        "warnings": warnings
    }


# ======================================================
# MAIN VALIDATION
# ======================================================

def main():

    print(
        "[+] Starting CTI validation"
    )


    records = load_data()


    if not records:

        print(
            "[!] No records available"
        )

        return


    print(
        f"[+] Records loaded: "
        f"{len(records)}"
    )


    # --------------------------------------------------
    # Duplicate detection
    # --------------------------------------------------

    seen_cves = set()
    duplicate_cves = []


    for record in records:

        cve_id = record.get(
            "cve_id"
        )

        if cve_id in seen_cves:

            duplicate_cves.append(
                cve_id
            )

        else:

            seen_cves.add(
                cve_id
            )


    # --------------------------------------------------
    # Validate records
    # --------------------------------------------------

    validation_results = []


    for index, record in enumerate(
        records,
        start=1
    ):

        result = validate_record(
            record,
            index
        )

        validation_results.append(
            result
        )


    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    passed = sum(
        1
        for result in validation_results
        if result["status"] == "PASS"
    )


    failed = sum(
        1
        for result in validation_results
        if result["status"] == "FAIL"
    )


    warnings = sum(
        len(result["warnings"])
        for result in validation_results
    )


    validation_rate = (
        passed
        / len(records)
        * 100
        if records
        else 0
    )


    overall_status = (
        "PASS"
        if failed == 0
        and not duplicate_cves
        else "FAIL"
    )


    # --------------------------------------------------
    # Validation report
    # --------------------------------------------------

    report = {

        "validation_summary": {

            "overall_status":
                overall_status,

            "total_records":
                len(records),

            "passed_records":
                passed,

            "failed_records":
                failed,

            "validation_rate":
                round(
                    validation_rate,
                    2
                ),

            "duplicate_cves":
                sorted(
                    set(
                        duplicate_cves
                    )
                ),

            "warning_count":
                warnings
        },

        "checks": [

            "CVE format validation",

            "Duplicate CVE detection",

            "Required field validation",

            "NVD structure validation",

            "CVSS range validation",

            "Provenance validation",

            "Confidence score validation",

            "Confidence category validation",

            "KEV status validation",

            "Risk structure validation",

            "Pipeline metadata validation"
        ],

        "records":
            validation_results
    }


    # --------------------------------------------------
    # Save report
    # --------------------------------------------------

    with REPORT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=2
        )


    # ==================================================
    # TERMINAL OUTPUT
    # ==================================================

    print()
    print(
        "=============================="
    )

    print(
        "CTI VALIDATION SUMMARY"
    )

    print(
        "=============================="
    )

    print(
        f"Total records: "
        f"{len(records)}"
    )

    print(
        f"Passed: "
        f"{passed}"
    )

    print(
        f"Failed: "
        f"{failed}"
    )

    print(
        f"Validation rate: "
        f"{validation_rate:.2f}%"
    )

    print(
        f"Duplicate CVEs: "
        f"{len(set(duplicate_cves))}"
    )

    print(
        f"Warnings: "
        f"{warnings}"
    )

    print(
        f"Overall status: "
        f"{overall_status}"
    )

    print()

    print(
        f"[+] Validation report saved to:"
    )

    print(
        f"    {REPORT_FILE}"
    )


    # --------------------------------------------------
    # Show failures
    # --------------------------------------------------

    if failed > 0:

        print()
        print(
            "[!] Validation failures:"
        )

        for result in validation_results:

            if result["status"] == "FAIL":

                print()
                print(
                    f"CVE: "
                    f"{result['cve_id']}"
                )

                for error in result["errors"]:

                    print(
                        f"  - {error}"
                    )


    # --------------------------------------------------
    # Show duplicates
    # --------------------------------------------------

    if duplicate_cves:

        print()
        print(
            "[!] Duplicate CVEs detected:"
        )

        for cve in sorted(
            set(duplicate_cves)
        ):

            print(
                f"  - {cve}"
            )


if __name__ == "__main__":

    main()
