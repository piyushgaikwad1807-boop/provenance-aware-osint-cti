import subprocess
import sys
from pathlib import Path


# ======================================================
# PROJECT CONFIGURATION
# ======================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent


PYTHON = sys.executable


# ======================================================
# PIPELINE STEPS
# ======================================================

PIPELINE_STEPS = [

    (
        "Collect CISA advisory listings",
        "src/collector.py"
    ),

    (
        "Collect full CISA advisories",
        "src/advisory_collector.py"
    ),

    (
        "Extract CVE identifiers",
        "src/extract_cves.py"
    ),

    (
        "Build CTI records",
        "src/build_cti_records.py"
    ),

    (
        "Normalize CTI records",
        "src/normalize_cti.py"
    ),

    (
        "Check duplicate CVEs",
        "src/check_duplicates.py"
    ),

    (
        "Enrich CTI with NVD",
        "src/nvd_enricher.py"
    ),

    (
        "Analyze vulnerability risk",
        "src/risk_analyzer.py"
    ),

    (
        "Build provenance records",
        "src/build_provenance.py"
    ),

    (
        "Generate confidence scores",
        "src/confidence_model.py"
    ),

    (
        "Collect CISA KEV data",
        "src/kev_collector.py"
    ),

    (
        "Match CTI records with KEV",
        "src/match_kev.py"
    ),

    (
        "Build final CTI dataset",
        "src/build_final_cti.py"
    ),

    (
        "Validate final CTI dataset",
        "src/validate_cti.py"
    ),
    
    (
        "Build final CTI dataset",
        "src/build_final_cti.py"
    ),

    (
        "Validate final CTI dataset", 
        "src/validate_cti.py"
    ),

    (
        "Evaluate CTI dataset", 
        "src/evaluate_cti.py"
    ),

    (   "Validate final CTI dataset",
        "src/validate_cti.py"
    ),

    (   "Evaluate CTI dataset",
        "src/evaluate_cti.py"
    ),

    (   "Save CTI historical snapshot",
        "src/save_snapshot.py"
    ),
]


# ======================================================
# RUN SINGLE STEP
# ======================================================

def run_step(
    step_number,
    description,
    script
):

    print()
    print(
        "=================================================="
    )

    print(
        f"STEP {step_number}: {description}"
    )

    print(
        "=================================================="
    )

    print(
        f"[+] Running: {script}"
    )

    print()


    script_path = PROJECT_ROOT / script


    if not script_path.exists():

        print(
            f"[!] Script not found: {script_path}"
        )

        return False


    result = subprocess.run(
        [
            PYTHON,
            str(script_path)
        ],
        cwd=PROJECT_ROOT
    )


    if result.returncode != 0:

        print()

        print(
            f"[!] STEP {step_number} FAILED"
        )

        print(
            f"[!] Script: {script}"
        )

        return False


    print()

    print(
        f"[+] STEP {step_number} completed successfully"
    )

    return True


# ======================================================
# MAIN PIPELINE
# ======================================================

def main():

    print()
    print(
        "=================================================="
    )

    print(
        "OSINT CYBER THREAT INTELLIGENCE PIPELINE"
    )

    print(
        "=================================================="
    )

    print(
        "[+] Project root:"
    )

    print(
        f"    {PROJECT_ROOT}"
    )

    print()

    print(
        f"[+] Pipeline steps: "
        f"{len(PIPELINE_STEPS)}"
    )


    # --------------------------------------------------
    # Run all steps
    # --------------------------------------------------

    completed_steps = 0


    for index, (
        description,
        script
    ) in enumerate(
        PIPELINE_STEPS,
        start=1
    ):

        success = run_step(
            index,
            description,
            script
        )


        if not success:

            print()
            print(
                "=================================================="
            )

            print(
                "PIPELINE STOPPED"
            )

            print(
                "=================================================="
            )

            print(
                f"[!] Failed at step {index}: "
                f"{description}"
            )

            print(
                f"[!] Script: {script}"
            )

            print()

            sys.exit(1)


        completed_steps += 1


    # --------------------------------------------------
    # Final status
    # --------------------------------------------------

    print()
    print(
        "=================================================="
    )

    print(
        "PIPELINE COMPLETED SUCCESSFULLY"
    )

    print(
        "=================================================="
    )

    print(
        f"[+] Completed steps: "
        f"{completed_steps}/{len(PIPELINE_STEPS)}"
    )

    print()

    print(
        "[+] Final dataset:"
    )

    print(
        "    data/processed/final_cti.json"
    )

    print()

    print(
        "[+] Validation report:"
    )

    print(
        "    data/processed/validation_report.json"
    )

    print()

    print(
        "[+] Dashboard command:"
    )

    print(
        "    streamlit run src/dashboard.py"
    )

    print()


# ======================================================
# ENTRY POINT
# ======================================================

if __name__ == "__main__":

    main()
