import subprocess
import sys
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent.parent


STEPS = [
    ("Collect CISA advisories", "src/collector.py"),
    ("Collect full CISA advisory data", "src/advisory_collector.py"),
    ("Extract CVEs", "src/extract_cves.py"),
    ("Build CTI records", "src/build_cti_records.py"),
    ("Normalize CTI data", "src/normalize_cti.py"),
    ("Enrich CTI with NVD", "src/nvd_enricher.py"),
    ("Analyze vulnerability risk", "src/risk_analyzer.py"),
    ("Build provenance records", "src/build_provenance.py"),
    ("Calculate confidence", "src/confidence_model.py"),
    ("Collect CISA KEV data", "src/kev_collector.py"),
    ("Match KEV vulnerabilities", "src/match_kev.py"),
    ("Build final CTI dataset", "src/build_final_cti.py"),
    ("Validate final CTI dataset", "src/validate_cti.py"),
    ("Evaluate CTI dataset", "src/evaluate_cti.py"),
    ("Save CTI historical snapshot", "src/save_snapshot.py"),
    ("Analyze historical CTI trends", "src/trend_analysis.py"),
    ("Run threat correlation", "src/threat_correlation.py"),
    ("Evaluate threat correlation", "src/evaluate_correlation.py"),
    ("Run improved correlation", "src/improved_correlation.py"),
    ("Build benchmark ground truth", "src/build_ground_truth.py"),
    ("Evaluate correlation benchmark", "src/evaluate_benchmark.py"),
    ("Analyze correlation thresholds", "src/threshold_analysis.py"),
    ("Run train-validation experiment", "src/train_validation_experiment.py"),
    ("Run ablation study", "src/ablation_study.py"),
    ("Run statistical analysis", "src/statistical_analysis.py"),
    ("Generate research visualizations", "src/research_visualizations.py"),
    ("Generate automated CTI report", "src/generate_report.py"),
]


def run_step(description, script):
    print()
    print("=" * 70)
    print(f"[+] {description}")
    print(f"[+] Running: {script}")
    print("=" * 70)

    result = subprocess.run(
        [sys.executable, script],
        cwd=BASE_DIR
    )

    if result.returncode != 0:
        print()
        print(f"[!] FAILED: {description}")
        print(f"[!] Exit code: {result.returncode}")
        return False

    print(f"[+] Completed: {description}")
    return True


def main():
    start_time = datetime.now()

    print("=" * 70)
    print("OSINT CTI REPRODUCIBILITY EXPERIMENT")
    print("=" * 70)
    print(f"[+] Started: {start_time.isoformat(timespec='seconds')}")
    print(f"[+] Project: {BASE_DIR}")
    print(f"[+] Python: {sys.executable}")

    completed = []

    for description, script in STEPS:
        success = run_step(description, script)

        if not success:
            print()
            print("=" * 70)
            print("[!] REPRODUCTION FAILED")
            print("=" * 70)
            return 1

        completed.append(description)

    end_time = datetime.now()
    duration = end_time - start_time

    print()
    print("=" * 70)
    print("REPRODUCIBILITY EXPERIMENT COMPLETE")
    print("=" * 70)
    print(f"[+] Started:  {start_time.isoformat(timespec='seconds')}")
    print(f"[+] Finished: {end_time.isoformat(timespec='seconds')}")
    print(f"[+] Duration: {duration}")
    print(f"[+] Completed steps: {len(completed)}")
    print()
    print("[+] Research outputs:")
    print("    data/processed/")
    print("    data/history/")
    print("    reports/")
    print("    reports/figures/")
    print()
    print("[+] The experiment can now be reproduced using this script.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
