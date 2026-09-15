# Provenance-Aware OSINT CTI

A research prototype for collecting, enriching, and correlating **Cyber Threat Intelligence (CTI)** from public OSINT sources.

## Features

* CISA advisory collection
* CVE extraction and normalization
* NVD vulnerability enrichment
* CISA KEV exploitation evidence
* Provenance and confidence tracking
* Explainable threat correlation
* Benchmark and threshold evaluation
* Statistical analysis and research visualizations
* Streamlit dashboard
* Automated CTI report generation

## Pipeline

```text
CISA + NVD + KEV
       ↓
OSINT Collection
       ↓
CVE Extraction
       ↓
Evidence Enrichment
       ↓
Provenance + Confidence
       ↓
Threat Correlation
       ↓
Evaluation + Visualization
```

## Run

```bash
git clone https://github.com/piyushgaikwad1807-boop/provenance-aware-osint-cti.git
cd provenance-aware-osint-cti

python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the dashboard:

```bash
streamlit run src/dashboard.py
```

## Research

The project is developed as a **research prototype** for studying provenance-aware CTI correlation and explainable threat analysis.

See [`paper/`](paper/) for the IEEE-style research draft and [`reports/`](reports/) for generated research artifacts.

## Limitations

The correlation score is a heuristic, not a probability. CISA KEV membership is used as a proxy exploitation label, and absence from KEV does not prove absence of exploitation.

## License

For research and educational use.
