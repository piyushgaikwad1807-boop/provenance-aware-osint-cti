# Provenance-Aware OSINT Cyber Threat Intelligence and Automated Threat Correlation System

## Project Overview

This project is a mini Cyber Threat Intelligence (CTI) system that collects publicly available cybersecurity information, extracts vulnerability identifiers, enriches the collected information using multiple authoritative sources, tracks evidence provenance, calculates explainable confidence scores, identifies known exploited vulnerabilities, validates the final dataset, and presents the results through a dashboard.

The project focuses on combining **Open Source Intelligence (OSINT)** with automated data processing and evidence correlation.

The main objective is to create a reproducible and explainable CTI pipeline rather than simply displaying vulnerability information.

---

# Project Objectives

The main objectives of the project are:

* Collect cybersecurity information from public sources.
* Collect CISA cybersecurity advisory information.
* Extract CVE identifiers automatically.
* Convert raw information into structured CTI records.
* Normalize and validate CVE identifiers.
* Enrich vulnerability information using the NVD.
* Identify CVSS severity information.
* Track the provenance of collected evidence.
* Correlate information from multiple sources.
* Generate explainable confidence scores.
* Identify vulnerabilities listed in the CISA Known Exploited Vulnerabilities (KEV) catalog.
* Calculate vulnerability risk information.
* Build a unified CTI dataset.
* Automatically validate the final dataset.
* Provide a visual dashboard for analysis.
* Automate the complete processing workflow.

---

# Technologies Used

The project uses:

* Python
* Requests
* BeautifulSoup
* Regular Expressions
* JSON
* Pandas
* Streamlit
* CISA advisories
* CISA Known Exploited Vulnerabilities catalog
* NIST National Vulnerability Database (NVD)
* Linux / Kali Linux
* Git-friendly project structure

---

# Project Structure

```text
osint-cti/
│
├── data/
│   ├── processed/
│   │   ├── cti_records.json
│   │   ├── enriched_cti.json
│   │   ├── normalized_cti.json
│   │   ├── relevant_titles.json
│   │   ├── risk_analysis.json
│   │   ├── provenance_cti.json
│   │   ├── confidence_cti.json
│   │   ├── kev_cti.json
│   │   ├── final_cti.json
│   │   └── validation_report.json
│   │
│   └── raw/
│       ├── cisa_advisories.json
│       ├── cisa_advisories_full.json
│       └── cisa_kev.json
│
├── logs/
│
├── src/
│   ├── collector.py
│   ├── advisory_collector.py
│   ├── day2_basics.py
│   ├── process_titles.py
│   ├── cve_extractor.py
│   ├── extract_cves.py
│   ├── build_cti_records.py
│   ├── normalize_cti.py
│   ├── check_duplicates.py
│   ├── nvd_enricher.py
│   ├── risk_analyzer.py
│   ├── risk_summary.py
│   ├── build_provenance.py
│   ├── provenance_summary.py
│   ├── confidence_model.py
│   ├── confidence_summary.py
│   ├── kev_collector.py
│   ├── match_kev.py
│   ├── kev_summary.py
│   ├── risk_priority.py
│   ├── build_final_cti.py
│   ├── final_summary.py
│   ├── validate_cti.py
│   ├── run_pipeline.py
│   └── dashboard.py
│
├── tests/
│
├── README.md
└── .venv/
```

---

# Overall CTI Pipeline

The project gradually evolved into an automated CTI processing pipeline.

The overall architecture is:

```text
                 CISA Advisory Source
                         │
                         ▼
                Advisory Collection
                         │
                         ▼
                  CVE Extraction
                         │
                         ▼
                 CTI Record Creation
                         │
                         ▼
                  Data Normalization
                         │
                         ▼
                Duplicate Detection
                         │
                         ▼
              ┌──────────┴──────────┐
              │                     │
              ▼                     ▼
             NVD                   CISA KEV
          Enrichment              Matching
              │                     │
              └──────────┬──────────┘
                         ▼
                  Risk Analysis
                         │
                         ▼
                  Provenance Layer
                         │
                         ▼
                 Confidence Model
                         │
                         ▼
                Final CTI Dataset
                         │
                         ▼
                  Data Validation
                         │
                         ▼
                    Dashboard
```

---

# Day 1 - Initial OSINT Collection

## Objective

The first day focused on creating the basic project structure and collecting publicly available cybersecurity advisory information from CISA.

The initial collector accessed the CISA Cybersecurity Advisories page and extracted relevant headings.

## Initial Data

The collector successfully collected advisory-related headings and stored them as JSON.

Output file:

```text
data/raw/cisa_advisories.json
```

The collector produced 22 headings during the initial collection.

The raw data contains:

* Source URL
* Collection timestamp
* Collected headings

## Main Script

```text
src/collector.py
```

## Day 1 Result

The first stage established the basic OSINT collection layer of the project.

---

# Day 2 - Data Processing and CVE Extraction

## Objective

Day 2 introduced basic Python data processing.

The collected advisory headings were processed to identify vulnerability-related titles.

The project also introduced regular expressions for detecting CVE identifiers.

## Processing

The project filtered the collected titles and identified vulnerability-related advisory titles.

The processing stage identified:

```text
9 relevant vulnerability-related titles
```

The processed data was saved to:

```text
data/processed/relevant_titles.json
```

The CVE extraction stage initially returned:

```text
CVEs found: 0
```

This happened because the initial collector only collected headings rather than the full advisory content.

This observation led to the improvement implemented on Day 3.

## Main Scripts

```text
src/day2_basics.py
src/process_titles.py
src/cve_extractor.py
```

---

# Day 3 - Full Advisory Collection and CTI Record Creation

## Objective

Day 3 improved the collection process by discovering individual CISA advisory pages and retrieving their full content.

The processing flow became:

```text
CISA Advisory Listing
        ↓
Individual Advisory Links
        ↓
Advisory Page
        ↓
Full Advisory Content
        ↓
CVE Extraction
        ↓
Structured CTI Records
```

## Advisory Collection

The project discovered individual CISA advisory URLs and collected their page content.

Output:

```text
data/raw/cisa_advisories_full.json
```

Each advisory record contains:

* Advisory title
* Advisory URL
* Advisory content
* Collection timestamp

## CVE Extraction

Regular expressions were used to identify CVE identifiers.

The pattern used was:

```text
CVE-\d{4}-\d{4,7}
```

## CTI Records

The extracted CVEs were converted into structured CTI records.

Output:

```text
data/processed/cti_records.json
```

The records contain:

* CVE identifier
* Source
* Advisory title
* Advisory URL
* Evidence
* Confidence
* Collection timestamp

The collection produced:

```text
17 unique CVEs
```

---

# Day 4 - Data Normalization and Duplicate Detection

## Objective

Day 4 focused on improving the consistency and quality of CTI data.

The project introduced CVE normalization and duplicate detection.

## Normalization

The normalization process:

* Removes unnecessary whitespace.
* Converts CVE identifiers to uppercase.
* Validates CVE format.

Output:

```text
data/processed/normalized_cti.json
```

## Duplicate Detection

Duplicate CVE identifiers were checked automatically.

Main script:

```text
src/check_duplicates.py
```

This stage helps prevent duplicate vulnerability records from affecting later analysis.

---

# Day 5 - NVD Enrichment

## Objective

Day 5 introduced a second authoritative vulnerability information source: the National Vulnerability Database (NVD).

The purpose was to enrich the CISA-derived CTI records with additional vulnerability information.

## NVD API

The project uses the NVD CVE API.

The enrichment process attempts to retrieve:

* CVE description
* Published date
* Last modified date
* CVSS score
* CVSS severity
* CVSS vector
* References

## Main Script

```text
src/nvd_enricher.py
```

## Output

```text
data/processed/enriched_cti.json
```

## Rate Limiting

During initial testing, some NVD requests returned HTTP 429 responses.

HTTP 429 indicates that the request rate was limited.

The enrichment script was therefore improved to:

* Retry failed requests.
* Wait between requests.
* Use exponential backoff.
* Preserve failed records.
* Mark enrichment status.

This is important because the pipeline should not silently remove records when an external source is temporarily unavailable.

## Important Observation

NVD enrichment availability should not be interpreted as a measure of vulnerability severity.

NVD data availability and vulnerability severity are separate concepts.

---

# Day 6 - Risk Analysis

## Objective

Day 6 introduced automated vulnerability risk classification based on CVSS scores.

The project classified CVSS scores as:

```text
CVSS >= 9.0  → CRITICAL
CVSS >= 7.0  → HIGH
CVSS >= 4.0  → MEDIUM
CVSS < 4.0   → LOW
No CVSS      → UNKNOWN
```

## Main Script

```text
src/risk_analyzer.py
```

## Output

```text
data/processed/risk_analysis.json
```

## Important Distinction

CVSS severity is a technical severity measurement.

It should not automatically be treated as real-world risk.

Real-world prioritization can also depend on:

* Known exploitation
* Asset importance
* Exposure
* Threat intelligence
* Vulnerability age
* Availability of remediation
* Evidence quality

These additional factors are incorporated progressively in later stages of the project.

---

# Day 7 - Initial Dashboard

## Objective

Day 7 introduced a Streamlit dashboard for visualizing the CTI dataset.

The dashboard provides:

* Total CVE count
* Risk distribution
* CVE search
* Risk filtering
* CVE details
* CISA advisory information

## Main Script

```text
src/dashboard.py
```

## Start Dashboard

```bash
streamlit run src/dashboard.py
```

The dashboard is treated as the visualization layer of the system.

The main research contribution remains the collection, correlation, provenance, confidence, and validation pipeline.

---

# Day 8 - Provenance and Evidence Tracking

## Objective

Day 8 introduced provenance tracking.

The purpose of provenance is to answer:

> Where did this CTI information come from?

Each CTI record can now contain information about its supporting sources.

## Sources

The current system tracks:

```text
CISA
NVD
```

## Provenance Information

Each source record can contain:

* Source name
* Source type
* Source URL
* Evidence description

The system also calculates:

* Source count
* Corroboration status
* Confidence value

## Main Script

```text
src/build_provenance.py
```

## Output

```text
data/processed/provenance_cti.json
```

## Evidence Corroboration

If a CVE has evidence from both CISA and NVD, it is considered corroborated by the current project model.

```text
CISA
  +
NVD
  ↓
Corroborated Evidence
```

This creates the foundation for multi-source CTI correlation.

---

# Day 9 - Explainable Confidence Model

## Objective

Day 9 introduced an explainable confidence scoring model.

The score represents the strength of supporting evidence collected by this project.

It is a project-defined heuristic and is not a statistical probability.

## Confidence Components

The current model uses:

```text
Multiple source corroboration  +0.40
CISA evidence                  +0.25
NVD evidence                   +0.20
Evidence completeness          +0.10
Valid CVE identifier           +0.05
```

The maximum score is:

```text
1.00
```

## Confidence Categories

```text
>= 0.80  → HIGH
>= 0.60  → MEDIUM
>= 0.40  → LOW
<  0.40  → VERY_LOW
```

## Main Script

```text
src/confidence_model.py
```

## Output

```text
data/processed/confidence_cti.json
```

## Explainability

Each confidence score includes reasons explaining why the score was assigned.

This makes the scoring process more transparent than using an unexplained numerical score.

---

# Day 10 - CISA Known Exploited Vulnerabilities Integration

## Objective

Day 10 introduced the CISA Known Exploited Vulnerabilities (KEV) catalog.

The purpose is to identify vulnerabilities for which CISA has documented known exploitation.

## KEV Collection

The project retrieves the CISA KEV catalog and stores the raw information.

Output:

```text
data/raw/cisa_kev.json
```

## KEV Matching

Each project CVE is compared against the KEV catalog.

Possible states include:

```text
KNOWN_EXPLOITED
NOT_IN_KEV
UNKNOWN
```

## Main Scripts

```text
src/kev_collector.py
src/match_kev.py
src/kev_summary.py
```

## Important Interpretation

`KNOWN_EXPLOITED` indicates that the CVE was found in the CISA KEV catalog.

`NOT_IN_KEV` means that no matching record was found in the KEV catalog during collection.

It should **not** be interpreted as proof that the vulnerability has never been exploited.

---

# Day 11 - Unified CTI Dataset

## Objective

Day 11 combined the information generated by previous stages into a unified CTI record.

The unified record combines:

```text
CISA
NVD
KEV
Provenance
Confidence
Risk
Pipeline metadata
```

## Main Script

```text
src/build_final_cti.py
```

## Output

```text
data/processed/final_cti.json
```

## Example Logical Structure

```text
CVE
│
├── CISA information
│
├── NVD information
│
├── KEV information
│
├── Exploitation status
│
├── Provenance
│
├── Confidence
│
├── Risk
│
└── Pipeline metadata
```

This unified dataset becomes the primary input for the final dashboard and validation system.

---

# Day 12 - Advanced CTI Dashboard

## Objective

Day 12 upgraded the dashboard to use the unified CTI dataset.

The dashboard now reads:

```text
data/processed/final_cti.json
```

## Dashboard Features

The dashboard includes:

* Total CVEs
* NVD coverage
* Known exploited count
* Corroborated records
* Average confidence
* Evidence coverage
* CTI record table
* CVE search
* Severity filter
* Exploitation filter
* CVE details
* CISA advisory information
* KEV information
* Provenance information
* Confidence reasons
* NVD references

## Dashboard Role

The dashboard provides a human-readable interface for examining the CTI data generated by the automated pipeline.

---

# Day 13 - Automated Data Validation

## Objective

Day 13 introduced automated validation of the final CTI dataset.

The objective is to detect structural and data-quality problems before the data is used by the dashboard or research analysis.

## Validation Checks

The validator checks:

* CVE identifier presence
* CVE identifier format
* NVD structure
* CVSS availability
* CVSS range
* Provenance structure
* Source count
* Confidence score
* Confidence category
* Exploitation status
* Risk structure
* Pipeline metadata
* Duplicate CVEs

## Main Script

```text
src/validate_cti.py
```

## Output

```text
data/processed/validation_report.json
```

## Validation Status

The validator produces an overall status:

```text
PASS
```

or

```text
FAIL
```

It also reports:

* Passed records
* Failed records
* Warnings
* Validation rate
* Duplicate CVEs

## Importance

Automated validation improves the reliability and reproducibility of the CTI pipeline.

Instead of manually checking JSON files, the project can automatically verify the structure of the final dataset.

---

# Day 14 - Automated End-to-End Pipeline

## Objective

Day 14 focuses on automation and reproducibility.

Before Day 14, the individual project stages had to be executed separately.

For example:

```bash
python src/collector.py
python src/advisory_collector.py
python src/extract_cves.py
python src/build_cti_records.py
...
```

This is inconvenient and increases the possibility of accidentally skipping a stage.

Day 14 introduces a single pipeline runner.

## Main Script

```text
src/run_pipeline.py
```

The pipeline runner executes the project stages automatically in sequence.

---

# Day 14 Pipeline Sequence

The automated pipeline executes the following stages:

```text
1. Collect CISA advisory listings
2. Collect full CISA advisories
3. Extract CVE identifiers
4. Build CTI records
5. Normalize CTI records
6. Check duplicate CVEs
7. Enrich CTI with NVD
8. Analyze vulnerability risk
9. Build provenance records
10. Generate confidence scores
11. Collect CISA KEV data
12. Match CTI records with KEV
13. Build final CTI dataset
14. Validate final CTI dataset
```

The pipeline stops if a critical processing stage fails.

This prevents later stages from operating on incomplete data.

---

# Day 14 Automation Architecture

```text
                 START
                   │
                   ▼
          CISA Advisory Collection
                   │
                   ▼
           Full Advisory Collection
                   │
                   ▼
              CVE Extraction
                   │
                   ▼
            CTI Record Creation
                   │
                   ▼
             Normalization
                   │
                   ▼
          Duplicate Detection
                   │
                   ▼
             NVD Enrichment
                   │
                   ▼
             Risk Analysis
                   │
                   ▼
             Provenance
                   │
                   ▼
          Confidence Scoring
                   │
                   ▼
             CISA KEV
                   │
                   ▼
             KEV Matching
                   │
                   ▼
          Final CTI Dataset
                   │
                   ▼
              Validation
                   │
                   ▼
                  END
```

---

# Running the Complete Pipeline

Activate the virtual environment:

```bash
cd ~/osint-cti
source .venv/bin/activate
```

Run the complete pipeline:

```bash
python src/run_pipeline.py
```

The script automatically executes the processing stages.

There is no need to manually execute every processing script one by one.

---

# Final Output Files

After the pipeline completes, the main outputs are:

```text
data/processed/final_cti.json
```

and

```text
data/processed/validation_report.json
```

The first contains the unified CTI dataset.

The second contains the automated validation results.

---

# Verify Final CTI Dataset

The final JSON can be checked using:

```bash
python -m json.tool data/processed/final_cti.json > /dev/null
```

The number of final records can be checked using:

```bash
python -c "import json; d=json.load(open('data/processed/final_cti.json')); print('Final records:', len(d)); print('Unique CVEs:', len(set(x['cve_id'] for x in d)))"
```

---

# Verify Validation Report

Check the JSON structure:

```bash
python -m json.tool data/processed/validation_report.json > /dev/null
```

Display validation results:

```bash
python -c "import json; d=json.load(open('data/processed/validation_report.json')); s=d['validation_summary']; print('Status:', s['overall_status']); print('Passed:', s['passed_records']); print('Failed:', s['failed_records']); print('Validation rate:', s['validation_rate'])"
```

---

# Running the Dashboard

After the pipeline completes, start the dashboard:

```bash
streamlit run src/dashboard.py
```

The dashboard uses:

```text
data/processed/final_cti.json
```

as its primary dataset.

---

# Day 14 Reproducibility

The major improvement introduced on Day 14 is reproducibility.

A user can now execute:

```bash
python src/run_pipeline.py
```

instead of manually running every processing stage.

This makes the project easier to:

* Re-run
* Test
* Demonstrate
* Debug
* Extend
* Reproduce
* Use for future research experiments

---

# Error Handling

The pipeline runner uses the same Python interpreter that is executing the pipeline.

This is implemented using:

```python
sys.executable
```

This helps ensure that the scripts use the active Python virtual environment.

The pipeline also checks the return code of each script.

If a stage fails, the pipeline reports the failed stage and stops.

This prevents the system from continuing as if the failed stage had succeeded.

---

# Data Flow

The complete data flow can be summarized as:

```text
RAW DATA
   │
   ▼
CISA Advisories
   │
   ▼
CVE Extraction
   │
   ▼
STRUCTURED DATA
   │
   ▼
Normalization
   │
   ▼
NVD Enrichment
   │
   ▼
KEV Matching
   │
   ▼
Evidence Provenance
   │
   ▼
Confidence Scoring
   │
   ▼
Risk Analysis
   │
   ▼
FINAL CTI DATASET
   │
   ▼
Validation
   │
   ▼
Dashboard
```

---

# CTI Record Model

The final CTI record is designed around several separate evidence dimensions.

```text
CVE
│
├── Technical Severity
│      └── CVSS / NVD
│
├── Exploitation Evidence
│      └── CISA KEV
│
├── Evidence Provenance
│      └── CISA + NVD
│
├── Confidence
│      └── Project-defined evidence score
│
└── Risk
       └── Risk classification
```

Keeping these dimensions separate is important.

For example:

```text
CVSS severity ≠ exploitation status ≠ confidence
```

A vulnerability may have a high CVSS score but not be present in the KEV catalog.

Similarly, a record may have strong evidence provenance without necessarily having a critical CVSS score.

---

# Research Significance

The project is not intended to be only a vulnerability dashboard.

The main research-oriented concept is the automated correlation of CTI evidence from multiple public sources.

The system attempts to answer:

```text
What vulnerability was identified?
        ↓
Where was it identified?
        ↓
What evidence supports it?
        ↓
Is the information corroborated?
        ↓
Is exploitation known?
        ↓
How severe is the vulnerability?
        ↓
How confident is the collected evidence?
```

This provides a foundation for a future research paper on provenance-aware and explainable CTI correlation.

---

# Important Limitations

The current system has several limitations.

## 1. Confidence Score

The confidence score is a project-defined heuristic.

It is not a statistical probability.

Future versions may use:

* Historical validation
* Source reliability weights
* Temporal decay
* More independent sources
* Machine learning
* Probabilistic models

---

## 2. KEV Interpretation

`KNOWN_EXPLOITED` indicates that the CVE appears in the CISA KEV catalog.

`NOT_IN_KEV` does not prove that exploitation does not exist.

The KEV catalog should therefore be treated as an exploitation evidence source rather than a complete global exploitation database.

---

## 3. NVD Availability

NVD enrichment may fail because of:

* API rate limiting
* Network problems
* Temporary service issues
* Missing enrichment data

The system preserves failed enrichment states rather than silently deleting records.

---

## 4. Risk Model

The current risk analysis primarily uses CVSS severity.

The project also contains a prototype risk-priority concept.

Future work should develop and evaluate a more rigorous prioritization model using:

```text
CVSS
+
KEV exploitation
+
Confidence
+
Asset context
+
Threat intelligence
+
Temporal information
```

---

# Day 14 Research Contribution

Day 14 adds an important engineering and research property:

## Reproducibility

The complete CTI processing workflow can now be executed automatically through:

```bash
python src/run_pipeline.py
```

This converts the project from a collection of independent scripts into a more complete processing pipeline.

The pipeline can be repeated whenever new source data is collected.

This is important for future experimentation and research because the same processing workflow can be applied to new datasets.

---

# Current Project Status

At the end of Day 14, the project contains:

```text
OSINT Collection
        ↓
Advisory Collection
        ↓
CVE Extraction
        ↓
CTI Structuring
        ↓
Normalization
        ↓
Duplicate Detection
        ↓
NVD Enrichment
        ↓
Risk Analysis
        ↓
Provenance Tracking
        ↓
Confidence Scoring
        ↓
KEV Integration
        ↓
Final CTI Dataset
        ↓
Automated Validation
        ↓
Dashboard
```

The project has progressed from basic OSINT collection to an automated provenance-aware CTI processing architecture.

---

# Day 14 Learning Outcomes

After completing Day 14, the following concepts were introduced:

* Python subprocess execution
* Automated workflow execution
* Pipeline design
* Sequential processing
* Error handling
* Exit codes
* Reproducible processing
* Data pipeline architecture
* CTI automation
* Dataset validation
* Research reproducibility

---

# Future Work

Future development can focus on:

* Additional OSINT sources
* Exploit database integration
* Vendor security advisories
* GitHub security information
* Threat intelligence feeds
* Temporal evidence tracking
* Source reliability scoring
* Improved risk prioritization
* Automated alerts
* Historical CTI datasets
* Unit tests
* Integration tests
* Performance measurement
* Correlation accuracy evaluation
* False-positive analysis
* Research methodology
* Experimental evaluation
* IEEE-style research paper preparation

---

# Project Execution

The complete workflow is now:

```bash
cd ~/osint-cti
source .venv/bin/activate
python src/run_pipeline.py
streamlit run src/dashboard.py
```

The first command activates the project environment.

The second command executes the complete CTI pipeline.

The third command starts the visualization dashboard.

---

# Conclusion

This project started as a basic OSINT collection system and has progressively developed into a provenance-aware Cyber Threat Intelligence processing pipeline.

The current architecture combines:

```text
OSINT
+
CVE Extraction
+
NVD Enrichment
+
CISA KEV
+
Provenance
+
Confidence
+
Risk Analysis
+
Validation
+
Automation
+
Visualization
```

Day 14 completes the initial automation layer by providing a single entry point for executing the major CTI processing stages.

The project is now ready for the next phase: improving testing, evaluation, correlation methodology, and research documentation.

# Day 15 - CTI Evaluation and Research Metrics

## Objective

Day 15 introduces an evaluation layer for the automated CTI pipeline.

The objective is to measure the quality, completeness, coverage, and corroboration of the generated CTI dataset.

The evaluation layer helps transform the project from a data-processing prototype into a system that can be quantitatively evaluated.

---

## Evaluation Pipeline

The Day 15 workflow is:

```text
Final CTI Dataset
        ↓
Validation
        ↓
Evaluation
        ↓
Research Metrics
```

The evaluation process reads:

```text
data/processed/final_cti.json
```

and, when available:

```text
data/processed/validation_report.json
```

---

## Evaluation Script

The main Day 15 script is:

```text
src/evaluate_cti.py
```

It generates:

```text
data/processed/evaluation_report.json
```

---

## Evaluation Metrics

The system calculates several metrics.

### 1. Total Records

The total number of CTI records contained in the final dataset.

---

### 2. Unique CVEs

The number of unique CVE identifiers.

This helps identify whether duplicate records are present.

---

### 3. Valid CVE Rate

The percentage of records containing a valid CVE identifier.

The validation pattern used by the project is:

```text
CVE-\d{4}-\d{4,7}
```

---

### 4. NVD Coverage

NVD coverage measures the percentage of CTI records for which NVD information is available.

```text
NVD Coverage =
NVD Available Records / Total Records × 100
```

---

### 5. CVSS Coverage

CVSS coverage measures the percentage of records containing a valid CVSS score.

The project expects CVSS values within the range:

```text
0.0 - 10.0
```

---

### 6. Provenance Coverage

Provenance coverage measures how many CTI records contain source provenance information.

The provenance layer records supporting information from sources such as:

```text
CISA
NVD
```

---

### 7. Corroboration Rate

Corroboration measures the proportion of records supported by multiple sources according to the current project model.

The current model considers a record corroborated when multiple supporting sources are present.

```text
Corroboration Rate =
Corroborated Records / Total Records × 100
```

---

### 8. Confidence Coverage

Confidence coverage measures how many records contain a valid project-defined confidence score.

Confidence is an evidence-strength heuristic and should not be interpreted as a statistical probability.

---

### 9. KEV Match Rate

KEV match rate measures the proportion of project CVEs found in the CISA Known Exploited Vulnerabilities catalog.

```text
KEV Match Rate =
Known Exploited Records / Total Records × 100
```

A KEV match indicates that the CVE was found in the CISA KEV catalog.

A CVE not found in KEV should not be interpreted as proof that the vulnerability has never been exploited.

---

### 10. Data Completeness Rate

Data completeness measures the percentage of records containing the major fields required by the current project model.

The current completeness check considers:

* Valid CVE
* NVD information
* Provenance
* Confidence
* Valid exploitation status

```text
Data Completeness =
Complete Records / Total Records × 100
```

---

## Evaluation Output

The evaluation results are stored in:

```text
data/processed/evaluation_report.json
```

The report contains:

* Total records
* Unique CVEs
* Duplicate records
* Valid CVEs
* NVD coverage
* CVSS coverage
* Provenance coverage
* Corroboration rate
* Confidence coverage
* Known exploited vulnerabilities
* KEV match rate
* Data completeness
* Validation status
* Validation rate

---

## Day 15 Automation

The evaluation stage was added to the automated pipeline.

The complete processing sequence is now:

```text
1. Collect CISA advisory listings
2. Collect full CISA advisories
3. Extract CVE identifiers
4. Build CTI records
5. Normalize CTI records
6. Check duplicate CVEs
7. Enrich CTI with NVD
8. Analyze vulnerability risk
9. Build provenance records
10. Generate confidence scores
11. Collect CISA KEV data
12. Match CTI records with KEV
13. Build final CTI dataset
14. Validate final CTI dataset
15. Evaluate CTI dataset
```

The complete workflow can be executed with:

```bash
python src/run_pipeline.py
```

---

## Research Importance

The evaluation layer is important for future research because a CTI system should not only collect and process information.

It should also provide measurable evidence about the quality of its output.

The evaluation metrics provide a foundation for the future research evaluation section.

For example:

```text
Dataset Size
NVD Coverage
KEV Coverage
Corroboration Rate
Confidence Coverage
Data Completeness
Validation Rate
```

These measurements can later be compared across different collection periods, source combinations, or system versions.

---

## Reproducibility

The evaluation results can be regenerated whenever the pipeline is executed.

This provides a reproducible workflow:

```text
Source Data
    ↓
Automated Processing
    ↓
Final CTI Dataset
    ↓
Validation
    ↓
Evaluation Metrics
```

This is useful for future experiments and research documentation.

---

## Current Research Direction

The project is progressing toward an evaluation-based CTI research system.

The current architecture separates:

```text
Severity
    ↓
CVSS / NVD

Exploitation
    ↓
CISA KEV

Evidence
    ↓
CISA + NVD

Confidence
    ↓
Project-defined evidence model

Validation
    ↓
Data quality checks

Evaluation
    ↓
Quantitative research metrics
```

Keeping these concepts separate makes the system easier to analyze and explain.

---

## Day 15 Learning Outcomes

Day 15 introduced:

* CTI evaluation
* Research metrics
* Dataset coverage
* Data completeness
* Corroboration measurement
* Validation measurement
* Reproducibility metrics
* Automated evaluation
* Quantitative system analysis

The project can now generate not only CTI intelligence but also measurements describing the quality and coverage of the generated dataset.

---

## Day 15 Conclusion

Day 15 adds an evaluation layer to the automated CTI system.

The system now performs:

```text
Collection
    ↓
Extraction
    ↓
Normalization
    ↓
Enrichment
    ↓
Correlation
    ↓
Provenance
    ↓
Confidence
    ↓
Exploitation Analysis
    ↓
Risk Analysis
    ↓
Validation
    ↓
Evaluation
    ↓
Visualization
```

This provides a stronger foundation for future experimental evaluation and preparation of an IEEE-style research paper.

# Day 16 - Historical CTI Snapshots and Time-Based Analysis

## Objective

Day 16 introduces historical CTI data preservation.

Previously, each pipeline execution generated a new final CTI dataset that could replace the previous state.

The Day 16 implementation preserves each successful pipeline result as a timestamped historical snapshot.

This allows the project to analyze how CTI information changes across different collection periods.

---

## Historical Data Architecture

The Day 16 workflow is:

```text
Automated CTI Pipeline
        ↓
Final CTI Dataset
        ↓
Evaluation
        ↓
Historical Snapshot
        ↓
data/history/
        ↓
Historical Analysis
```

---

## Historical Snapshot Script

The snapshot generator is:

```text
src/save_snapshot.py
```

It reads:

```text
data/processed/final_cti.json
```

and:

```text
data/processed/evaluation_report.json
```

The generated snapshot is stored in:

```text
data/history/
```

---

## Snapshot Naming

Snapshots use a timestamp-based filename.

Example:

```text
cti_snapshot_20260910_194500.json
```

The timestamp provides a unique identifier for each collection run.

---

## Snapshot Contents

Each snapshot contains:

* Snapshot ID
* Creation timestamp
* Total record count
* Complete CTI records
* Evaluation metrics

Logical structure:

```text
Snapshot
│
├── snapshot_id
├── created_at
│
├── dataset
│   ├── total_records
│   └── records
│
└── evaluation
    ├── coverage metrics
    ├── corroboration metrics
    ├── completeness metrics
    └── validation information
```

---

## Historical Analysis

The historical analysis script is:

```text
src/historical_analysis.py
```

It loads all available historical snapshots and calculates summary metrics for each snapshot.

The current analysis reports:

* Total CVEs
* Known exploited vulnerabilities
* Corroborated records
* NVD availability
* Average confidence

---

## Historical Metrics

The system can now compare metrics across collection runs.

Example:

```text
Snapshot A
Total CVEs: 17
Known exploited: X
Corroborated: X
NVD available: X
Average confidence: X.XXX

Snapshot B
Total CVEs: 20
Known exploited: X
Corroborated: X
NVD available: X
Average confidence: X.XXX
```

The values depend on the actual data collected during each pipeline execution.

---

## Reproducible Historical Data

Each pipeline execution can produce a new historical snapshot.

This means that the project no longer depends only on the current state of the CTI dataset.

Instead:

```text
Collection 1 → Snapshot 1
Collection 2 → Snapshot 2
Collection 3 → Snapshot 3
Collection 4 → Snapshot 4
```

Historical snapshots can later be used for experiments and trend analysis.

---

## Day 16 Automation

The historical snapshot stage was added to the automated pipeline.

The complete workflow is now:

```text
1. Collect CISA advisory listings
2. Collect full CISA advisories
3. Extract CVE identifiers
4. Build CTI records
5. Normalize CTI records
6. Check duplicate CVEs
7. Enrich CTI with NVD
8. Analyze vulnerability risk
9. Build provenance records
10. Generate confidence scores
11. Collect CISA KEV data
12. Match CTI records with KEV
13. Build final CTI dataset
14. Validate final CTI dataset
15. Evaluate CTI dataset
16. Save historical CTI snapshot
```

The complete pipeline can be executed using:

```bash
python src/run_pipeline.py
```

---

## Research Importance

Historical snapshots provide an important foundation for CTI research.

Cybersecurity intelligence is dynamic.

The state of vulnerability information can change over time because:

* New CVEs are published.
* Existing CVEs receive additional enrichment.
* Vulnerabilities can become listed in KEV.
* Vulnerability metadata can change.
* Evidence from multiple sources can become available.
* Confidence values can change as supporting evidence changes.

Therefore, storing historical snapshots allows the system to study changes instead of only analyzing one static dataset.

---

## Possible Research Questions

Historical data enables future research questions such as:

### Question 1

How does the number of observed vulnerabilities change over time?

### Question 2

How frequently do collected vulnerabilities become listed in the KEV catalog?

### Question 3

Does multi-source corroboration increase over time?

### Question 4

How does NVD enrichment coverage change across collection periods?

### Question 5

How does the project's evidence confidence change as additional source information becomes available?

These questions can later become part of the experimental evaluation of the research paper.

---

## Important Limitation

A historical snapshot represents the state of the collected data at a particular time.

It does not necessarily represent the complete state of global vulnerability intelligence at that time.

The system is limited by:

* Available public sources
* Collection frequency
* API availability
* Rate limiting
* Source coverage
* Data quality
* Collection errors

Therefore, historical results should be interpreted as observations from the project's selected data sources.

---

## Day 16 Learning Outcomes

Day 16 introduced:

* Historical data preservation
* Timestamped snapshots
* Time-based CTI analysis
* Dataset versioning
* Historical metrics
* Reproducible data collection
* Trend-analysis foundations
* Temporal CTI research

---

## Day 16 Conclusion

Day 16 extends the CTI system from a single-state analysis system into a time-aware architecture.

The project can now preserve multiple CTI collection states:

```text
CTI Collection
      ↓
Final Dataset
      ↓
Evaluation
      ↓
Historical Snapshot
      ↓
Historical Dataset
      ↓
Time-Based Analysis
```

This creates a foundation for future temporal analysis, experimental evaluation, and research-paper results.

# Day 17 - CTI Trend Analysis and Historical Visualization

## Objective

Day 17 introduces time-based analysis of the historical CTI snapshots created during Day 16.

The purpose is to analyze how the project's CTI dataset and evidence metrics change across multiple collection runs.

This extends the project from static CTI analysis toward temporal analysis.

---

## Day 17 Architecture

The workflow is:

```text
Historical Snapshots
        ↓
Metric Extraction
        ↓
Historical Metrics
        ↓
Trend Analysis
        ↓
Visualization
```

---

## Historical Data Source

The historical snapshots are stored in:

```text
data/history/
```

Each snapshot represents the state of the CTI dataset at a particular collection time.

---

## Trend Analysis Script

The main analysis script is:

```text
src/trend_analysis.py
```

It processes all files matching:

```text
cti_snapshot_*.json
```

from:

```text
data/history/
```

The resulting historical metrics are saved to:

```text
data/processed/historical_metrics.json
```

---

## Historical Metrics

The system extracts the following metrics from each snapshot:

* Total CVEs
* Known exploited vulnerabilities
* Corroborated records
* NVD availability
* Average confidence
* NVD coverage rate
* KEV match rate
* Corroboration rate

---

## NVD Coverage

NVD coverage is calculated as:

```text
NVD Available Records
--------------------- × 100
Total Records
```

This measures the proportion of project records containing NVD information at the time of the snapshot.

---

## KEV Match Rate

The KEV match rate is calculated as:

```text
Known Exploited Records
----------------------- × 100
Total Records
```

The value represents the proportion of collected CVEs that matched the CISA KEV catalog during the collection.

A CVE not present in the KEV catalog should not be interpreted as proof that the vulnerability has never been exploited.

---

## Corroboration Rate

The corroboration rate is calculated as:

```text
Corroborated Records
-------------------- × 100
Total Records
```

The current project considers records corroborated when multiple supporting sources are present according to the project's provenance model.

---

## Average Confidence

The system calculates the average project-defined confidence score across the records in each historical snapshot.

The confidence score represents evidence strength under the project's heuristic model.

It is not a statistical probability.

---

## Historical Visualization

Day 17 introduces:

```text
src/trend_dashboard.py
```

The dashboard reads:

```text
data/processed/historical_metrics.json
```

and displays historical trends.

---

## Trend Dashboard

The Day 17 dashboard provides:

* Historical CTI metrics table
* CVEs observed over time
* Known exploited vulnerabilities over time
* NVD coverage over time
* Corroboration rate over time
* Average confidence over time

The dashboard can be started using:

```bash
streamlit run src/trend_dashboard.py
```

---

## Original CTI Dashboard

The original CTI dashboard remains available:

```bash
streamlit run src/dashboard.py
```

The original dashboard focuses on individual CTI records.

The Day 17 dashboard focuses on historical and temporal analysis.

---

## Temporal CTI Analysis

The project can now represent CTI observations across time:

```text
Snapshot 1
    ↓
Snapshot 2
    ↓
Snapshot 3
    ↓
Snapshot 4
    ↓
Trend Analysis
```

This makes it possible to study changes in the collected intelligence over multiple collection periods.

---

## Research Questions

Historical analysis enables several future research questions.

### Question 1

How does the number of observed CVEs change over time?

### Question 2

How does NVD enrichment coverage change over time?

### Question 3

How frequently do collected CVEs match the CISA KEV catalog?

### Question 4

Does multi-source corroboration remain stable over time?

### Question 5

How does the average evidence confidence change over time?

---

## Research Importance

A CTI system should ideally be evaluated across multiple observations rather than a single dataset.

Historical snapshots allow the project to preserve previous system states and compare them.

This provides a foundation for longitudinal CTI analysis.

---

## Experimental Evaluation

The historical dataset can later support experiments such as:

```text
Collection Period
       ↓
Dataset Size
       ↓
Source Coverage
       ↓
KEV Matching
       ↓
Corroboration
       ↓
Confidence
```

The resulting measurements can be used in the experimental evaluation section of the future research paper.

---

## Important Limitation

Historical snapshots represent the information collected by this project from its selected sources.

They do not represent the complete global vulnerability landscape.

The results may be affected by:

* Source availability
* Collection frequency
* API rate limits
* Source updates
* Missing data
* Network failures
* Changes in source content

Therefore, historical trends should be interpreted as trends within the project's observation process.

---

## Day 17 Automation

The trend-analysis stage has been added to the automated pipeline.

The pipeline now performs:

```text
1. CISA Collection
2. Advisory Collection
3. CVE Extraction
4. CTI Record Creation
5. Normalization
6. Duplicate Detection
7. NVD Enrichment
8. Risk Analysis
9. Provenance
10. Confidence Scoring
11. KEV Collection
12. KEV Matching
13. Final CTI Dataset
14. Validation
15. Evaluation
16. Historical Snapshot
17. Historical Trend Analysis
```

The entire workflow can be executed using:

```bash
python src/run_pipeline.py
```

---

## Day 17 Learning Outcomes

Day 17 introduced:

* Historical CTI analysis
* Temporal datasets
* Trend metrics
* Longitudinal analysis
* Time-based visualization
* Historical evidence comparison
* Research-oriented data visualization
* Experimental metric tracking

---

## Day 17 Conclusion

Day 17 extends the project from a static CTI processing system into a time-aware CTI analysis system.

The architecture is now:

```text
OSINT Collection
      ↓
CTI Processing
      ↓
Evidence Correlation
      ↓
Validation
      ↓
Evaluation
      ↓
Historical Snapshots
      ↓
Temporal Analysis
      ↓
Research Visualization
```

This provides a foundation for future experiments involving CTI changes over time and strengthens the project's preparation for an IEEE-style research paper.


## Day 18 - Automated CTI Report Generation

An automated CTI report generation layer was added to the project.

The purpose of this stage is to automatically convert the processed
CTI dataset into a structured, human-readable research report.

### Report Generator

A new Python module was created:

```text
src/generate_report.py





## Day 19 - Explainable Threat Correlation

An explainable threat correlation engine was introduced to
combine multiple CTI evidence signals into a transparent
correlation score.

The new module is:

```text
src/threat_correlation.py


## Day 20 - Research Evaluation of the Threat Correlation Model

The project introduced a descriptive evaluation stage for the
explainable threat correlation model.

The new module is:

```text
src/evaluate_correlation.py




## Day 21 - Improved Explainable Threat Correlation Model

The threat correlation methodology was improved by introducing a
signal-based weighted correlation model.

The new module is:

```text
src/improved_correlation.py



## Day 22 - Ground-Truth Benchmark and Quantitative Evaluation

A benchmark-based evaluation layer was added to the CTI
correlation methodology.

The purpose of this stage is to compare the output of the
explainable correlation model against an explicitly defined
benchmark label.

### Benchmark Generator

A new module was created:

```text
src/build_ground_truth.py


## Day 23 - Correlation Threshold Sensitivity Analysis

A threshold sensitivity analysis was added to evaluate how the
performance of the CTI correlation model changes when different
decision thresholds are applied.

The new module is:

```text
src/threshold_analysis.py


## Day 24 - Train/Validation-Style Correlation Experiment

A train/validation-style experimental framework was added to
reduce the risk of evaluating a threshold on the same data used
to select that threshold.

The new module is:

```text
src/train_validation_experiment.py



## Day 25 - Correlation Model Ablation Study

An ablation study was added to investigate the contribution of
individual evidence signals to the proposed CTI correlation model.

The new module is:

```text
src/ablation_study.py


## Day 26 - Statistical Analysis

An exploratory statistical analysis layer was added to evaluate
the distributions of CTI correlation scores and related evidence
attributes.

The new module is:

```text
src/statistical_analysis.py


## Day 27 - Final Research Visualizations

A research visualization layer was added to the CTI analysis
pipeline.

The new module is:

```text
src/research_visualizations.py


## Day 28 - Reproducibility and Experiment Automation

A reproducibility layer was added to the project.

The new module is:

```text
src/reproduce_experiment.py
