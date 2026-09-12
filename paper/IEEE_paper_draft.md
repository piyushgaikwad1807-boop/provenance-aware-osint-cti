# Provenance-Aware OSINT Cyber Threat Intelligence and Automated Threat Correlation System

## Abstract

Cyber Threat Intelligence (CTI) relies on information collected from
multiple heterogeneous sources. However, combining vulnerability
information from different sources can introduce challenges related
to provenance, evidence consistency, confidence assessment, and
automated correlation.

This work presents a provenance-aware OSINT Cyber Threat Intelligence
and automated threat correlation framework. The proposed system
collects vulnerability intelligence from authoritative sources,
including the Cybersecurity and Infrastructure Security Agency
(CISA), the National Vulnerability Database (NVD), and the CISA
Known Exploited Vulnerabilities (KEV) catalog.

The framework performs CVE extraction, normalization, NVD enrichment,
provenance tracking, confidence estimation, exploitation-status
matching, risk analysis, and explainable signal-based threat
correlation. The correlation model combines evidence signals
representing source evidence, exploitation evidence, source
corroboration, CVSS severity, and confidence.

The experimental framework includes benchmark evaluation, threshold
analysis, train-validation experimentation, ablation analysis,
descriptive statistical analysis, and automated research
visualization.

The current implementation is intended as a research prototype.
The benchmark dataset is small, CISA KEV membership is used as a
proxy exploitation label, and the correlation weights are heuristic.
Therefore, the experimental results should be interpreted as
preliminary rather than as evidence of general predictive
performance.

## Keywords

Cyber Threat Intelligence, OSINT, Vulnerability Intelligence,
CVE, CISA KEV, NVD, Provenance, Threat Correlation, Cybersecurity,
Explainable Correlation

---

# I. Introduction

Cyber Threat Intelligence provides security teams with information
that can support vulnerability management, threat monitoring, and
security decision-making. Modern CTI workflows frequently combine
information from multiple sources, creating a need for systematic
methods for collecting, normalizing, correlating, and evaluating
security evidence.

Open-source intelligence provides a useful foundation for automated
CTI collection because vulnerability advisories and security
databases contain structured and semi-structured information.
However, raw information from individual sources does not
automatically provide a complete representation of a vulnerability.

A vulnerability may contain information such as a CVE identifier,
severity score, advisory description, exploitation status, external
references, and source-specific evidence. Combining these attributes
requires maintaining information about where each piece of evidence
originated.

This project addresses this problem by developing a
provenance-aware CTI processing and correlation framework.

The primary objectives of the proposed system are:

1. Collect vulnerability intelligence from authoritative OSINT
   sources.

2. Extract and normalize CVE identifiers.

3. Enrich vulnerability records with NVD information.

4. Track the provenance of collected evidence.

5. Estimate evidence confidence using a transparent heuristic.

6. Identify known exploited vulnerabilities using CISA KEV data.

7. Generate explainable CTI correlation scores.

8. Evaluate the correlation methodology using benchmark,
   threshold, train-validation, ablation, and statistical analysis.

9. Generate reproducible research outputs and visualizations.

The main contribution of this work is a prototype framework that
combines provenance tracking, evidence confidence, exploitation
status, and explainable correlation into an automated CTI processing
pipeline.

---

# II. Related Concepts

## A. Open-Source Intelligence

Open-source intelligence refers to intelligence derived from
publicly accessible information sources. In cybersecurity,
OSINT can provide vulnerability advisories, security alerts,
technical reports, indicators, and exploitation information.

## B. Cyber Threat Intelligence

CTI transforms raw security information into structured intelligence
that can support cybersecurity analysis and decision-making.

## C. Common Vulnerabilities and Exposures

CVE identifiers provide standardized identifiers for publicly known
security vulnerabilities.

## D. CVSS

The Common Vulnerability Scoring System provides a standardized
framework for describing vulnerability severity.

## E. CISA Known Exploited Vulnerabilities

The CISA KEV catalog provides information about vulnerabilities that
have been identified as exploited in the wild.

## F. Provenance

Data provenance records the origin and supporting evidence associated
with a data item. In CTI systems, provenance can improve
traceability and support analysis of evidence reliability.

---

# III. Proposed System

## A. System Architecture

The proposed architecture consists of several processing stages.

```text
CISA
  |
NVD
  |
KEV
  |
  v
Data Collection
  |
  v
CVE Extraction
  |
  v
Normalization
  |
  v
NVD Enrichment
  |
  v
Provenance Tracking
  |
  v
Confidence Estimation
  |
  v
KEV Matching
  |
  v
Risk Analysis
  |
  v
Threat Correlation
  |
  +-------------------+
  |                   |
  v                   v
Evaluation       Visualization
  |                   |
  +---------+---------+
            |
            v
      Research Report
