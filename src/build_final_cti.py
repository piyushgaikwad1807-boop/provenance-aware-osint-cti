import json
from pathlib import Path
from datetime import datetime, timezone


ENRICHED_FILE = Path(
    "data/processed/enriched_cti.json"
)

PROVENANCE_FILE = Path(
    "data/processed/provenance_cti.json"
)

CONFIDENCE_FILE = Path(
    "data/processed/confidence_cti.json"
)

KEV_FILE = Path(
    "data/processed/kev_cti.json"
)

RISK_FILE = Path(
    "data/processed/risk_analysis.json"
)

OUTPUT_FILE = Path(
    "data/processed/final_cti.json"
)


def load_json(path):
    """Load JSON data safely."""

    if not path.exists():
        print(f"[!] File not found: {path}")
        return []

    try:
        with path.open(
            "r",
            encoding="utf-8"
        ) as file:
            return json.load(file)

    except json.JSONDecodeError as error:
        print(
            f"[!] Invalid JSON in {path}: "
            f"{error}"
        )
        return []


def index_by_cve(records):
    """Create CVE -> record lookup."""

    result = {}

    for record in records:

        cve_id = record.get("cve_id")

        if cve_id:
            result[cve_id] = record

    return result


def main():

    print("[+] Loading project datasets")

    enriched = load_json(
        ENRICHED_FILE
    )

    provenance = load_json(
        PROVENANCE_FILE
    )

    confidence = load_json(
        CONFIDENCE_FILE
    )

    kev = load_json(
        KEV_FILE
    )

    risk = load_json(
        RISK_FILE
    )

    print(
        f"[+] Enriched records: "
        f"{len(enriched)}"
    )

    print(
        f"[+] Provenance records: "
        f"{len(provenance)}"
    )

    print(
        f"[+] Confidence records: "
        f"{len(confidence)}"
    )

    print(
        f"[+] KEV records: "
        f"{len(kev)}"
    )

    print(
        f"[+] Risk records: "
        f"{len(risk)}"
    )

    # --------------------------------------------------
    # Build indexes
    # --------------------------------------------------

    enriched_by_cve = index_by_cve(
        enriched
    )

    provenance_by_cve = index_by_cve(
        provenance
    )

    confidence_by_cve = index_by_cve(
        confidence
    )

    kev_by_cve = index_by_cve(
        kev
    )

    risk_by_cve = index_by_cve(
        risk
    )

    # --------------------------------------------------
    # Use enriched data as primary dataset
    # --------------------------------------------------

    cve_ids = set()

    cve_ids.update(
        enriched_by_cve.keys()
    )

    cve_ids.update(
        provenance_by_cve.keys()
    )

    cve_ids.update(
        confidence_by_cve.keys()
    )

    cve_ids.update(
        kev_by_cve.keys()
    )

    cve_ids.update(
        risk_by_cve.keys()
    )

    final_records = []

    # --------------------------------------------------
    # Merge all information
    # --------------------------------------------------

    for cve_id in sorted(cve_ids):

        enriched_record = (
            enriched_by_cve.get(
                cve_id,
                {}
            )
        )

        provenance_record = (
            provenance_by_cve.get(
                cve_id,
                {}
            )
        )

        confidence_record = (
            confidence_by_cve.get(
                cve_id,
                {}
            )
        )

        kev_record = (
            kev_by_cve.get(
                cve_id,
                {}
            )
        )

        risk_record = (
            risk_by_cve.get(
                cve_id,
                {}
            )
        )

        # --------------------------------------------------
        # NVD
        # --------------------------------------------------

        nvd_data = enriched_record.get(
            "nvd"
        )

        if not isinstance(
            nvd_data,
            dict
        ):
            nvd_data = None

        # --------------------------------------------------
        # CISA advisory
        # --------------------------------------------------

        cisa_advisory = {
            "title": enriched_record.get(
                "advisory_title"
            ),
            "url": enriched_record.get(
                "advisory_url"
            ),
            "source": "CISA"
        }

        # --------------------------------------------------
        # KEV
        # --------------------------------------------------

        kev_data = kev_record.get(
            "kev"
        )

        if not isinstance(
            kev_data,
            dict
        ):
            kev_data = {
                "known_exploited": False
            }

        # --------------------------------------------------
        # Provenance
        # --------------------------------------------------

        sources = provenance_record.get(
            "sources",
            []
        )

        source_count = provenance_record.get(
            "source_count",
            len(sources)
        )

        corroborated = provenance_record.get(
            "corroborated",
            source_count >= 2
        )

        # --------------------------------------------------
        # Confidence
        # --------------------------------------------------

        confidence_score = (
            confidence_record.get(
                "confidence_score"
            )
        )

        confidence_category = (
            confidence_record.get(
                "confidence_category"
            )
        )

        confidence_reasons = (
            confidence_record.get(
                "confidence_reasons",
                []
            )
        )

        # --------------------------------------------------
        # Risk
        # --------------------------------------------------

        risk_level = risk_record.get(
            "risk_level"
        )

        # --------------------------------------------------
        # Final unified record
        # --------------------------------------------------

        final_record = {

            "cve_id": cve_id,

            "cisa": {
                "advisory_title":
                    cisa_advisory.get(
                        "title"
                    ),

                "advisory_url":
                    cisa_advisory.get(
                        "url"
                    ),

                "source": "CISA"
            },

            "nvd": nvd_data,

            "kev": kev_data,

            "exploitation_status":
                kev_record.get(
                    "exploitation_status",
                    "UNKNOWN"
                ),

            "provenance": {
                "sources": sources,
                "source_count":
                    source_count,
                "corroborated":
                    corroborated
            },

            "confidence": {
                "score":
                    confidence_score,

                "category":
                    confidence_category,

                "reasons":
                    confidence_reasons
            },

            "risk": {
                "risk_level":
                    risk_level,

                "cvss_score":
                    risk_record.get(
                        "cvss_score"
                    ),

                "severity":
                    risk_record.get(
                        "severity"
                    )
            },

            "pipeline": {
                "enriched":
                    enriched_record.get(
                        "enrichment_status"
                    ),

                "generated_at":
                    datetime.now(
                        timezone.utc
                    ).isoformat()
            }
        }

        final_records.append(
            final_record
        )

    # --------------------------------------------------
    # Save final dataset
    # --------------------------------------------------

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            final_records,
            file,
            indent=4,
            ensure_ascii=False
        )

    # --------------------------------------------------
    # Summary
    # --------------------------------------------------

    nvd_count = sum(
        1
        for record in final_records
        if record.get("nvd") is not None
    )

    kev_count = sum(
        1
        for record in final_records
        if record.get(
            "exploitation_status"
        ) == "KNOWN_EXPLOITED"
    )

    corroborated_count = sum(
        1
        for record in final_records
        if record.get(
            "provenance",
            {}
        ).get(
            "corroborated",
            False
        )
    )

    print()
    print("=" * 60)
    print("FINAL CTI DATASET")
    print("=" * 60)

    print(
        f"Total CVE records      : "
        f"{len(final_records)}"
    )

    print(
        f"NVD enriched records   : "
        f"{nvd_count}"
    )

    print(
        f"KEV matches            : "
        f"{kev_count}"
    )

    print(
        f"Corroborated records   : "
        f"{corroborated_count}"
    )

    print(
        f"Saved                  : "
        f"{OUTPUT_FILE}"
    )

    print("=" * 60)


if __name__ == "__main__":
    main()
