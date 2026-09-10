import json
from pathlib import Path
from datetime import datetime, timezone


CTI_FILE = Path(
    "data/processed/confidence_cti.json"
)

KEV_FILE = Path(
    "data/raw/cisa_kev.json"
)

OUTPUT_FILE = Path(
    "data/processed/kev_cti.json"
)


def load_json(path):

    if not path.exists():

        print(
            f"[!] File not found: {path}"
        )

        return None

    with path.open(
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


def main():

    print("[+] Loading CTI records")

    cti_records = load_json(
        CTI_FILE
    )

    print("[+] Loading CISA KEV catalog")

    kev_data = load_json(
        KEV_FILE
    )

    if cti_records is None:
        return

    if kev_data is None:
        return

    kev_entries = kev_data.get(
        "vulnerabilities",
        []
    )

    # Create fast CVE lookup table
    kev_lookup = {
        entry.get("cveID"): entry
        for entry in kev_entries
        if entry.get("cveID")
    }

    print(
        f"[+] KEV entries loaded: "
        f"{len(kev_lookup)}"
    )

    output_records = []

    kev_matches = 0

    for record in cti_records:

        cve_id = record.get(
            "cve_id"
        )

        kev_entry = kev_lookup.get(
            cve_id
        )

        result = record.copy()

        if kev_entry:

            kev_matches += 1

            result["kev"] = {
                "known_exploited": True,
                "date_added": kev_entry.get(
                    "dateAdded"
                ),
                "vendor_project": kev_entry.get(
                    "vendorProject"
                ),
                "product": kev_entry.get(
                    "product"
                ),
                "vulnerability_name": kev_entry.get(
                    "vulnerabilityName"
                ),
                "short_description": kev_entry.get(
                    "shortDescription"
                ),
                "required_action": kev_entry.get(
                    "requiredAction"
                ),
                "due_date": kev_entry.get(
                    "dueDate"
                ),
                "source": "CISA KEV",
                "source_url": kev_data.get(
                    "source_url"
                )
            }

            result["exploitation_status"] = (
                "KNOWN_EXPLOITED"
            )

        else:

            result["kev"] = {
                "known_exploited": False,
                "source": "CISA KEV",
                "source_url": kev_data.get(
                    "source_url"
                )
            }

            result["exploitation_status"] = (
                "NOT_IN_KEV"
            )

        result["kev_checked_at"] = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )

        output_records.append(
            result
        )

    # --------------------------------------------------
    # Save
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
            output_records,
            file,
            indent=4,
            ensure_ascii=False
        )

    print()
    print(
        f"[+] CTI records checked: "
        f"{len(output_records)}"
    )

    print(
        f"[+] KEV matches: "
        f"{kev_matches}"
    )

    print(
        f"[+] Not in KEV: "
        f"{len(output_records) - kev_matches}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
