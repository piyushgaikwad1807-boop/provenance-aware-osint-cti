import json
import requests
import time

INPUT_FILE = "data/processed/normalized_cti.json"
OUTPUT_FILE = "data/processed/enriched_cti.json"

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

HEADERS = {
    "User-Agent": "OSINT-CTI-Research/1.0"
}

# Conservative settings for a public API
MAX_RETRIES = 5
INITIAL_WAIT = 5
REQUEST_DELAY = 2


def get_nvd_data(cve_id):
    """
    Query NVD for a CVE.
    Retries automatically when NVD returns HTTP 429.
    """

    params = {
        "cveId": cve_id
    }

    for attempt in range(MAX_RETRIES):

        try:
            response = requests.get(
                NVD_URL,
                params=params,
                headers=HEADERS,
                timeout=20
            )

        except requests.RequestException as error:

            print(
                f"[!] Network error for {cve_id}: {error}"
            )

            if attempt < MAX_RETRIES - 1:

                wait_time = INITIAL_WAIT * (2 ** attempt)

                print(
                    f"[!] Retrying in {wait_time} seconds..."
                )

                time.sleep(wait_time)
                continue

            return None

        # Successful request
        if response.status_code == 200:
            return response.json()

        # Rate limited
        if response.status_code == 429:

            wait_time = INITIAL_WAIT * (2 ** attempt)

            print(
                f"[!] NVD rate limited {cve_id}"
            )

            print(
                f"[!] Waiting {wait_time} seconds "
                f"before retry {attempt + 1}/{MAX_RETRIES}"
            )

            if attempt < MAX_RETRIES - 1:
                time.sleep(wait_time)
                continue

            print(
                f"[!] Maximum retries reached for {cve_id}"
            )

            return None

        # Other HTTP error
        print(
            f"[!] HTTP {response.status_code} "
            f"for {cve_id}"
        )

        return None

    return None


def extract_nvd_information(data):
    """
    Extract useful information from the NVD response.
    """

    if not data:
        return None

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )

    if not vulnerabilities:
        return None

    cve = vulnerabilities[0].get(
        "cve",
        {}
    )

    # -----------------------------
    # Description
    # -----------------------------

    descriptions = cve.get(
        "descriptions",
        []
    )

    english_description = ""

    for description in descriptions:

        if description.get("lang") == "en":

            english_description = description.get(
                "value",
                ""
            )

            break

    # -----------------------------
    # References
    # -----------------------------

    references = []

    for reference in cve.get(
        "references",
        []
    ):

        url = reference.get("url")

        if url:
            references.append(url)

    # -----------------------------
    # CVSS information
    # -----------------------------

    metrics = cve.get(
        "metrics",
        {}
    )

    cvss_score = None
    severity = None
    vector = None

    # Try CVSS v3.1 first
    if metrics.get("cvssMetricV31"):

        metric = metrics["cvssMetricV31"][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        cvss_score = cvss_data.get(
            "baseScore"
        )

        severity = cvss_data.get(
            "baseSeverity"
        )

        vector = cvss_data.get(
            "vectorString"
        )

    # Try CVSS v3.0
    elif metrics.get("cvssMetricV30"):

        metric = metrics["cvssMetricV30"][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        cvss_score = cvss_data.get(
            "baseScore"
        )

        severity = cvss_data.get(
            "baseSeverity"
        )

        vector = cvss_data.get(
            "vectorString"
        )

    # Try CVSS v2
    elif metrics.get("cvssMetricV2"):

        metric = metrics["cvssMetricV2"][0]

        cvss_data = metric.get(
            "cvssData",
            {}
        )

        cvss_score = cvss_data.get(
            "baseScore"
        )

        severity = metric.get(
            "baseSeverity"
        )

        vector = cvss_data.get(
            "vectorString"
        )

    # -----------------------------
    # Return structured NVD data
    # -----------------------------

    return {
        "description": english_description,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "cvss_score": cvss_score,
        "severity": severity,
        "cvss_vector": vector,
        "references": references
    }


def main():

    print("[+] Loading CTI records")

    try:

        with open(
            INPUT_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            records = json.load(file)

    except FileNotFoundError:

        print(
            f"[!] Input file not found: {INPUT_FILE}"
        )

        return

    print(
        f"[+] Records loaded: {len(records)}"
    )

    enriched_records = []

    processed_cves = set()

    successful = 0
    failed = 0

    for record in records:

        cve_id = record.get("cve_id")

        if not cve_id:
            print("[!] Record has no CVE ID")
            continue

        # Prevent duplicate NVD requests
        if cve_id in processed_cves:
            continue

        processed_cves.add(cve_id)

        print()
        print(
            f"[+] Querying NVD: {cve_id}"
        )

        nvd_data = get_nvd_data(cve_id)

        # ---------------------------------
        # Successful NVD lookup
        # ---------------------------------

        if nvd_data:

            nvd_info = extract_nvd_information(
                nvd_data
            )

            combined = {
                "cve_id": cve_id,

                "cisa": {
                    "source": record.get(
                        "source",
                        "CISA"
                    ),
                    "advisory_title": record.get(
                        "advisory_title"
                    ),
                    "advisory_url": record.get(
                        "advisory_url"
                    ),
                    "collected_at": record.get(
                        "collected_at"
                    )
                },

                "nvd": nvd_info,

                "enrichment_status": "success",

                "enriched_at": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ",
                    time.gmtime()
                )
            }

            enriched_records.append(
                combined
            )

            successful += 1

            print(
                f"[+] NVD enrichment successful: {cve_id}"
            )

        # ---------------------------------
        # Failed NVD lookup
        # ---------------------------------

        else:

            combined = {
                "cve_id": cve_id,

                "cisa": {
                    "source": record.get(
                        "source",
                        "CISA"
                    ),
                    "advisory_title": record.get(
                        "advisory_title"
                    ),
                    "advisory_url": record.get(
                        "advisory_url"
                    ),
                    "collected_at": record.get(
                        "collected_at"
                    )
                },

                "nvd": None,

                "enrichment_status": "failed",

                "enriched_at": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ",
                    time.gmtime()
                )
            }

            enriched_records.append(
                combined
            )

            failed += 1

            print(
                f"[!] NVD enrichment failed: {cve_id}"
            )

        # Be polite to the public API
        time.sleep(REQUEST_DELAY)

    # ---------------------------------
    # Save results
    # ---------------------------------

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            enriched_records,
            file,
            indent=4,
            ensure_ascii=False
        )

    # ---------------------------------
    # Final summary
    # ---------------------------------

    print()
    print("=" * 60)
    print("NVD ENRICHMENT SUMMARY")
    print("=" * 60)

    print(
        f"Input records:       {len(records)}"
    )

    print(
        f"Unique CVEs:         {len(processed_cves)}"
    )

    print(
        f"NVD successful:      {successful}"
    )

    print(
        f"NVD failed:          {failed}"
    )

    print(
        f"Output records:      {len(enriched_records)}"
    )

    print()
    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
