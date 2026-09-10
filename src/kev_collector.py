import json
from pathlib import Path
from datetime import datetime, timezone

import requests


KEV_URL = (
    "https://www.cisa.gov/sites/default/files/"
    "feeds/known_exploited_vulnerabilities.json"
)

OUTPUT_FILE = Path(
    "data/raw/cisa_kev.json"
)


def main():

    print("[+] Downloading CISA KEV catalog")

    try:
        response = requests.get(
            KEV_URL,
            timeout=30
        )

        response.raise_for_status()

    except requests.RequestException as error:

        print(
            f"[!] Failed to download KEV catalog: "
            f"{error}"
        )

        return

    try:

        data = response.json()

    except ValueError:

        print("[!] CISA response was not valid JSON")
        return

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )

    output = {
        "source": "CISA KEV",
        "source_url": KEV_URL,
        "catalog_version": data.get(
            "catalogVersion"
        ),
        "date_released": data.get(
            "dateReleased"
        ),
        "date_updated": data.get(
            "dateUpdated"
        ),
        "collected_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "vulnerabilities": vulnerabilities
    }

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(
        f"[+] KEV vulnerabilities: "
        f"{len(vulnerabilities)}"
    )

    print(
        f"[+] Saved: {OUTPUT_FILE}"
    )


if __name__ == "__main__":
    main()
