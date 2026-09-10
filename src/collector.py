import json
import requests
from bs4 import BeautifulSoup
from datetime import datetime, timezone

URL = "https://www.cisa.gov/news-events/cybersecurity-advisories"

HEADERS = {
    "User-Agent": "OSINT-CTI-Research/1.0"
}


def collect_page(url):
    response = requests.get(
        url,
        headers=HEADERS,
        timeout=10
    )

    response.raise_for_status()

    return response.text


def extract_titles(html):
    soup = BeautifulSoup(html, "html.parser")

    titles = []

    for heading in soup.find_all(["h1", "h2", "h3"]):
        text = heading.get_text(" ", strip=True)

        if text:
            titles.append(text)

    return titles


if __name__ == "__main__":
    print("[+] Starting OSINT collector")

    html = collect_page(URL)
    titles = extract_titles(html)

    result = {
        "source": URL,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "titles": titles
    }

    output_file = "data/raw/cisa_advisories.json"

    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(result, file, indent=4)

    print(f"[+] Collected {len(titles)} headings")
    print(f"[+] Saved to {output_file}")
