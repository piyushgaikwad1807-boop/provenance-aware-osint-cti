import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime, timezone

BASE_URL = "https://www.cisa.gov"
LIST_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories"

HEADERS = {
    "User-Agent": "OSINT-CTI-Research/1.0"
}


def download_page(url):
    response = requests.get(
        url,
        headers=HEADERS,
        timeout=15
    )

    response.raise_for_status()

    return response.text


def find_advisory_links(html):
    soup = BeautifulSoup(html, "html.parser")

    advisories = []

    for link in soup.find_all("a", href=True):

        title = link.get_text(" ", strip=True)
        href = link["href"]

        if "CISA Adds" in title:
            url = urljoin(BASE_URL, href)

            advisories.append({
                "title": title,
                "url": url
            })

    return advisories


def extract_advisory_text(html):
    soup = BeautifulSoup(html, "html.parser")

    main = soup.find("main")

    if main:
        return main.get_text(" ", strip=True)

    return soup.get_text(" ", strip=True)


if __name__ == "__main__":

    print("[+] Starting advisory collector")

    listing_html = download_page(LIST_URL)

    advisories = find_advisory_links(listing_html)

    print(f"[+] Found {len(advisories)} advisory links")
    print()

    results = []

    for number, advisory in enumerate(advisories, start=1):

        print(
            f"[{number}/{len(advisories)}] "
            f"Downloading: {advisory['title']}"
        )

        try:
            html = download_page(advisory["url"])

            text = extract_advisory_text(html)

            results.append({
                "title": advisory["title"],
                "url": advisory["url"],
                "content": text,
                "collected_at": datetime.now(timezone.utc).isoformat()
            })

        except requests.RequestException as error:

            print("[!] Failed:", error)

    output_file = "data/raw/cisa_advisories_full.json"

    with open(output_file, "w", encoding="utf-8") as file:

        json.dump(
            results,
            file,
            indent=4,
            ensure_ascii=False
        )

    print()
    print(f"[+] Successfully collected {len(results)} advisories")
    print(f"[+] Saved: {output_file}")
