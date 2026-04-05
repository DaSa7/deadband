"""
collector.py — Fetch CVEs from NVD and ICS advisories from CISA,
filtered by a vendor keyword (e.g. "Siemens").
"""

import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

REQUEST_TIMEOUT = 30  # seconds
NVD_PAGE_SIZE = 100
NVD_RATE_LIMIT_DELAY = 6   # seconds between requests without API key
NVD_RATE_LIMIT_DELAY_KEY = 0.6  # seconds between requests with API key


def _nvd_headers() -> dict:
    """
    Return request headers, including the NVD API key if present in the environment.

    Strips whitespace from the key to guard against trailing newlines in .env files.
    Warns if the key is present but does not match the expected UUID format (36 chars).
    """
    api_key = os.getenv("NVD_API_KEY", "").strip()
    if not api_key:
        return {}
    if len(api_key) != 36:
        print(
            f"[NVD] WARNING: NVD_API_KEY looks malformed "
            f"(got {len(api_key)} chars, expected 36 for a UUID). "
            "Requests may return 404 — verify the key in your .env file."
        )
    return {"apiKey": api_key}


def fetch_nvd_cves(keyword: str) -> list[dict]:
    """
    Fetch CVEs from the NVD REST API 2.0 filtered by a keyword.

    Paginates through all results and handles 429 rate-limit responses by
    backing off and retrying. Returns a flat list of cleaned CVE dicts.

    Args:
        keyword: Vendor or product keyword to search for (e.g. "Siemens").

    Returns:
        List of dicts, each containing: cve_id, description, published,
        last_modified, cvss_score, cvss_severity, references.
    """
    headers = _nvd_headers()
    has_key = bool(headers)
    delay = NVD_RATE_LIMIT_DELAY_KEY if has_key else NVD_RATE_LIMIT_DELAY

    if not has_key:
        print("[NVD] No NVD_API_KEY found — using unauthenticated rate limit (slower).")

    print(f"[NVD] Fetching CVEs for keyword: '{keyword}' ...")

    results = []
    start_index = 0

    while True:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": NVD_PAGE_SIZE,
            "startIndex": start_index,
        }

        response = _get_with_retry(NVD_API_URL, params=params, headers=headers)
        if response is None:
            print("[NVD] Failed to retrieve a page — stopping pagination.")
            break

        data = response.json()
        total = data.get("totalResults", 0)
        vulnerabilities = data.get("vulnerabilities", [])

        if start_index == 0:
            print(f"[NVD] Total results reported by API: {total}")

        for item in vulnerabilities:
            cve = item.get("cve", {})
            results.append(_parse_nvd_cve(cve))

        fetched_so_far = start_index + len(vulnerabilities)
        print(f"[NVD] Retrieved {fetched_so_far}/{total} CVEs ...")

        if fetched_so_far >= total or not vulnerabilities:
            break

        start_index = fetched_so_far
        time.sleep(delay)

    print(f"[NVD] Done. {len(results)} CVEs collected.")
    return results


def _get_with_retry(url: str, params: dict, headers: dict, max_retries: int = 3) -> requests.Response | None:
    """
    Perform a GET request, retrying on 429 (rate limited) or transient errors.

    Args:
        url: Target URL.
        params: Query parameters.
        headers: HTTP headers.
        max_retries: Maximum number of retry attempts.

    Returns:
        A successful Response object, or None if all retries are exhausted.
    """
    for attempt in range(1, max_retries + 1):
        try:
            response = requests.get(url, params=params, headers=headers, timeout=REQUEST_TIMEOUT)

            if response.status_code == 200:
                return response

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 30))
                print(f"[NVD] Rate limited. Waiting {retry_after}s before retry {attempt}/{max_retries} ...")
                time.sleep(retry_after)
                continue

            if response.status_code == 404:
                if headers.get("apiKey"):
                    print(
                        "[NVD] 404 received — this usually means the API key is invalid or malformed. "
                        "Retrying without the API key ..."
                    )
                    headers = {k: v for k, v in headers.items() if k != "apiKey"}
                    continue
                print("[NVD] 404 received — check that the NVD API endpoint is correct.")
                return None

            if response.status_code in (403, 401):
                print(f"[NVD] Auth error {response.status_code} — the API key may be invalid or expired.")
                return None

            print(f"[NVD] Unexpected status {response.status_code} on attempt {attempt}/{max_retries}.")
            if attempt < max_retries:
                time.sleep(5 * attempt)

        except requests.exceptions.Timeout:
            print(f"[NVD] Request timed out (attempt {attempt}/{max_retries}).")
            if attempt < max_retries:
                time.sleep(5 * attempt)

        except requests.exceptions.RequestException as exc:
            print(f"[NVD] Request error on attempt {attempt}/{max_retries}: {exc}")
            if attempt < max_retries:
                time.sleep(5 * attempt)

    return None


def _parse_nvd_cve(cve: dict) -> dict:
    """
    Extract relevant fields from a raw NVD CVE object.

    Args:
        cve: Raw CVE dict from the NVD API vulnerabilities[].cve node.

    Returns:
        Dict with keys: cve_id, description, published, last_modified,
        cvss_score, cvss_severity, references.
    """
    cve_id = cve.get("id", "UNKNOWN")

    descriptions = cve.get("descriptions", [])
    description = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        "No description available.",
    )

    # CVSS v3.1 preferred, fall back to v3.0, then v2.0
    metrics = cve.get("metrics", {})
    cvss_score = None
    cvss_severity = None

    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity") or metric_list[0].get("baseSeverity")
            break

    references = [
        ref.get("url") for ref in cve.get("references", []) if ref.get("url")
    ]

    return {
        "cve_id": cve_id,
        "description": description,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "references": references,
        "source": "NVD",
    }


def fetch_cisa_advisories(keyword: str) -> list[dict]:
    """
    Fetch CISA Known Exploited Vulnerabilities (KEV) and filter by keyword.

    Downloads the full KEV catalogue and returns only entries where the
    vendor or product name contains the keyword (case-insensitive).

    Args:
        keyword: Vendor or product keyword to filter by (e.g. "Siemens").

    Returns:
        List of dicts, each containing: cve_id, vendor, product, vulnerability_name,
        date_added, short_description, required_action, due_date.
    """
    print(f"[CISA] Fetching Known Exploited Vulnerabilities catalogue ...")

    try:
        response = requests.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.exceptions.Timeout:
        print("[CISA] Request timed out.")
        return []
    except requests.exceptions.RequestException as exc:
        print(f"[CISA] Failed to fetch KEV catalogue: {exc}")
        return []

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])
    print(f"[CISA] Catalogue contains {len(vulnerabilities)} total entries.")

    keyword_lower = keyword.lower()
    matches = []

    for vuln in vulnerabilities:
        vendor = vuln.get("vendorProject", "")
        product = vuln.get("product", "")
        if keyword_lower in vendor.lower() or keyword_lower in product.lower():
            matches.append(_parse_cisa_advisory(vuln))

    print(f"[CISA] Found {len(matches)} entries matching '{keyword}'.")
    return matches


def _parse_cisa_advisory(vuln: dict) -> dict:
    """
    Extract relevant fields from a raw CISA KEV vulnerability entry.

    Args:
        vuln: Raw vulnerability dict from the CISA KEV JSON feed.

    Returns:
        Dict with keys: cve_id, vendor, product, vulnerability_name,
        date_added, short_description, required_action, due_date, source.
    """
    return {
        "cve_id": vuln.get("cveID"),
        "vendor": vuln.get("vendorProject"),
        "product": vuln.get("product"),
        "vulnerability_name": vuln.get("vulnerabilityName"),
        "date_added": vuln.get("dateAdded"),
        "short_description": vuln.get("shortDescription"),
        "required_action": vuln.get("requiredAction"),
        "due_date": vuln.get("dueDate"),
        "source": "CISA-KEV",
    }


def collect_all(keyword: str) -> dict:
    """
    Run both NVD and CISA collectors for a given vendor keyword.

    Args:
        keyword: Vendor or product keyword (e.g. "Siemens").

    Returns:
        Dict with keys 'nvd' and 'cisa', each containing a list of result dicts.
    """
    print(f"\n=== Deadband Collector: '{keyword}' ===\n")
    nvd_results = fetch_nvd_cves(keyword)
    print()
    cisa_results = fetch_cisa_advisories(keyword)
    print(f"\n=== Collection complete: {len(nvd_results)} NVD CVEs, {len(cisa_results)} CISA advisories ===\n")
    return {"nvd": nvd_results, "cisa": cisa_results}

if __name__ == "__main__":
    results = collect_all("Siemens")
    print(f"NVD: {len(results['nvd'])} CVEs")
    print(f"CISA: {len(results['cisa'])} advisories")
