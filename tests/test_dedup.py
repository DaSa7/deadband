"""
Tests for CVE deduplication in main.py.
"""

from main import _deduplicate_cves


def test_deduplicate_removes_dupes():
    cves = [
        {"cve_id": "CVE-2024-0001", "source": "NVD"},
        {"cve_id": "CVE-2024-0002", "source": "NVD"},
        {"cve_id": "CVE-2024-0001", "source": "CISA-KEV"},
    ]
    result = _deduplicate_cves(cves)
    assert len(result) == 2
    # first occurrence wins
    assert result[0]["source"] == "NVD"


def test_deduplicate_preserves_order():
    cves = [
        {"cve_id": "CVE-B", "source": "NVD"},
        {"cve_id": "CVE-A", "source": "NVD"},
    ]
    result = _deduplicate_cves(cves)
    assert [c["cve_id"] for c in result] == ["CVE-B", "CVE-A"]


def test_deduplicate_empty():
    assert _deduplicate_cves([]) == []


def test_deduplicate_skips_missing_cve_id():
    cves = [
        {"cve_id": "CVE-2024-0001"},
        {"description": "no cve_id field"},
        {"cve_id": "CVE-2024-0001"},
    ]
    result = _deduplicate_cves(cves)
    assert len(result) == 1
