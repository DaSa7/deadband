"""
Tests for src/gap_analyzer.py — threat profile extraction, gap analysis, and helpers.
"""

from src.gap_analyzer import (
    extract_threat_profile,
    analyze_gaps,
    list_platforms,
    list_categories,
    _empty_report,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_SAMPLE_MAPPED = [
    {
        "cve_id": "CVE-2024-0001",
        "source": "NVD",
        "description": "Buffer overflow in Modbus parser",
        "cvss_score": 9.8,
        "cvss_severity": "CRITICAL",
        "techniques": [
            {
                "technique_id": "T0801",
                "name": "Monitor Process State",
                "tactics": ["collection"],
                "platforms": ["Control Server"],
                "url": "https://attack.mitre.org/techniques/T0801",
                "score": 3,
                "matched_keywords": ["monitor", "process", "state"],
                "groups": [{"name": "SANDWORM", "aliases": ["Sandworm Team"]}],
            },
            {
                "technique_id": "T0803",
                "name": "Block Command Message",
                "tactics": ["inhibit-response-function"],
                "platforms": ["Control Server"],
                "url": "https://attack.mitre.org/techniques/T0803",
                "score": 2,
                "matched_keywords": ["block", "command"],
                "groups": [],
            },
        ],
    },
    {
        "cve_id": "CVE-2024-0002",
        "source": "CISA-KEV",
        "description": "RCE in SCADA firmware update",
        "cvss_score": 7.5,
        "cvss_severity": "HIGH",
        "techniques": [
            {
                "technique_id": "T0801",
                "name": "Monitor Process State",
                "tactics": ["collection"],
                "platforms": ["Control Server"],
                "url": "https://attack.mitre.org/techniques/T0801",
                "score": 2,
                "matched_keywords": ["monitor", "process"],
                "groups": [{"name": "SANDWORM", "aliases": ["Sandworm Team"]}],
            },
        ],
    },
]

_SAMPLE_CONFIG = {
    "test_platform": {
        "category": "ot",
        "description": "Test platform for unit tests.",
        "techniques": ["T0801"],
    },
    "empty_platform": {
        "category": "siem",
        "description": "Platform with no coverage.",
        "techniques": [],
    },
}


# ---------------------------------------------------------------------------
# Threat profile extraction
# ---------------------------------------------------------------------------

def test_extract_threat_profile_deduplicates_techniques():
    profile = extract_threat_profile(_SAMPLE_MAPPED)
    assert "T0801" in profile
    assert "T0803" in profile
    assert len(profile) == 2


def test_extract_threat_profile_merges_cve_ids():
    profile = extract_threat_profile(_SAMPLE_MAPPED)
    entry = profile["T0801"]
    assert "CVE-2024-0001" in entry["cve_ids"]
    assert "CVE-2024-0002" in entry["cve_ids"]


def test_extract_threat_profile_deduplicates_groups():
    profile = extract_threat_profile(_SAMPLE_MAPPED)
    entry = profile["T0801"]
    group_names = [g["name"] for g in entry["groups"]]
    assert group_names.count("SANDWORM") == 1


def test_extract_threat_profile_cleans_scratch_fields():
    profile = extract_threat_profile(_SAMPLE_MAPPED)
    for entry in profile.values():
        assert "_seen_group_names" not in entry


def test_extract_threat_profile_empty_input():
    profile = extract_threat_profile([])
    assert profile == {}


# ---------------------------------------------------------------------------
# Gap analysis
# ---------------------------------------------------------------------------

def test_analyze_gaps_identifies_covered_and_gaps():
    report = analyze_gaps("test_platform", _SAMPLE_MAPPED, config=_SAMPLE_CONFIG)
    assert report["platform"] == "test_platform"
    assert report["total_techniques"] == 2
    assert report["covered"] == 1  # T0801
    assert report["gaps"] == 1     # T0803
    assert report["coverage_pct"] == 50.0


def test_analyze_gaps_empty_coverage_platform():
    report = analyze_gaps("empty_platform", _SAMPLE_MAPPED, config=_SAMPLE_CONFIG)
    assert report["covered"] == 0
    assert report["gaps"] == 2


def test_analyze_gaps_unknown_platform_raises():
    try:
        analyze_gaps("nonexistent", _SAMPLE_MAPPED, config=_SAMPLE_CONFIG)
        assert False, "Should have raised ValueError"
    except ValueError as exc:
        assert "Unknown platform" in str(exc)


def test_analyze_gaps_empty_mapped_results():
    report = analyze_gaps("test_platform", [], config=_SAMPLE_CONFIG)
    assert report["total_techniques"] == 0
    assert report["coverage_pct"] == 0.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def test_list_platforms_returns_all():
    platforms = list_platforms(_SAMPLE_CONFIG)
    assert "test_platform" in platforms
    assert "empty_platform" in platforms


def test_list_platforms_filters_by_category():
    platforms = list_platforms(_SAMPLE_CONFIG, category="ot")
    assert platforms == ["test_platform"]


def test_list_categories():
    categories = list_categories(_SAMPLE_CONFIG)
    assert "ot" in categories
    assert "siem" in categories


def test_empty_report():
    report = _empty_report("p", "cat", "desc")
    assert report["total_techniques"] == 0
    assert report["coverage_pct"] == 0.0
    assert report["gap_techniques"] == []
