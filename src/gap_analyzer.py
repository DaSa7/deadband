"""
gap_analyzer.py — Takes the CVE-to-technique mapping from mapper.py and asks
the hard question: for a given security platform, which of the techniques in
your threat profile can't it actually detect?

Those blind spots are your gaps. This module finds them.

Supports OT-specific platforms (Claroty, Dragos, Nozomi), SIEMs (Splunk,
QRadar, Sentinel), EDRs (CrowdStrike, Defender), and open-source tools
(Zeek, Snort). Platform categories come from detection_coverage.json, so
adding a new platform is just a JSON edit away.
"""

import json
import os

COVERAGE_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "detection_coverage.json")


# ---------------------------------------------------------------------------
# Loading coverage config
# ---------------------------------------------------------------------------

def load_coverage_config(path: str | None = None) -> dict:
    """
    Loads the detection coverage config from disk.

    The config maps platform names to lists of ATT&CK ICS technique IDs they
    can detect. If no path is given it defaults to data/detection_coverage.json
    relative to this file.

    Raises:
        FileNotFoundError: If the file doesn't exist at the expected path.
        ValueError: If the JSON is malformed.
    """
    target = os.path.normpath(path or COVERAGE_FILE)

    if not os.path.exists(target):
        raise FileNotFoundError(
            f"Detection coverage file not found at: {target}\n"
            "Create data/detection_coverage.json — see the project README for format."
        )

    print(f"[GapAnalyzer] Loading coverage config from {target} ...")

    with open(target, "r", encoding="utf-8") as fh:
        try:
            config = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Couldn't parse coverage config as JSON: {exc}") from exc

    # strip the _comment key if present — it's documentation, not a platform
    config.pop("_comment", None)
    return config


def list_platforms(config: dict, category: str | None = None) -> list[str]:
    """
    Returns the list of platform names defined in the coverage config.

    Pass a category ("ot", "siem", "edr", "open_source") to filter the list.
    Useful for CLI autocomplete, or for telling the user what's available when
    they spell a platform name wrong.
    """
    if category:
        return sorted(k for k, v in config.items() if v.get("category") == category)
    return sorted(config.keys())


def list_categories(config: dict) -> list[str]:
    """
    Returns the unique platform categories present in the coverage config
    (e.g. ["edr", "open_source", "ot", "siem"]).
    """
    return sorted({v.get("category", "unknown") for v in config.values()})


# ---------------------------------------------------------------------------
# Building the threat profile from mapper output
# ---------------------------------------------------------------------------

def extract_threat_profile(mapped_results: list[dict]) -> dict[str, dict]:
    """
    Collapses the per-CVE mapper output into a flat threat profile: a dict
    of unique technique IDs to everything we know about them (name, tactics,
    groups, which CVEs triggered the match).

    A technique only needs to appear once across any CVE to show up in the
    profile — we're building a picture of the adversary's full playbook, not
    counting how many CVEs hit each technique.

    Args:
        mapped_results: The list returned by mapper.map_cves_to_techniques().

    Returns:
        Dict of technique_id → profile entry with keys: technique_id, name,
        tactics, platforms, url, groups (deduplicated), cve_ids (which CVEs
        triggered this technique).
    """
    profile: dict[str, dict] = {}

    for result in mapped_results:
        cve_id = result.get("cve_id", "UNKNOWN")
        for tech in result.get("techniques", []):
            tid = tech.get("technique_id")
            if not tid:
                continue

            if tid not in profile:
                profile[tid] = {
                    "technique_id": tid,
                    "name": tech.get("name", ""),
                    "tactics": tech.get("tactics", []),
                    "platforms": tech.get("platforms", []),
                    "url": tech.get("url"),
                    "groups": [],
                    "cve_ids": [],
                    "_seen_group_names": set(),  # scratch space, removed before returning
                }

            entry = profile[tid]

            # deduplicate CVEs
            if cve_id not in entry["cve_ids"]:
                entry["cve_ids"].append(cve_id)

            # merge groups, deduplicated by name
            for grp in tech.get("groups", []):
                grp_name = grp.get("name", "")
                if grp_name and grp_name not in entry["_seen_group_names"]:
                    entry["_seen_group_names"].add(grp_name)
                    entry["groups"].append({
                        "name": grp_name,
                        "aliases": grp.get("aliases", []),
                    })

    # clean up the scratch sets before handing data back to the caller
    for entry in profile.values():
        entry.pop("_seen_group_names", None)

    return profile


# ---------------------------------------------------------------------------
# The gap analysis itself
# ---------------------------------------------------------------------------

def analyze_gaps(
    platform: str,
    mapped_results: list[dict],
    config: dict | None = None,
) -> dict:
    """
    Compares the techniques in your CVE threat profile against what a given
    platform can detect, and returns a structured gap report.

    Args:
        platform: Platform name to check against — must match a key in the
                  coverage config (case-insensitive). E.g. "claroty", "dragos".
        mapped_results: Output of mapper.map_cves_to_techniques().
        config: Already-loaded coverage config dict. If None, loads from disk.

    Returns:
        A gap report dict with:
          platform            — normalised platform name
          total_techniques    — unique techniques in the threat profile
          covered             — how many the platform can detect
          gaps                — how many it can't
          coverage_pct        — covered / total as a percentage (0–100)
          covered_techniques  — list of covered technique dicts
          gap_techniques      — list of blind-spot technique dicts (the important bit)

    Raises:
        ValueError: If the platform name isn't in the coverage config.
    """
    if config is None:
        config = load_coverage_config()

    # normalise so "Claroty" and "claroty" both work
    platform_key = platform.strip().lower()
    available = list_platforms(config)

    if platform_key not in config:
        raise ValueError(
            f"Unknown platform '{platform}'. "
            f"Available platforms: {', '.join(available)}"
        )

    platform_coverage: set[str] = set(config[platform_key].get("techniques", []))
    platform_desc: str = config[platform_key].get("description", "")
    platform_category: str = config[platform_key].get("category", "unknown")

    print(f"[GapAnalyzer] Building threat profile from {len(mapped_results)} CVE results ...")
    threat_profile = extract_threat_profile(mapped_results)
    total = len(threat_profile)

    if total == 0:
        print("[GapAnalyzer] No techniques found in the threat profile — nothing to analyse.")
        return _empty_report(platform_key, platform_category, platform_desc)

    print(
        f"[GapAnalyzer] Threat profile contains {total} unique techniques. "
        f"Checking against {platform_key} coverage ({len(platform_coverage)} techniques) ..."
    )

    covered_techniques = []
    gap_techniques = []

    for tid, entry in sorted(threat_profile.items()):
        if tid in platform_coverage:
            covered_techniques.append(entry)
        else:
            gap_techniques.append(entry)

    covered = len(covered_techniques)
    gaps = len(gap_techniques)
    coverage_pct = round((covered / total) * 100, 1) if total > 0 else 0.0

    print(
        f"[GapAnalyzer] Done. {covered}/{total} techniques covered ({coverage_pct}%). "
        f"{gaps} blind spot(s) identified."
    )

    return {
        "platform": platform_key,
        "platform_category": platform_category,
        "platform_description": platform_desc,
        "total_techniques": total,
        "covered": covered,
        "gaps": gaps,
        "coverage_pct": coverage_pct,
        "covered_techniques": covered_techniques,
        "gap_techniques": gap_techniques,
    }


def _empty_report(platform: str, platform_category: str, platform_desc: str) -> dict:
    """Returns a zeroed-out gap report for when the threat profile is empty."""
    return {
        "platform": platform,
        "platform_category": platform_category,
        "platform_description": platform_desc,
        "total_techniques": 0,
        "covered": 0,
        "gaps": 0,
        "coverage_pct": 0.0,
        "covered_techniques": [],
        "gap_techniques": [],
    }


# ---------------------------------------------------------------------------
# Convenience: run all platforms at once and compare
# ---------------------------------------------------------------------------

def compare_all_platforms(mapped_results: list[dict], config: dict | None = None) -> dict[str, dict]:
    """
    Runs gap analysis against every platform in the coverage config and
    returns all reports in a single dict keyed by platform name.

    Handy for generating a side-by-side comparison without calling
    analyze_gaps() in a loop yourself.

    Args:
        mapped_results: Output of mapper.map_cves_to_techniques().
        config: Already-loaded coverage config. Loaded from disk if None.

    Returns:
        Dict of platform_name → gap report (same shape as analyze_gaps()).
    """
    if config is None:
        config = load_coverage_config()

    reports = {}
    for platform in list_platforms(config):
        print(f"\n[GapAnalyzer] === Analysing platform: {platform} ===")
        reports[platform] = analyze_gaps(platform, mapped_results, config=config)

    return reports


def compare_by_category(
    category: str,
    mapped_results: list[dict],
    config: dict | None = None,
) -> dict[str, dict]:
    """
    Same as compare_all_platforms but filters to one platform category.

    Useful when you want to answer "which SIEM handles this threat profile
    best?" without wading through OT and EDR results at the same time.

    Valid categories are whatever's in the coverage config — typically
    "ot", "siem", "edr", "open_source". Pass an unknown category and you'll
    get an empty dict back plus a warning.

    Args:
        category: Platform category to filter by (case-sensitive).
        mapped_results: Output of mapper.map_cves_to_techniques().
        config: Already-loaded coverage config. Loaded from disk if None.

    Returns:
        Dict of platform_name → gap report for platforms in that category.
    """
    if config is None:
        config = load_coverage_config()

    platforms = list_platforms(config, category=category)
    if not platforms:
        available_cats = list_categories(config)
        print(
            f"[GapAnalyzer] WARNING: No platforms found for category '{category}'. "
            f"Available categories: {', '.join(available_cats)}"
        )
        return {}

    reports = {}
    for platform in platforms:
        print(f"\n[GapAnalyzer] === [{category}] Analysing platform: {platform} ===")
        reports[platform] = analyze_gaps(platform, mapped_results, config=config)

    return reports


if __name__ == "__main__":
    # Quick smoke-test: load a saved mapper result or synthesise a fake one.
    import sys

    fake_results = [
        {
            "cve_id": "CVE-2022-12345",
            "source": "NVD",
            "description": "Remote code execution via exploitation of remote services.",
            "techniques": [
                {
                    "technique_id": "T0866",
                    "name": "Exploitation of Remote Services",
                    "tactics": ["initial-access", "lateral-movement"],
                    "platforms": ["Engineering Workstation"],
                    "url": "https://attack.mitre.org/techniques/T0866",
                    "score": 3,
                    "matched_keywords": ["remote", "execution", "exploitation"],
                    "groups": [{"name": "Dragonfly", "aliases": ["Dragonfly 2.0"]}],
                }
            ],
        },
        {
            "cve_id": "CVE-2023-99999",
            "source": "CISA-KEV",
            "description": "Firmware modification allowing persistent access to PLCs.",
            "techniques": [
                {
                    "technique_id": "T0839",
                    "name": "Module Firmware",
                    "tactics": ["persistence", "impair-process-control"],
                    "platforms": ["Field Controller/RTU/PLC/IED"],
                    "url": "https://attack.mitre.org/techniques/T0839",
                    "score": 2,
                    "matched_keywords": ["firmware", "persistent"],
                    "groups": [],
                }
            ],
        },
    ]

    config = load_coverage_config()
    print(f"\nAvailable platforms: {', '.join(list_platforms(config))}")
    print(f"Available categories: {', '.join(list_categories(config))}\n")

    for cat in list_categories(config):
        reports = compare_by_category(cat, fake_results, config=config)
        print(f"\n--- {cat.upper()} summary ---")
        for name, report in reports.items():
            print(
                f"  {name:15s}  covered {report['covered']}/{report['total_techniques']} "
                f"({report['coverage_pct']}%)  gaps: {report['gaps']}"
            )
