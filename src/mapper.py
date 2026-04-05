"""
mapper.py — Takes CVEs from collector.py and figures out which ATT&CK for ICS
techniques they relate to, and which threat groups actually use those techniques.

The matching isn't perfect — it's keyword-based — but it gets you 80% of the way
there and the results are good enough to build a real threat profile from.
"""

import json
import os
import re
import requests

ATTACK_ICS_URL = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"
ATTACK_ICS_LOCAL = os.path.join(os.path.dirname(__file__), "..", "data", "attack_ics.json")

REQUEST_TIMEOUT = 60  # the bundle is ~4MB so give it some breathing room


# ---------------------------------------------------------------------------
# Loading the ATT&CK bundle
# ---------------------------------------------------------------------------

def load_attack_bundle() -> dict:
    """
    Loads the ATT&CK for ICS STIX bundle. Downloads it from MITRE on first run,
    then reads from disk every time after that — no point hammering their server.
    """
    local_path = os.path.normpath(ATTACK_ICS_LOCAL)
    os.makedirs(os.path.dirname(local_path), exist_ok=True)

    if os.path.exists(local_path):
        print(f"[ATT&CK] Found cached bundle at {local_path}, loading ...")
        with open(local_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    print("[ATT&CK] No local bundle found — downloading from MITRE CTI ...")
    try:
        response = requests.get(ATTACK_ICS_URL, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        raise RuntimeError(f"Couldn't download the ATT&CK ICS bundle: {exc}") from exc

    bundle = response.json()
    with open(local_path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh)
    print(f"[ATT&CK] Saved bundle to {local_path} for next time.")
    return bundle


# ---------------------------------------------------------------------------
# Building indexes from the raw STIX data
# ---------------------------------------------------------------------------

def _technique_id(stix_obj: dict) -> str | None:
    """
    Pulls the human-readable technique ID (like T0803) out of a STIX object.
    It's buried in external_references — this just digs it out.
    """
    for ref in stix_obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def build_technique_index(bundle: dict) -> dict[str, dict]:
    """
    Builds a clean lookup of all ICS techniques from the raw STIX bundle.
    Skips anything revoked or deprecated — we only want current, relevant stuff.
    """
    index = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = _technique_id(obj)
        tactics = [phase["phase_name"] for phase in obj.get("kill_chain_phases", [])]
        url = next(
            (r.get("url") for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack" and r.get("url")),
            None,
        )

        index[obj["id"]] = {
            "stix_id": obj["id"],
            "technique_id": technique_id,
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "tactics": tactics,
            "platforms": obj.get("x_mitre_platforms", []),
            "url": url,
        }
    return index


def build_group_index(bundle: dict) -> dict[str, dict]:
    """
    Same idea as build_technique_index but for threat groups — Sandworm,
    OilRig, ALLANITE, etc. Again, skipping anything revoked or deprecated.
    """
    index = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "intrusion-set":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        index[obj["id"]] = {
            "stix_id": obj["id"],
            "name": obj.get("name", ""),
            "aliases": obj.get("aliases", []),
            "description": obj.get("description", ""),
        }
    return index


def build_group_technique_map(bundle: dict) -> dict[str, list[str]]:
    """
    Figures out which groups use which techniques by parsing STIX 'uses'
    relationships. Only looks at direct group → technique links — campaign
    relationships are excluded to keep things focused on named threat actors.
    """
    # grab all group IDs upfront so we can filter relationships quickly
    group_ids = {
        obj["id"]
        for obj in bundle.get("objects", [])
        if obj.get("type") == "intrusion-set"
        and not obj.get("revoked")
        and not obj.get("x_mitre_deprecated")
    }

    technique_to_groups: dict[str, list[str]] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") != "uses":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        source = obj.get("source_ref", "")
        target = obj.get("target_ref", "")

        if source in group_ids and target.startswith("attack-pattern--"):
            technique_to_groups.setdefault(target, []).append(source)

    return technique_to_groups


# ---------------------------------------------------------------------------
# Keyword matching — where CVEs meet ATT&CK
# ---------------------------------------------------------------------------

def _extract_keywords(text: str) -> list[str]:
    """
    Breaks a CVE description into keywords we can match against technique text.
    Filters out short words (under 4 chars) — they're too generic to be useful.
    """
    return [w.lower() for w in re.findall(r"[a-zA-Z]{4,}", text)]


def match_techniques(
    cve: dict,
    technique_index: dict[str, dict],
    min_keyword_hits: int = 1,
) -> list[dict]:
    """
    Matches a CVE to ATT&CK ICS techniques by checking how many keywords from
    the CVE description appear in each technique's name and description.

    Higher score = more keyword overlap = more likely to be a real match.
    min_keyword_hits lets you filter out weak matches (default is 1, raise it
    to reduce noise).
    """
    description = cve.get("description") or cve.get("short_description") or ""
    if not description:
        return []

    keywords = _extract_keywords(description)
    if not keywords:
        return []

    # deduplicate so the same word doesn't boost the score multiple times
    unique_keywords = list(dict.fromkeys(keywords))

    matches = []
    for tech in technique_index.values():
        haystack = (tech["name"] + " " + tech["description"]).lower()
        hit_words = [kw for kw in unique_keywords if kw in haystack]
        score = len(hit_words)

        if score >= min_keyword_hits:
            matches.append({
                "technique_id": tech["technique_id"],
                "name": tech["name"],
                "tactics": tech["tactics"],
                "platforms": tech["platforms"],
                "url": tech["url"],
                "score": score,
                "matched_keywords": hit_words,
            })

    # best matches first
    matches.sort(key=lambda m: m["score"], reverse=True)
    return matches


# ---------------------------------------------------------------------------
# Attaching threat groups to matched techniques
# ---------------------------------------------------------------------------

def resolve_groups(
    technique_stix_id: str,
    group_technique_map: dict[str, list[str]],
    group_index: dict[str, dict],
) -> list[dict]:
    """
    Given a technique's STIX ID, returns the threat groups known to use it.
    This is where it gets interesting — connecting a CVE all the way to
    a named threat actor like Sandworm or OilRig.
    """
    group_stix_ids = group_technique_map.get(technique_stix_id, [])
    groups = []
    seen = set()

    for gid in group_stix_ids:
        if gid in group_index and gid not in seen:
            seen.add(gid)
            g = group_index[gid]
            groups.append({
                "name": g["name"],
                "aliases": g["aliases"],
                "description": g["description"],
            })
    return groups


# ---------------------------------------------------------------------------
# Main function — runs the full mapping pipeline
# ---------------------------------------------------------------------------

def map_cves_to_techniques(cves: list[dict]) -> list[dict]:
    """
    Takes a list of CVEs (from collector.py) and runs them through the full
    mapping pipeline — technique matching + threat group resolution.

    This is the function everything else calls. Returns one result dict per CVE
    with all the matched techniques and groups attached.
    """
    print("[Mapper] Loading ATT&CK for ICS bundle ...")
    bundle = load_attack_bundle()

    print("[Mapper] Building indexes ...")
    technique_index = build_technique_index(bundle)
    group_index = build_group_index(bundle)
    group_technique_map = build_group_technique_map(bundle)

    print(
        f"[Mapper] Indexed {len(technique_index)} techniques, "
        f"{len(group_index)} groups."
    )

    # reverse lookup so we can go from technique_id string → stix_id
    tech_stix_by_id = {v["technique_id"]: v["stix_id"] for v in technique_index.values()}

    results = []
    total = len(cves)

    for i, cve in enumerate(cves, start=1):
        cve_id = cve.get("cve_id", "UNKNOWN")
        if i % 50 == 0 or i == total:
            print(f"[Mapper] Processing CVE {i}/{total} ...")

        matched = match_techniques(cve, technique_index)

        # attach groups to each matched technique
        for match in matched:
            stix_id = tech_stix_by_id.get(match["technique_id"])
            match["groups"] = resolve_groups(stix_id, group_technique_map, group_index) if stix_id else []

        results.append({
            "cve_id": cve_id,
            "source": cve.get("source"),
            "description": cve.get("description") or cve.get("short_description"),
            "cvss_score": cve.get("cvss_score"),
            "cvss_severity": cve.get("cvss_severity"),
            "vendor": cve.get("vendor"),
            "product": cve.get("product"),
            "techniques": matched,
        })

    mapped_count = sum(1 for r in results if r["techniques"])
    print(f"[Mapper] Done. {mapped_count}/{total} CVEs matched at least one technique.")
    return results


if __name__ == "__main__":
    from collector import collect_all
    data = collect_all("Siemens")
    all_cves = data["nvd"] + data["cisa"]
    results = map_cves_to_techniques(all_cves)

    # show first 3 CVEs that matched something
    matched = [r for r in results if r["techniques"]]
    for r in matched[:3]:
        print(f"\n{r['cve_id']} — {r['cvss_severity']}")
        for t in r["techniques"][:2]:
            print(f"  → {t['technique_id']} {t['name']} (score: {t['score']})")
            for g in t["groups"]:
                print(f"     Group: {g['name']}")
