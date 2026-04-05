"""
main.py — Deadband CLI entry point.

Usage:
    python main.py --vendor "Siemens" --platform claroty
    python main.py --vendor "Schneider" --platform dragos
    python main.py --vendor "Rockwell" --platform splunk
    python main.py --list-platforms
"""

import argparse
import sys

from src.collector import collect_all
from src.mapper import map_cves_to_techniques
from src.gap_analyzer import load_coverage_config, analyze_gaps, list_platforms, list_categories
from src.reporter import generate_report


def main():
    parser = argparse.ArgumentParser(
        prog="deadband",
        description="ICS/OT adversary mapping tool — CVEs → ATT&CK for ICS → detection gaps → PDF report",
    )
    parser.add_argument("--vendor", type=str, help='Vendor or protocol to search (e.g. "Siemens", "Modbus")')
    parser.add_argument("--platform", type=str, help="Security platform to gap-analyse against (e.g. claroty, splunk)")
    parser.add_argument("--output", type=str, default=None, help="Output PDF path (optional, auto-named if omitted)")
    parser.add_argument("--list-platforms", action="store_true", help="List all available platforms and exit")

    args = parser.parse_args()

    # load config early — needed for platform listing and validation
    config = load_coverage_config()

    if args.list_platforms:
        print("\nAvailable platforms by category:\n")
        for category in list_categories(config):
            platforms = list_platforms(config, category=category)
            print(f"  {category.upper()}")
            for p in platforms:
                desc = config[p].get("description", "").split(".")[0]
                print(f"    {p:<15} {desc}")
        print()
        sys.exit(0)

    if not args.vendor or not args.platform:
        parser.print_help()
        print("\nError: --vendor and --platform are required.\n")
        sys.exit(1)

    vendor = args.vendor.strip()
    platform = args.platform.strip().lower()

    # validate platform before doing any heavy work
    available = list_platforms(config)
    if platform not in available:
        print(f"\nUnknown platform '{platform}'.")
        print(f"Available: {', '.join(available)}\n")
        sys.exit(1)

    output_path = args.output or f"reports/deadband_{vendor.lower().replace(' ', '_')}_{platform}.pdf"

    print(f"\n// deadband — ICS/OT Threat Intelligence Mapper")
    print(f"   Vendor   : {vendor}")
    print(f"   Platform : {platform}")
    print(f"   Output   : {output_path}\n")

    # run the pipeline
    collection = collect_all(vendor)
    all_cves = collection["nvd"] + collection["cisa"]
    mapped_results = map_cves_to_techniques(all_cves)
    gap_report = analyze_gaps(platform, mapped_results, config=config)
    path = generate_report(
        vendor=vendor,
        platform=platform,
        mapped_results=mapped_results,
        gap_report=gap_report,
        output_path=output_path,
    )

    print(f"\n✓ Report ready: {path}")
    print(f"  {gap_report['total_techniques']} techniques | {gap_report['covered']} covered | {gap_report['gaps']} blind spots | {gap_report['coverage_pct']}% coverage\n")


if __name__ == "__main__":
    main()