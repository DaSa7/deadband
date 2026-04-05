from src.collector import collect_all
from src.mapper import map_cves_to_techniques
from src.gap_analyzer import load_coverage_config, analyze_gaps

data = collect_all("Siemens")
all_cves = data["nvd"] + data["cisa"]
results = map_cves_to_techniques(all_cves)

config = load_coverage_config()
report = analyze_gaps("claroty", results, config=config)

print(f"\nPlatform: {report['platform']}")
print(f"Total techniques: {report['total_techniques']}")
print(f"Covered: {report['covered']} ({report['coverage_pct']}%)")
print(f"Gaps: {report['gaps']}")
print(f"\nBlind spots:")
for t in report['gap_techniques'][:5]:
    print(f"  {t['technique_id']} — {t['name']}")
    for g in t['groups']:
        print(f"    Actor: {g['name']}")