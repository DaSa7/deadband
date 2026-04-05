"""
reporter.py — Takes everything collector, mapper, and gap_analyzer produced
and turns it into a professional-looking HTML report, then renders it to PDF
via WeasyPrint.

The HTML template lives inline below as a Jinja2 string — no separate files
needed. Tweak the CSS there if you want to change the look.
"""

import os
from datetime import datetime, timezone

from jinja2 import Environment, BaseLoader
from weasyprint import HTML as WeasyHTML

# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------

# This is the entire report in one Jinja2 string. Keeping it inline means
# the module is self-contained — no template directory to manage.
_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Deadband — {{ vendor }} Threat Intelligence Report</title>
<style>
  /* ── Reset & base ─────────────────────────────────────────────── */
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: #0d1117;
    color: #e6edf3;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    font-size: 13px;
    line-height: 1.6;
  }

  /* ── Layout ───────────────────────────────────────────────────── */
  .page { max-width: 1100px; margin: 0 auto; padding: 40px 48px; }

  /* ── Typography helpers ───────────────────────────────────────── */
  h1, h2, h3 { font-weight: 600; letter-spacing: -0.02em; }
  h2 { font-size: 15px; color: #00ff88; text-transform: uppercase;
       letter-spacing: 0.08em; margin-bottom: 16px; padding-bottom: 6px;
       border-bottom: 1px solid #21262d; }
  h3 { font-size: 13px; color: #8b949e; margin-bottom: 8px; }
  .mono { font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; }
  .dim  { color: #8b949e; }
  .accent { color: #00ff88; }

  /* ── Header ───────────────────────────────────────────────────── */
  .header {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    padding-bottom: 32px;
    border-bottom: 2px solid #21262d;
    margin-bottom: 40px;
  }
  .logo {
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: 28px;
    font-weight: 700;
    color: #00ff88;
    letter-spacing: -0.04em;
  }
  .logo-sub {
    font-size: 11px;
    color: #8b949e;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-top: 2px;
  }
  .header-meta { text-align: right; }
  .header-meta .report-title {
    font-size: 18px;
    font-weight: 600;
    color: #e6edf3;
    margin-bottom: 8px;
  }
  .header-meta .meta-row { font-size: 12px; color: #8b949e; margin-top: 3px; }
  .header-meta .meta-row span { color: #e6edf3; }

  /* ── Section spacing ──────────────────────────────────────────── */
  .section { margin-bottom: 48px; }

  /* ── Executive summary cards ──────────────────────────────────── */
  .summary-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 12px;
    margin-bottom: 24px;
  }
  .stat-card {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 16px 12px;
    text-align: center;
  }
  .stat-value {
    font-size: 28px;
    font-weight: 700;
    color: #00ff88;
    font-family: "SFMono-Regular", Consolas, monospace;
    display: block;
  }
  .stat-value.danger { color: #f85149; }
  .stat-value.warn   { color: #d29922; }
  .stat-label {
    font-size: 10px;
    color: #8b949e;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-top: 4px;
  }
  .threat-actors {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 16px 20px;
  }
  .actor-list { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
  .actor-pill {
    background: #1f2937;
    border: 1px solid #374151;
    border-radius: 20px;
    padding: 3px 12px;
    font-size: 12px;
    color: #d1d5db;
  }
  .actor-pill.nation-state {
    border-color: #f85149;
    color: #ffa198;
    background: #2d1214;
  }

  /* ── Tables ───────────────────────────────────────────────────── */
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  thead th {
    background: #161b22;
    color: #8b949e;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-size: 10px;
    padding: 10px 12px;
    text-align: left;
    border-bottom: 1px solid #21262d;
  }
  tbody tr { border-bottom: 1px solid #161b22; }
  tbody tr:nth-child(odd)  { background: #0d1117; }
  tbody tr:nth-child(even) { background: #111720; }
  tbody tr:hover { background: #1c2333; }
  tbody tr.actor-hit { border-left: 3px solid #f85149; }
  tbody td { padding: 9px 12px; vertical-align: top; }

  /* ── Severity badges ──────────────────────────────────────────── */
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    font-family: "SFMono-Regular", Consolas, monospace;
  }
  .badge-CRITICAL { background: #3d0f0f; color: #f85149; border: 1px solid #f85149; }
  .badge-HIGH     { background: #2d1a00; color: #e3b341; border: 1px solid #e3b341; }
  .badge-MEDIUM   { background: #1f2400; color: #d29922; border: 1px solid #d29922; }
  .badge-LOW      { background: #161b22; color: #8b949e; border: 1px solid #30363d; }
  .badge-UNKNOWN  { background: #161b22; color: #6e7681; border: 1px solid #21262d; }

  /* ── Tactic pills ─────────────────────────────────────────────── */
  .tactic {
    display: inline-block;
    background: #1f2937;
    border: 1px solid #374151;
    border-radius: 3px;
    padding: 1px 6px;
    font-size: 10px;
    color: #9ca3af;
    margin: 1px 2px 1px 0;
    white-space: nowrap;
  }

  /* ── Group chips ──────────────────────────────────────────────── */
  .group-chip {
    display: inline-block;
    background: #2d1214;
    border: 1px solid #f85149;
    border-radius: 3px;
    padding: 1px 6px;
    font-size: 10px;
    color: #ffa198;
    margin: 1px 2px 1px 0;
    white-space: nowrap;
  }

  /* ── Coverage bar ─────────────────────────────────────────────── */
  .coverage-bar-wrap {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 16px 20px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 16px;
  }
  .coverage-label { font-size: 12px; color: #8b949e; min-width: 120px; }
  .bar-track {
    flex: 1;
    height: 8px;
    background: #21262d;
    border-radius: 4px;
    overflow: hidden;
  }
  .bar-fill {
    height: 100%;
    border-radius: 4px;
    background: linear-gradient(90deg, #00ff88, #00cc6a);
  }
  .coverage-pct {
    font-family: "SFMono-Regular", Consolas, monospace;
    font-size: 14px;
    font-weight: 700;
    color: #00ff88;
    min-width: 46px;
    text-align: right;
  }

  /* ── Empty state ──────────────────────────────────────────────── */
  .empty { color: #8b949e; font-style: italic; padding: 16px 0; }

  /* ── Footer ───────────────────────────────────────────────────── */
  .footer {
    margin-top: 64px;
    padding-top: 20px;
    border-top: 1px solid #21262d;
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 11px;
    color: #6e7681;
  }
  .footer .brand { color: #00ff88; font-weight: 600; }

  /* ── Print / PDF tweaks ───────────────────────────────────────── */
  @media print {
    body { background: #0d1117 !important; -webkit-print-color-adjust: exact; }
    .page { padding: 20px 24px; }
    .summary-grid { grid-template-columns: repeat(5, 1fr); }
  }
  @page { size: A4; margin: 0; }
</style>
</head>
<body>
<div class="page">

  <!-- ── Header ─────────────────────────────────────────────────── -->
  <div class="header">
    <div>
      <div class="logo">// deadband</div>
      <div class="logo-sub">ICS/OT Threat Intelligence Mapper</div>
    </div>
    <div class="header-meta">
      <div class="report-title">Threat Intelligence Report</div>
      <div class="meta-row">Vendor / Keyword&nbsp;&nbsp;<span>{{ vendor }}</span></div>
      <div class="meta-row">Platform Analysed&nbsp;&nbsp;<span>{{ platform | upper }}</span></div>
      <div class="meta-row">Generated&nbsp;&nbsp;<span>{{ generated_at }}</span></div>
    </div>
  </div>

  <!-- ── Executive Summary ──────────────────────────────────────── -->
  <div class="section">
    <h2>Executive Summary</h2>

    <div class="summary-grid">
      <div class="stat-card">
        <span class="stat-value">{{ total_cves }}</span>
        <div class="stat-label">CVEs Collected</div>
      </div>
      <div class="stat-card">
        <span class="stat-value">{{ total_techniques }}</span>
        <div class="stat-label">Unique Techniques</div>
      </div>
      <div class="stat-card">
        <span class="stat-value">{{ coverage_pct }}%</span>
        <div class="stat-label">Coverage</div>
      </div>
      <div class="stat-card">
        <span class="stat-value danger">{{ blind_spots }}</span>
        <div class="stat-label">Blind Spots</div>
      </div>
      <div class="stat-card">
        <span class="stat-value warn">{{ critical_cve_count }}</span>
        <div class="stat-label">Critical CVEs</div>
      </div>
    </div>

    <div class="coverage-bar-wrap">
      <span class="coverage-label">{{ platform | upper }} Detection Coverage</span>
      <div class="bar-track">
        <div class="bar-fill" style="width: {{ coverage_pct }}%;"></div>
      </div>
      <span class="coverage-pct">{{ coverage_pct }}%</span>
    </div>

    {% if top_actors %}
    <div class="threat-actors">
      <h3>Top Threat Actors in Profile</h3>
      <div class="actor-list">
        {% for actor in top_actors %}
        <span class="actor-pill nation-state">{{ actor }}</span>
        {% endfor %}
      </div>
    </div>
    {% endif %}
  </div>

  <!-- ── Blind Spot Analysis ────────────────────────────────────── -->
  <div class="section">
    <h2>Blind Spot Analysis</h2>
    <p class="dim" style="margin-bottom:14px; font-size:12px;">
      Techniques present in the threat profile that <strong style="color:#f85149">{{ platform | upper }}</strong>
      cannot detect. Rows with known threat actor involvement are highlighted.
    </p>

    {% if gap_techniques %}
    <table>
      <thead>
        <tr>
          <th style="width:80px">ID</th>
          <th style="width:200px">Technique</th>
          <th>Tactics</th>
          <th>Threat Actors</th>
          <th style="width:80px">CVEs</th>
        </tr>
      </thead>
      <tbody>
        {% for tech in gap_techniques %}
        <tr class="{{ 'actor-hit' if tech.groups else '' }}">
          <td><a class="mono accent" href="{{ tech.url or '#' }}" style="text-decoration:none;">{{ tech.technique_id }}</a></td>
          <td>{{ tech.name }}</td>
          <td>
            {% for tactic in tech.tactics %}
            <span class="tactic">{{ tactic | replace('-', ' ') }}</span>
            {% endfor %}
          </td>
          <td>
            {% if tech.groups %}
              {% for grp in tech.groups %}
              <span class="group-chip">{{ grp.name }}</span>
              {% endfor %}
            {% else %}
              <span class="dim">—</span>
            {% endif %}
          </td>
          <td class="mono dim">{{ tech.cve_ids | length }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p class="empty">No blind spots detected — {{ platform | upper }} covers all techniques in this threat profile.</p>
    {% endif %}
  </div>

  <!-- ── CVE List ───────────────────────────────────────────────── -->
  <div class="section">
    <h2>Top CVEs by Severity</h2>
    <p class="dim" style="margin-bottom:14px; font-size:12px;">
      Top {{ top_cves | length }} CVEs by CVSS score. "Matched" = number of ATT&CK ICS techniques
      the CVE description was linked to.
    </p>

    {% if top_cves %}
    <table>
      <thead>
        <tr>
          <th style="width:140px">CVE ID</th>
          <th style="width:90px">Severity</th>
          <th style="width:60px">Score</th>
          <th style="width:70px">Source</th>
          <th style="width:60px">Matched</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        {% for cve in top_cves %}
        <tr>
          <td class="mono accent" style="white-space:nowrap">{{ cve.cve_id }}</td>
          <td>
            <span class="badge badge-{{ cve.cvss_severity or 'UNKNOWN' }}">
              {{ cve.cvss_severity or 'N/A' }}
            </span>
          </td>
          <td class="mono" style="text-align:right; padding-right:20px;">
            {{ "%.1f"|format(cve.cvss_score) if cve.cvss_score else '—' }}
          </td>
          <td class="dim">{{ cve.source or '—' }}</td>
          <td class="mono" style="text-align:center;">
            {% if cve.techniques | length > 0 %}
            <span class="accent">{{ cve.techniques | length }}</span>
            {% else %}
            <span class="dim">0</span>
            {% endif %}
          </td>
          <td class="dim" style="font-size:11px; max-width:380px;">
            {{ cve.description | truncate(160) if cve.description else '—' }}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p class="empty">No CVEs with CVSS scores available.</p>
    {% endif %}
  </div>

  <!-- ── Covered Techniques ─────────────────────────────────────── -->
  <div class="section">
    <h2>Covered Techniques</h2>
    <p class="dim" style="margin-bottom:14px; font-size:12px;">
      Techniques in the threat profile that {{ platform | upper }} can detect.
    </p>

    {% if covered_techniques %}
    <table>
      <thead>
        <tr>
          <th style="width:80px">ID</th>
          <th style="width:220px">Technique</th>
          <th>Tactics</th>
          <th>Threat Actors</th>
        </tr>
      </thead>
      <tbody>
        {% for tech in covered_techniques %}
        <tr>
          <td><a class="mono accent" href="{{ tech.url or '#' }}" style="text-decoration:none;">{{ tech.technique_id }}</a></td>
          <td>{{ tech.name }}</td>
          <td>
            {% for tactic in tech.tactics %}
            <span class="tactic">{{ tactic | replace('-', ' ') }}</span>
            {% endfor %}
          </td>
          <td>
            {% if tech.groups %}
              {% for grp in tech.groups %}
              <span class="group-chip">{{ grp.name }}</span>
              {% endfor %}
            {% else %}
              <span class="dim">—</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% else %}
    <p class="empty">No techniques from this threat profile are covered by {{ platform | upper }}.</p>
    {% endif %}
  </div>

  <!-- ── Footer ─────────────────────────────────────────────────── -->
  <div class="footer">
    <div>Generated by <span class="brand">// deadband</span> — ICS/OT Threat Intelligence Mapper</div>
    <div class="mono">{{ generated_at }}</div>
  </div>

</div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Helper: extract top threat actors across the full threat profile
# ---------------------------------------------------------------------------

def _collect_top_actors(gap_report: dict, top_n: int = 10) -> list[str]:
    """
    Pulls together all unique threat actor names mentioned across both gap
    and covered techniques, sorted by how many techniques they appear in.
    Returns the top N names — just the names, no extra data.
    """
    actor_hits: dict[str, int] = {}
    all_techniques = gap_report.get("gap_techniques", []) + gap_report.get("covered_techniques", [])
    for tech in all_techniques:
        for grp in tech.get("groups", []):
            name = grp.get("name", "")
            if name:
                actor_hits[name] = actor_hits.get(name, 0) + 1

    # sort by frequency descending, return just names
    return [name for name, _ in sorted(actor_hits.items(), key=lambda x: x[1], reverse=True)][:top_n]


# ---------------------------------------------------------------------------
# Helper: sort CVEs by CVSS score for the top-20 table
# ---------------------------------------------------------------------------

def _top_cves_by_score(mapped_results: list[dict], limit: int = 20) -> list[dict]:
    """
    Sorts mapped CVE results by CVSS score descending and returns the top N.
    CVEs without a score are pushed to the bottom.
    """
    return sorted(
        mapped_results,
        key=lambda r: r.get("cvss_score") or 0.0,
        reverse=True,
    )[:limit]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_report(
    vendor: str,
    platform: str,
    mapped_results: list[dict],
    gap_report: dict,
    output_path: str = "reports/deadband_report.pdf",
) -> str:
    """
    Builds an HTML report from the collector/mapper/gap_analyzer outputs and
    renders it to PDF using WeasyPrint.

    Args:
        vendor:         The keyword used for collection (e.g. "Siemens").
        platform:       The platform name that was gap-analysed (e.g. "claroty").
        mapped_results: Output of mapper.map_cves_to_techniques().
        gap_report:     Output of gap_analyzer.analyze_gaps().
        output_path:    Where to write the PDF. Parent directory is created
                        if it doesn't exist. Defaults to reports/deadband_report.pdf.

    Returns:
        The absolute path to the generated PDF file.

    Raises:
        RuntimeError: If WeasyPrint fails to render the PDF.
    """
    print(f"[Reporter] Building report for vendor='{vendor}', platform='{platform}' ...")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # ── Derived stats ──────────────────────────────────────────────────────
    total_cves = len(mapped_results)
    total_techniques = gap_report.get("total_techniques", 0)
    coverage_pct = gap_report.get("coverage_pct", 0.0)
    blind_spots = gap_report.get("gaps", 0)
    critical_cve_count = sum(
        1 for r in mapped_results
        if (r.get("cvss_severity") or "").upper() == "CRITICAL"
    )
    top_actors = _collect_top_actors(gap_report)
    top_cves = _top_cves_by_score(mapped_results)

    # ── Render HTML ────────────────────────────────────────────────────────
    print("[Reporter] Rendering HTML template ...")
    env = Environment(loader=BaseLoader())
    template = env.from_string(_TEMPLATE)
    html_str = template.render(
        vendor=vendor,
        platform=platform,
        generated_at=generated_at,
        total_cves=total_cves,
        total_techniques=total_techniques,
        coverage_pct=coverage_pct,
        blind_spots=blind_spots,
        critical_cve_count=critical_cve_count,
        top_actors=top_actors,
        gap_techniques=gap_report.get("gap_techniques", []),
        covered_techniques=gap_report.get("covered_techniques", []),
        top_cves=top_cves,
    )

    # ── Write PDF via WeasyPrint ───────────────────────────────────────────
    abs_path = os.path.abspath(output_path)
    print(f"[Reporter] Rendering PDF → {abs_path} ...")
    try:
        WeasyHTML(string=html_str).write_pdf(abs_path)
    except Exception as exc:
        raise RuntimeError(f"WeasyPrint failed to render the PDF: {exc}") from exc

    print(f"[Reporter] Done. Report saved to {abs_path}")
    return abs_path
