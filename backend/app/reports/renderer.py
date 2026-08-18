"""Markdown + HTML SRE RCA report rendering."""

from __future__ import annotations

import html
import json
import math
from pathlib import Path

from jinja2 import Template

from app.models.schemas import DevOpsReport

MD_TEMPLATE = Template(
    """# AI DevOps SRE Report — {{ report.repo_url }}

**Report ID:** {{ report.id }}  
**Job ID:** {{ report.job_id }}  
**Branch:** {{ report.branch or "default" }}  
**Generated:** {{ report.created_at }}  
**Health score:** {{ report.health_score }}/100  
**Risk level:** {{ report.risk_level }}

## Executive summary

{{ report.executive_summary }}

{% if report.primary_root_cause %}
## Primary root cause

{{ report.primary_root_cause }}
{% endif %}

{% if report.correlated_timeline %}
## Correlated timeline

{% for item in report.correlated_timeline %}- {{ item }}
{% endfor %}
{% endif %}

{% if report.domain_coverage %}
## Domain coverage

{% for d in report.domain_coverage %}- **{{ d.domain }}**: {{ d.status }}{% if d.notes %} — {{ d.notes }}{% endif %}
{% endfor %}
{% endif %}

## Quick wins

{% for item in report.quick_wins %}- {{ item }}
{% endfor %}

## Roadmap

{% for item in report.roadmap %}{{ loop.index }}. {{ item }}
{% endfor %}

{% for section in report.sections %}
## {{ section.title }}

{{ section.summary }}

{% for f in section.findings %}
### [{{ f.severity | upper }}] {{ f.title }} (confidence {{ f.confidence_score }}%)

- **Category:** {{ f.category }}
- **Executive summary:** {{ f.executive_summary or f.description }}
- **Affected services:** {{ f.affected_services | join(', ') if f.affected_services else 'n/a' }}
- **What happened:** {{ f.what_happened or f.description }}
- **Root cause:** {{ f.root_cause or 'n/a' }}
{% if f.evidence %}- **Evidence:** {{ f.evidence }}
{% endif %}- **Impact:** {{ f.impact or 'n/a' }}
- **Recommended fixes:**
{% for fix in f.recommended_fixes %}  - {{ fix }}
{% else %}  - {{ f.recommendation }}
{% endfor %}- **Preventive measures:**
{% for p in f.preventive_measures %}  - {{ p }}
{% else %}  - n/a
{% endfor %}- **Related components:** {{ f.related_components | join(', ') if f.related_components else 'n/a' }}
- **File:** {{ f.file_path or 'n/a' }}
- **Effort:** {{ f.effort or 'n/a' }}

{% endfor %}
{% endfor %}

## Collected facts (compact)

```json
{{ facts_json }}
```
"""
)

HTML_TEMPLATE = Template(
    """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>AI DevOps SRE Report {{ report.id }}</title>
<style>
  :root { --bg:#0f1419; --card:#1a222c; --text:#e7eef7; --muted:#8b9bb0; --accent:#3dd6c6; --crit:#ff5c7a; --high:#ff9f43; --med:#f6c945; --low:#6bcb77; }
  body { margin:0; font-family: "IBM Plex Sans", system-ui, sans-serif; background: radial-gradient(1200px 600px at 10% -10%, #1d3a3a 0%, var(--bg) 55%); color: var(--text); }
  main { max-width: 960px; margin: 0 auto; padding: 48px 24px 80px; }
  h1 { font-family: "IBM Plex Serif", Georgia, serif; font-weight: 600; font-size: 2rem; }
  .meta { color: var(--muted); display:flex; flex-wrap:wrap; gap:12px 20px; margin-bottom: 24px; }
  .score { display:inline-flex; align-items:center; gap:8px; background: var(--card); padding: 8px 14px; border-radius: 8px; }
  section { background: color-mix(in srgb, var(--card) 88%, transparent); border: 1px solid #2a3542; border-radius: 12px; padding: 20px 22px; margin: 18px 0; }
  .finding { border-left: 3px solid var(--med); padding-left: 14px; margin: 16px 0; }
  .critical { border-color: var(--crit); } .high { border-color: var(--high); } .medium { border-color: var(--med); } .low,.info { border-color: var(--low); }
  .badge { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: var(--muted); }
  ul { margin: 6px 0 10px 18px; }
  a { color: var(--accent); }
</style>
</head>
<body>
<main>
  <p class="badge">AI DevOps · SRE RCA</p>
  <h1>Investigation report</h1>
  <div class="meta">
    <span>{{ report.repo_url }}</span>
    <span>branch: {{ report.branch or "default" }}</span>
    <span class="score">Health {{ report.health_score }}/100 · {{ report.risk_level }}</span>
  </div>
  <section>
    <h2>Executive summary</h2>
    <p>{{ report.executive_summary }}</p>
    {% if report.primary_root_cause %}<p><strong>Primary root cause:</strong> {{ report.primary_root_cause }}</p>{% endif %}
  </section>
  {% for section in report.sections %}
  <section>
    <h2>{{ section.title }}</h2>
    <p>{{ section.summary }}</p>
    {% for f in section.findings %}
    <div class="finding {{ f.severity }}">
      <div class="badge">{{ f.severity }} · {{ f.category }} · {{ f.confidence_score }}% confidence</div>
      <h3>{{ f.title }}</h3>
      <p>{{ f.executive_summary or f.what_happened or f.description }}</p>
      <p><strong>Root cause:</strong> {{ f.root_cause or "n/a" }}</p>
      <p><strong>Impact:</strong> {{ f.impact or "n/a" }}</p>
      {% if f.evidence %}<p><strong>Evidence:</strong> {{ f.evidence }}</p>{% endif %}
      <p><strong>Fixes:</strong></p>
      <ul>{% for fix in f.recommended_fixes %}<li>{{ fix }}</li>{% else %}<li>{{ f.recommendation }}</li>{% endfor %}</ul>
      {% if f.file_path %}<p><code>{{ f.file_path }}</code></p>{% endif %}
    </div>
    {% endfor %}
  </section>
  {% endfor %}
</main>
</body>
</html>
"""
)


def write_report_files(report: DevOpsReport, reports_dir: Path) -> dict[str, str]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    facts_json = json.dumps(report.collected_facts, indent=2, default=str)
    md = MD_TEMPLATE.render(report=report, facts_json=facts_json)
    html = HTML_TEMPLATE.render(report=report)
    md_path = reports_dir / f"{report.id}.md"
    html_path = reports_dir / f"{report.id}.html"
    json_path = reports_dir / f"{report.id}.json"
    md_path.write_text(md, encoding="utf-8")
    html_path.write_text(html, encoding="utf-8")
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return {"markdown": str(md_path), "html": str(html_path), "json": str(json_path)}


WSO2_MD = Template(
    """# WSO2 APIM SRE Log Analysis

**Report ID:** {{ report.id }}  
**Job ID:** {{ report.job_id }}  
**Generated:** {{ report.created_at }}  
**Health:** {{ report.health_score }}/100 · **Risk:** {{ report.risk_level }}

## Context
- OS: {{ report.context.os }}
- APIM: {{ report.context.apim_version }}
- EI: {{ report.context.ei_version }}
- DB: {{ report.context.db_version }}
- IPs: {{ report.context.ip_addresses }}
- Compute allocation: {{ report.context.compute_allocation }}
- Compute consumption: {{ report.context.infra_compute_consumption }}

## Executive summary
{{ report.executive_summary }}

{% if report.log_coverage and report.log_coverage.file_stats %}
## Per log file
{% for f in report.log_coverage.file_stats %}
### {{ f.display_name or f.file }} — `{{ f.ip or "IP not mapped" }}`
- Total transac: {{ f.total_transactions }}
- Success: {{ f.total_success }}
- Error: {{ f.total_errors }}
- Error %: {{ f.error_pct }}%
{% endfor %}
{% endif %}

{% if report.primary_root_cause %}## Primary root cause
{{ report.primary_root_cause }}
{% endif %}

## Documentation
{% for d in report.doc_references %}- {{ d }}
{% endfor %}

## Log coverage
```json
{{ coverage_json }}
```

## Errors

{% for e in report.errors %}
### [{{ e.severity | upper }}] {{ e.error }}

- **Log type:** {{ e.log_type }}
- **Logger:** {{ e.logger or 'n/a' }}
- **Subsystem:** {{ e.subsystem or 'n/a' }}
- **Error source:** {{ e.error_source or 'n/a' }}
- **Functional error:** {{ e.functional_error or 'n/a' }}
- **Exception (root cause signal):** {{ e.exception_type or 'n/a' }}
- **Source:** {{ e.source_file or 'n/a' }}
- **Description:** {{ e.description }}
- **Possible occurrence:** {{ e.possible_occurrence }}
- **Evidence:** {{ e.evidence or 'n/a' }}
- **VA correlation:** {{ e.va_correlation or 'n/a' }}
- **Confidence:** {{ e.confidence_score }}%
- **Remedial actions:**
{% for a in e.remedial_actions %}  - {{ a }}
{% endfor %}- **WSO2 doc refs:**
{% for r in e.wso2_doc_refs %}  - {{ r }}
{% endfor %}
{% endfor %}

## Vulnerability Assessment correlations

{% for v in report.va_correlations %}
### {{ v.va_finding }} ({{ v.risk }})
{{ v.correlation_notes }}
- Related errors: {{ v.related_log_errors | join(', ') }}
- Actions:
{% for a in v.recommended_actions %}  - {{ a }}
{% endfor %}
{% endfor %}

## Quick wins
{% for q in report.quick_wins %}- {{ q }}
{% endfor %}

## Roadmap
{% for r in report.roadmap %}{{ loop.index }}. {{ r }}
{% endfor %}
"""
)

SEV_COLORS = {
    "critical": "#b42318",
    "high": "#c45c26",
    "medium": "#b8860b",
    "low": "#2f6b4f",
    "info": "#3d5a80",
}


def _severity_counts(errors: list) -> list[dict]:
    order = ["critical", "high", "medium", "low", "info"]
    counts = {s: 0 for s in order}
    for e in errors:
        sev = getattr(e.severity, "value", e.severity) if e.severity is not None else "medium"
        sev = str(sev).lower()
        if sev not in counts:
            counts[sev] = 0
        counts[sev] += 1
    return [
        {"label": s, "value": counts[s], "color": SEV_COLORS.get(s, "#5a6b60")}
        for s in order
        if counts.get(s, 0) > 0
    ]


def _pie_svg(slices: list[dict], size: int = 220) -> str:
    total = sum(s["value"] for s in slices) or 1
    cx = cy = size / 2
    r = size * 0.38
    if len(slices) == 1:
        return (
            f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">'
            f'<circle cx="{cx}" cy="{cy}" r="{r}" fill="{slices[0]["color"]}"/>'
            f'<circle cx="{cx}" cy="{cy}" r="{r * 0.52}" fill="#fff"/>'
            f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" font-size="28" font-weight="700" '
            f'font-family="DM Sans,Segoe UI,sans-serif" fill="#102018">{total}</text>'
            f'<text x="{cx}" y="{cy + 18}" text-anchor="middle" font-size="12" '
            f'font-family="DM Sans,Segoe UI,sans-serif" fill="#5a6b60">issues</text></svg>'
        )

    angle = -90.0
    parts = []
    for s in slices:
        sweep = (s["value"] / total) * 360.0
        a0 = math.radians(angle)
        a1 = math.radians(angle + sweep)
        x0, y0 = cx + r * math.cos(a0), cy + r * math.sin(a0)
        x1, y1 = cx + r * math.cos(a1), cy + r * math.sin(a1)
        large = 1 if sweep > 180 else 0
        parts.append(
            f'<path d="M {cx} {cy} L {x0:.2f} {y0:.2f} A {r:.2f} {r:.2f} 0 {large} 1 {x1:.2f} {y1:.2f} Z" '
            f'fill="{s["color"]}"/>'
        )
        angle += sweep
    return (
        f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}">'
        + "".join(parts)
        + f'<circle cx="{cx}" cy="{cy}" r="{r * 0.52}" fill="#fff"/>'
        + f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" font-size="28" font-weight="700" '
        + f'font-family="DM Sans,Segoe UI,sans-serif" fill="#102018">{total}</text>'
        + f'<text x="{cx}" y="{cy + 18}" text-anchor="middle" font-size="12" '
        + f'font-family="DM Sans,Segoe UI,sans-serif" fill="#5a6b60">issues</text></svg>'
    )


def _bars_html(rows: list[dict], title: str) -> str:
    max_v = max((r["value"] for r in rows), default=1) or 1
    items = []
    for r in rows:
        pct = max(8, int((r["value"] / max_v) * 100))
        label = html.escape(str(r["label"])[:48])
        items.append(
            f'<div class="bar-row"><div class="bar-label" title="{label}">{label}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{pct}%;background:{r["color"]}"></div></div>'
            f'<div class="bar-val">{html.escape(str(r["value"]))}</div></div>'
        )
    return f'<div class="chart-card"><h3>{html.escape(title)}</h3>{"".join(items)}</div>'


def render_wso2_html(report) -> str:
    """Standalone HTML report with fonts, layout, pie + bar charts."""
    errors = list(report.errors or [])
    sev = _severity_counts(errors)
    pie = _pie_svg(sev) if sev else ""
    legend = "".join(
        f'<li><span class="swatch" style="background:{s["color"]}"></span>'
        f'<span class="cap">{html.escape(s["label"])}</span><strong>{s["value"]}</strong></li>'
        for s in sev
    )
    issue_bars = []
    order = ["critical", "high", "medium", "low", "info"]
    for e in errors[:10]:
        sev_name = str(getattr(e.severity, "value", e.severity) or "medium").lower()
        weight = max(1, len(order) - (order.index(sev_name) if sev_name in order else 2))
        conf = int(getattr(e, "confidence_score", None) or 70)
        issue_bars.append(
            {
                "label": (e.error or "Issue")[:48],
                "value": round(weight * (conf / 20), 1),
                "color": SEV_COLORS.get(sev_name, "#5a6b60"),
            }
        )
    ctx = report.context
    risk = html.escape(str(getattr(report.risk_level, "value", report.risk_level) or "medium"))
    docs = "".join(
        f'<li><a href="{html.escape(d)}">{html.escape(d)}</a></li>' for d in (report.doc_references or [])
    )
    error_cards = []
    for e in errors:
        sev_name = html.escape(str(getattr(e.severity, "value", e.severity) or "medium").lower())
        actions = "".join(f"<li>{html.escape(a)}</li>" for a in (e.remedial_actions or []))
        configs = "".join(f"<li>{html.escape(c)}</li>" for c in (e.config_checks or []))
        flow = "".join(f"<li>{html.escape(s)}</li>" for s in (e.call_flow or []))
        customers = html.escape(", ".join(e.impacted_customers or []) or "n/a")
        impact = ""
        if e.failure_count is not None and e.failure_total is not None:
            impact = (
                f"<p><strong>Impact:</strong> {int(e.failure_count)} of {int(e.failure_total)} failures"
                f"{f' ({e.impact_pct}%)' if e.impact_pct is not None else ''}"
                f"{' — ' + html.escape(e.impact_summary) if e.impact_summary else ''}</p>"
            )
        tech = (
            f'<p class="muted">Technical signal: {html.escape(e.technical_name)}'
            f"{' · ' + html.escape(e.exception_type) if e.exception_type else ''}</p>"
            if e.technical_name and e.technical_name != e.error
            else ""
        )
        error_cards.append(
            f"""
<article class="issue {sev_name}">
  <div class="issue-head"><span class="badge {sev_name}">{sev_name}</span><h3>{html.escape(e.error or "")}</h3></div>
  {tech}
  {impact}
  {"<p><strong>In plain words:</strong> " + html.escape(e.plain_meaning) + "</p>" if e.plain_meaning else ""}
  {"<p><strong>Call flow:</strong></p><ol class='flow'>" + flow + "</ol>" if flow else ""}
  <p><strong>Impacted customers / partners:</strong> {customers}</p>
  {"<p><strong>Configs to check:</strong></p><ul>" + configs + "</ul>" if configs else ""}
  <p>{html.escape(e.description or "")}</p>
  <dl>
    <div><dt>Possible occurrence</dt><dd>{html.escape(e.possible_occurrence or "n/a")}</dd></div>
    <div><dt>Logger</dt><dd>{html.escape(e.logger or "n/a")}</dd></div>
    <div><dt>Subsystem</dt><dd>{html.escape(e.subsystem or "n/a")}</dd></div>
    <div><dt>Exception</dt><dd>{html.escape(e.exception_type or "n/a")}</dd></div>
    <div><dt>Confidence</dt><dd>{int(e.confidence_score or 0)}%</dd></div>
  </dl>
  {"<h4>Remedial actions</h4><ul>" + actions + "</ul>" if actions else ""}
</article>"""
        )
    wins = "".join(f"<li>{html.escape(q)}</li>" for q in (report.quick_wins or []))
    roadmap = "".join(f"<li>{html.escape(r)}</li>" for r in (report.roadmap or []))
    apim = html.escape(str(getattr(ctx, "apim_version", None) or "n/a"))
    mi = html.escape(str(getattr(ctx, "ei_version", None) or "n/a"))
    db = html.escape(str(getattr(ctx, "db_version", None) or "n/a"))
    os_name = html.escape(str(getattr(ctx, "os", None) or "n/a"))
    env = html.escape(str(getattr(ctx, "environment", None) or "n/a"))
    summary = html.escape(report.executive_summary or "")
    root = html.escape(report.primary_root_cause or "") if report.primary_root_cause else ""
    created = html.escape(str(report.created_at))
    rid = html.escape(str(report.id))

    cust_sum = (report.log_coverage or {}).get("impacted_customers_summary") or {}
    cust_headline = html.escape(str(cust_sum.get("headline") or ""))
    cust_rows = ""
    for row in (cust_sum.get("customers") or [])[:12]:
        cust_rows += (
            f"<tr><td>{html.escape(str(row.get('customer') or ''))}</td>"
            f"<td>{int(row.get('failure_hits') or 0)}</td></tr>"
        )
    app_rows = "".join(
        f"<li>{html.escape(str(a.get('name') or ''))} "
        f"<strong>({int(a.get('count') or 0)})</strong></li>"
        for a in (cust_sum.get("top_apps") or [])[:8]
    )
    api_rows = "".join(
        f"<li>{html.escape(str(a.get('name') or ''))} "
        f"<strong>({int(a.get('count') or 0)})</strong></li>"
        for a in (cust_sum.get("top_apis") or [])[:8]
    )
    customer_section = ""
    if cust_headline or cust_rows:
        customer_section = f"""
    <section class="chart-card" style="margin-bottom:22px">
      <h3>Who is impacted</h3>
      <p><strong>{cust_headline or "See table below"}</strong></p>
      {"<table class='cust'><thead><tr><th>Customer / partner</th><th>Failure hits</th></tr></thead><tbody>" + cust_rows + "</tbody></table>" if cust_rows else ""}
      <div class="grid2" style="margin-top:12px">
        {"<div><h4>Top apps</h4><ul>" + app_rows + "</ul></div>" if app_rows else "<div></div>"}
        {"<div><h4>Top APIs</h4><ul>" + api_rows + "</ul></div>" if api_rows else "<div></div>"}
      </div>
    </section>"""

    file_stats = (report.log_coverage or {}).get("file_stats") or []
    file_cards = []
    for row in file_stats:
        pct = float(row.get("error_pct") or 0)
        name = html.escape(str(row.get("display_name") or row.get("file") or "log"))
        ip = html.escape(str(row.get("ip") or "IP not mapped"))
        product = html.escape(str(row.get("product") or ""))
        file_cards.append(
            f"""
      <article class="file-stat">
        <div class="file-stat-head">
          <h4>{name}</h4>
          <span class="ip">{ip}</span>
        </div>
        <p class="muted">{product} · {html.escape(str(row.get("log_type") or ""))}</p>
        <ul class="file-metrics">
          <li><span>Total transac</span><strong>{int(row.get("total_transactions") or 0):,}</strong></li>
          <li><span>Success</span><strong>{int(row.get("total_success") or 0):,}</strong></li>
          <li><span>Error</span><strong>{int(row.get("total_errors") or 0):,}</strong></li>
        </ul>
        <div class="pct">Error rate <strong>{pct:.2f}%</strong></div>
      </article>"""
        )
    file_section = ""
    if file_cards:
        file_section = f"""
    <h2>Per log file (node)</h2>
    <div class="file-grid">{"".join(file_cards)}</div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>WSO2 APIM/MI Report · {rid}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Instrument+Serif:ital@0;1&display=swap" rel="stylesheet" />
  <style>
    :root {{
      --ink:#102018; --muted:#5a6b60; --paper:#f3f6f2; --line:rgba(16,32,24,.12);
      --accent:#0f7a5a; --crit:#b42318; --high:#c45c26; --med:#b8860b; --low:#2f6b4f; --info:#3d5a80;
    }}
    * {{ box-sizing:border-box; }}
    body {{
      margin:0; color:var(--ink); font-family:"DM Sans",Segoe UI,sans-serif;
      background:linear-gradient(180deg,#e8efe8 0%, var(--paper) 40%, #eef2ea 100%);
      line-height:1.55;
    }}
    .wrap {{ max-width:980px; margin:0 auto; padding:36px 20px 64px; }}
    .brand {{ font-family:"Instrument Serif",Georgia,serif; font-size:2.2rem; margin:0 0 6px; }}
    .brand span {{ color:var(--accent); font-style:italic; }}
    .meta {{ color:var(--muted); font-size:.92rem; margin-bottom:22px; }}
    .hero-card {{
      display:grid; grid-template-columns:1.4fr .6fr; gap:18px; align-items:center;
      background:#fff; border:1px solid var(--line); border-radius:18px; padding:22px;
      box-shadow:0 18px 40px rgba(16,32,24,.06); margin-bottom:22px;
    }}
    h1 {{ font-family:"Instrument Serif",Georgia,serif; font-weight:400; font-size:1.9rem; margin:0 0 10px; }}
    .score {{
      width:110px; height:110px; border-radius:50%; margin:0 auto;
      display:grid; place-items:center; font-size:2rem; font-weight:700;
      background:conic-gradient(var(--accent) calc({int(report.health_score)} * 1%), rgba(16,32,24,.08) 0);
      position:relative;
    }}
    .score::before {{
      content:""; position:absolute; inset:10px; border-radius:50%; background:#fff;
    }}
    .score span {{ position:relative; z-index:1; }}
    .badge {{
      display:inline-flex; text-transform:uppercase; font-size:.72rem; font-weight:700;
      letter-spacing:.04em; padding:4px 10px; border-radius:999px; border:1px solid var(--line);
    }}
    .badge.critical {{ color:var(--crit); background:rgba(180,35,24,.08); }}
    .badge.high {{ color:var(--high); background:rgba(196,92,38,.1); }}
    .badge.medium {{ color:var(--med); background:rgba(184,134,11,.12); }}
    .badge.low {{ color:var(--low); background:rgba(47,107,79,.1); }}
    .badge.info {{ color:var(--info); background:rgba(61,90,128,.1); }}
    .grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:16px; margin:18px 0 26px; }}
    .chart-card {{
      background:#fff; border:1px solid var(--line); border-radius:16px; padding:16px 18px;
    }}
    .chart-card h3 {{ margin:0 0 12px; font-size:1rem; }}
    .pie-wrap {{ display:grid; grid-template-columns:220px 1fr; gap:12px; align-items:center; }}
    .pie-wrap ul {{ list-style:none; margin:0; padding:0; display:grid; gap:8px; }}
    .pie-wrap li {{ display:grid; grid-template-columns:12px 1fr auto; gap:8px; align-items:center; font-size:.88rem; }}
    .swatch {{ width:12px; height:12px; border-radius:3px; display:inline-block; }}
    .cap {{ text-transform:capitalize; }}
    .bar-row {{ display:grid; grid-template-columns:1.1fr 1.5fr 42px; gap:8px; align-items:center; margin-bottom:10px; }}
    .bar-label {{ font-size:.8rem; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
    .bar-track {{ height:12px; border-radius:999px; background:rgba(16,32,24,.08); overflow:hidden; }}
    .bar-fill {{ height:100%; border-radius:999px; }}
    .bar-val {{ font-size:.8rem; font-weight:700; text-align:right; color:var(--muted); }}
    .ctx {{
      display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin-bottom:22px;
    }}
    .ctx div {{ background:#fff; border:1px solid var(--line); border-radius:12px; padding:12px 14px; }}
    .ctx dt {{ font-size:.75rem; color:var(--muted); text-transform:uppercase; letter-spacing:.04em; }}
    .ctx dd {{ margin:4px 0 0; font-weight:600; word-break:break-word; }}
    .issue {{
      background:#fff; border:1px solid var(--line); border-radius:14px; padding:16px 18px; margin-bottom:12px;
    }}
    .issue-head {{ display:flex; gap:10px; align-items:center; margin-bottom:8px; }}
    .issue-head h3 {{ margin:0; font-size:1.05rem; }}
    .issue dl {{ display:grid; gap:8px; margin:12px 0; }}
    .issue dt {{ font-size:.75rem; color:var(--muted); text-transform:uppercase; letter-spacing:.03em; }}
    .issue dd {{ margin:2px 0 0; }}
    .muted {{ color:var(--muted); font-size:.88rem; }}
    .flow {{ margin:6px 0 12px; padding-left:1.2rem; }}
    table.cust {{ width:100%; border-collapse:collapse; margin-top:10px; font-size:.92rem; }}
    table.cust th, table.cust td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); }}
    table.cust th {{ color:var(--muted); font-size:.75rem; text-transform:uppercase; letter-spacing:.03em; }}
    .file-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(240px,1fr)); gap:14px; margin-bottom:22px; }}
    .file-stat {{ background:#fff; border:1px solid var(--line); border-radius:14px; padding:14px 16px; }}
    .file-stat-head {{ display:flex; justify-content:space-between; gap:8px; align-items:flex-start; }}
    .file-stat h4 {{ margin:0; font-size:.95rem; word-break:break-all; }}
    .file-stat .ip {{ font-family:ui-monospace,monospace; font-size:.8rem; color:var(--accent); white-space:nowrap; }}
    .file-metrics {{ list-style:none; margin:10px 0; padding:0; display:grid; gap:6px; }}
    .file-metrics li {{ display:flex; justify-content:space-between; font-size:.9rem; border-bottom:1px dashed var(--line); padding-bottom:4px; }}
    .file-stat .pct {{ margin-top:8px; font-size:.95rem; }}
    .file-stat .pct strong {{ font-size:1.25rem; }}
    h2 {{ font-family:"Instrument Serif",Georgia,serif; font-weight:400; font-size:1.55rem; margin:28px 0 12px; }}
    a {{ color:var(--accent); }}
    @media (max-width:800px) {{
      .hero-card,.grid2,.pie-wrap,.ctx {{ grid-template-columns:1fr; }}
      .score {{ margin-top:8px; }}
    }}
    @media print {{
      body {{ background:#fff; }}
      .wrap {{ max-width:none; padding:0; }}
      .issue,.chart-card,.hero-card,.ctx div {{ box-shadow:none; }}
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <p class="brand">AI <span>DevOps</span></p>
    <p class="meta">WSO2 APIM / MI report · #{rid} · Generated {created}</p>

    <section class="hero-card">
      <div>
        <span class="badge {risk}">{risk}</span>
        <h1>Health {int(report.health_score)}/100</h1>
        <p>{summary}</p>
        {"<p><strong>Primary root cause:</strong> " + root + "</p>" if root else ""}
      </div>
      <div class="score"><span>{int(report.health_score)}</span></div>
    </section>

    <div class="ctx">
      <div><dt>OS / Env</dt><dd>{os_name} · {env}</dd></div>
      <div><dt>APIM / MI</dt><dd>{apim} / {mi}</dd></div>
      <div><dt>Database</dt><dd>{db}</dd></div>
    </div>

    {customer_section}
    {file_section}

    <h2>Issue visuals</h2>
    <div class="grid2">
      <div class="chart-card">
        <h3>Issues by severity</h3>
        <div class="pie-wrap">{pie}<ul>{legend}</ul></div>
      </div>
      {_bars_html(sev, "Severity counts") if sev else ""}
    </div>
    {_bars_html(issue_bars, "Top issues (severity × confidence)") if issue_bars else ""}

    <h2>Errors ({len(errors)})</h2>
    {"".join(error_cards) if error_cards else "<p>No errors listed.</p>"}

    {"<h2>Quick wins</h2><ul>" + wins + "</ul>" if wins else ""}
    {"<h2>Roadmap</h2><ol>" + roadmap + "</ol>" if roadmap else ""}
    {"<h2>Documentation</h2><ul>" + docs + "</ul>" if docs else ""}
  </div>
</body>
</html>"""


def write_wso2_report_files(report, reports_dir: Path) -> dict[str, str]:
    reports_dir.mkdir(parents=True, exist_ok=True)
    coverage_json = json.dumps(report.log_coverage, indent=2, default=str)
    md = WSO2_MD.render(report=report, coverage_json=coverage_json)
    md_path = reports_dir / f"{report.id}.md"
    json_path = reports_dir / f"{report.id}.json"
    html_path = reports_dir / f"{report.id}.html"
    md_path.write_text(md, encoding="utf-8")
    json_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    html_path.write_text(render_wso2_html(report), encoding="utf-8")
    return {"markdown": str(md_path), "html": str(html_path), "json": str(json_path)}
