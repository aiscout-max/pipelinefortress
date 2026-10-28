"""Render the PipelineFortress metrics dashboard as one self-contained HTML file.

The metrics answer the CISO's questions rather than counting for the sake of it:
- Did the pipeline catch the weaknesses we planted? (catch rate vs the 80% target)
- How fast does a developer hear back? (push -> security verdict)
- Is the signal actionable? (blocking vs baselined, fix availability, noise sources)

Every string that came from a scanner is untrusted and is HTML-escaped; the
page loads nothing from the network.
"""
from __future__ import annotations

import argparse
import json
import sys
import tomllib
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path

from . import SEVERITIES, gate

STAGES = [("secrets", "Secrets"), ("sast", "SAST"), ("sca", "SCA"),
          ("iac", "IaC"), ("container", "Container"), ("dast", "DAST")]
STAGE_LABEL = dict(STAGES)
SEV_ORDER = list(reversed(SEVERITIES))  # CRITICAL first
OWNED_IAC = ("deploy/", "Dockerfile", ".github/", "policies/")
CATCH_TARGET = 0.80


def esc(value: object) -> str:
    return escape(str(value), quote=True)


def tip(rows: list[tuple[str, str, str | None]]) -> str:
    """data-tip payload: [value, label, css colour var or None] per line."""
    return esc(json.dumps(rows))


def fmt_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    return f"{seconds // 60}m {seconds % 60:02d}s" if seconds >= 60 else f"{seconds}s"


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# --------------------------------------------------------------------- metrics

def is_test_path(path: str | None) -> bool:
    path = path or ""
    return path.startswith(("test/", "cypress/")) or ".spec." in path or "/test/" in path


def noise_metrics(findings: list[dict]) -> list[tuple[str, str, str]]:
    by_cat: dict[str, list[dict]] = {}
    for f in findings:
        by_cat.setdefault(f["category"], []).append(f)
    secrets = by_cat.get("secrets", [])
    container = by_cat.get("container", [])
    deps = by_cat.get("sca", []) + container
    iac = by_cat.get("iac", [])
    sca_keys = {(f["rule_id"], f["package"], f["installed_version"]) for f in by_cat.get("sca", [])}

    def share(part: int, whole: int) -> str:
        return f"{part} of {whole}" + (f" ({part / whole:.0%})" if whole else "")

    return [
        ("Secrets found in test code", share(sum(is_test_path(f["file"]) for f in secrets), len(secrets)),
         "Fixture tokens, not production exposure. Allowlist candidates."),
        ("Container findings already reported by SCA",
         share(sum((f["rule_id"], f["package"], f["installed_version"]) in sca_keys for f in container),
               len(container)),
         "The same CVE seen twice. Triage should cluster these."),
        ("Dependency findings with a fix available", share(sum(bool(f["fixed_version"]) for f in deps), len(deps)),
         "Actionable today by upgrading."),
        ("IaC failures in files this team owns", share(sum((f["file"] or "").startswith(OWNED_IAC) for f in iac), len(iac)),
         "The rest are in upstream Terraform examples."),
    ]


def timeline(run: dict, jobs: list[dict]) -> tuple[list[dict], float | None]:
    t0 = parse_time(run["created_at"])
    rows = []
    for j in jobs:
        if not j.get("completed_at") or not j.get("started_at"):
            continue  # the job rendering this dashboard is still running
        rows.append({
            "name": j["name"],
            "start": (parse_time(j["started_at"]) - t0).total_seconds(),
            "end": (parse_time(j["completed_at"]) - t0).total_seconds(),
            "conclusion": j.get("conclusion") or "unknown",
            "security": not j["name"].startswith(("Build", "Consolidate")),
        })
    rows.sort(key=lambda r: (r["start"], r["end"]))
    verdict = next((r["end"] for r in rows if r["name"].startswith("Security gate")), None)
    return rows, verdict


# ---------------------------------------------------------------------- charts

def nice_max(value: float, step: int) -> int:
    return max(step, int(-(-value // step) * step))


def severity_chart(findings: list[dict]) -> str:
    counts = {cat: Counter(f["severity"] for f in findings if f["category"] == cat) for cat, _ in STAGES}
    totals = {cat: sum(c.values()) for cat, c in counts.items()}
    biggest = max(totals.values(), default=0)
    step = 25 if biggest <= 100 else 50 if biggest <= 250 else 100
    top = nice_max(biggest, step)
    label_w, plot_w, row_h, bar_h, top_pad = 92, 520, 36, 20, 8
    height = top_pad + row_h * len(STAGES) + 28
    sx = lambda v: label_w + v / top * plot_w  # noqa: E731

    parts = [f'<svg viewBox="0 0 {label_w + plot_w + 48} {height}" role="img" '
             f'aria-labelledby="sev-title" class="chart">']
    for tick in range(0, top + 1, step):
        x = sx(tick)
        parts.append(f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{top_pad}" y2="{height - 26}" class="grid"/>'
                     f'<text x="{x:.1f}" y="{height - 8}" class="tick" text-anchor="middle">{tick}</text>')
    for i, (cat, label) in enumerate(STAGES):
        y = top_pad + i * row_h + (row_h - bar_h) / 2
        parts.append(f'<text x="{label_w - 12}" y="{y + bar_h / 2 + 4:.1f}" class="row-label" text-anchor="end">{label}</text>')
        x = label_w
        present = [s for s in SEV_ORDER if counts[cat][s]]
        for n, sev in enumerate(present):
            w = counts[cat][sev] / top * plot_w
            gap = 2 if n < len(present) - 1 else 0  # surface gap between segments
            cls = f"sev-{sev.lower()}"
            if n == len(present) - 1 and w > 6:  # 4px rounded data-end, square at the baseline
                r = 4
                parts.append(f'<path class="{cls}" d="M{x:.1f},{y:.1f} h{w - r:.1f} a{r},{r} 0 0 1 {r},{r} '
                             f'v{bar_h - 2 * r} a{r},{r} 0 0 1 -{r},{r} h-{w - r:.1f} z"/>')
            else:
                parts.append(f'<rect class="{cls}" x="{x:.1f}" y="{y:.1f}" width="{max(w - gap, 1):.1f}" height="{bar_h}"/>')
            x += w
        parts.append(f'<text x="{x + 6:.1f}" y="{y + bar_h / 2 + 4:.1f}" class="value">{totals[cat]}</text>')
        rows = [(str(counts[cat][s]), s.title(), f"--sev-{s.lower()}") for s in SEV_ORDER if counts[cat][s]]
        parts.append(f'<rect class="hit" x="0" y="{top_pad + i * row_h}" width="{label_w + plot_w + 48}" '
                     f'height="{row_h}" tabindex="0" data-title="{esc(label)}: {totals[cat]} findings" '
                     f'data-tip="{tip(rows)}"/>')
    parts.append("</svg>")

    legend = "".join(f'<span class="key"><i class="swatch sev-{s.lower()}"></i>{s.title()}</span>' for s in SEV_ORDER)
    table = "".join(
        f"<tr><th scope='row'>{label}</th>" + "".join(f"<td>{counts[cat][s]}</td>" for s in SEV_ORDER)
        + f"<td>{totals[cat]}</td></tr>" for cat, label in STAGES)
    head = "".join(f"<th scope='col'>{s.title()}</th>" for s in SEV_ORDER)
    return f"""
<section class="card">
  <h2 id="sev-title">Findings by stage and severity</h2>
  <p class="sub">Everything each stage currently reports, including accepted baseline findings.</p>
  <div class="legend">{legend}</div>
  <div class="chart-wrap">{''.join(parts)}</div>
  <details><summary>Table view</summary>
    <table><thead><tr><th scope="col">Stage</th>{head}<th scope="col">Total</th></tr></thead><tbody>{table}</tbody></table>
  </details>
</section>"""


def timeline_chart(rows: list[dict], verdict: float | None) -> str:
    if not rows:
        return ('<section class="card"><h2>Pipeline timeline</h2>'
                '<p class="sub">Job timings were not available for this run.</p></section>')
    end = max(r["end"] for r in rows)
    step = 60 if end <= 900 else 120
    top = nice_max(end, step)
    label_w, plot_w, row_h, bar_h, top_pad = 200, 440, 28, 14, 8
    height = top_pad + row_h * len(rows) + 28
    sx = lambda v: label_w + v / top * plot_w  # noqa: E731

    parts = [f'<svg viewBox="0 0 {label_w + plot_w + 24} {height}" role="img" aria-labelledby="time-title" class="chart">']
    for tick in range(0, top + 1, step):
        x = sx(tick)
        parts.append(f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{top_pad}" y2="{height - 26}" class="grid"/>'
                     f'<text x="{x:.1f}" y="{height - 8}" class="tick" text-anchor="middle">{tick // 60}m</text>')
    for i, r in enumerate(rows):
        y = top_pad + i * row_h + (row_h - bar_h) / 2
        x0, x1 = sx(r["start"]), sx(r["end"])
        cls = "accent" if r["security"] else "context"
        parts.append(f'<text x="{label_w - 10}" y="{y + bar_h / 2 + 4:.1f}" class="row-label" text-anchor="end">{esc(r["name"])}</text>'
                     f'<rect class="{cls}" x="{x0:.1f}" y="{y:.1f}" width="{max(x1 - x0, 2):.1f}" height="{bar_h}" rx="3"/>')
        rows_tip = [(fmt_duration(r["end"] - r["start"]), "duration", None),
                    (f'{fmt_duration(r["start"])} → {fmt_duration(r["end"])}', "after push", None),
                    (r["conclusion"], "result", None)]
        parts.append(f'<rect class="hit" x="0" y="{top_pad + i * row_h}" width="{label_w + plot_w + 24}" height="{row_h}" '
                     f'tabindex="0" data-title="{esc(r["name"])}" data-tip="{tip(rows_tip)}"/>')
    if verdict is not None:
        x = sx(verdict)
        parts.append(f'<line x1="{x:.1f}" x2="{x:.1f}" y1="{top_pad - 4}" y2="{height - 26}" class="marker"/>')
    parts.append("</svg>")

    table = "".join(f"<tr><th scope='row'>{esc(r['name'])}</th><td>{fmt_duration(r['start'])}</td>"
                    f"<td>{fmt_duration(r['end'])}</td><td>{fmt_duration(r['end'] - r['start'])}</td>"
                    f"<td>{esc(r['conclusion'])}</td></tr>" for r in rows)
    note = f"Vertical line: security verdict at {fmt_duration(verdict)}." if verdict is not None else ""
    return f"""
<section class="card">
  <h2 id="time-title">Pipeline timeline</h2>
  <p class="sub">Time after push. Scans run in parallel with the build. {note}</p>
  <div class="legend"><span class="key"><i class="swatch accent"></i>Security stage</span>
    <span class="key"><i class="swatch context"></i>Build, test, consolidate</span></div>
  <div class="chart-wrap">{''.join(parts)}</div>
  <details><summary>Table view</summary>
    <table><thead><tr><th scope="col">Job</th><th scope="col">Start</th><th scope="col">End</th>
    <th scope="col">Duration</th><th scope="col">Result</th></tr></thead><tbody>{table}</tbody></table>
  </details>
</section>"""


def seeded_section(seeded: list[dict] | None) -> str:
    if not seeded:
        return ('<section class="card"><h2>Seeded-vulnerability experiment</h2>'
                '<p class="sub">Not run yet. See metrics/seeded-results.json.</p></section>')
    rows = []
    for s in seeded:
        caught = ", ".join(STAGE_LABEL.get(c, c) for c in s["caught_by"])
        caught_cell = (f'<span class="status good">✓</span> {esc(caught)}' if s["caught_by"]
                       else '<span class="status critical">✕</span> Missed')
        blocked_cell = ('<span class="status good">✓</span> Blocked' if s["blocked"]
                        else '<span class="status muted">–</span> Not blocked')
        link = f'<a href="{esc(s["url"])}">PR</a>' if s.get("url") else ""
        rows.append(f"<tr><th scope='row'>{esc(s['title'])}</th><td>{esc(STAGE_LABEL.get(s['expected'], s['expected']))}</td>"
                    f"<td>{caught_cell}</td><td>{blocked_cell}</td><td>{link}</td></tr>")
    return f"""
<section class="card">
  <h2>Seeded-vulnerability experiment</h2>
  <p class="sub">Each row is a pull request that deliberately introduced one weakness. "Caught" means a stage
  reported it as new; "blocked" means a gate failed the PR.</p>
  <div class="table-wrap"><table><thead><tr><th scope="col">Seeded weakness</th><th scope="col">Expected stage</th>
  <th scope="col">Caught by</th><th scope="col">Merge</th><th scope="col"></th></tr></thead>
  <tbody>{''.join(rows)}</tbody></table></div>
</section>"""


# ------------------------------------------------------------------------ page

def tile(label: str, value: str, note: str, hero: bool = False) -> str:
    return (f'<div class="tile{" hero" if hero else ""}"><div class="label">{label}</div>'
            f'<div class="value">{value}</div><div class="note">{note}</div></div>')


def render(findings: list[dict], baseline: dict | None, policy: dict, run: dict | None,
           jobs: list[dict], seeded: list[dict] | None, sbom: dict | None) -> str:
    result = gate.evaluate(findings, baseline, policy)
    rows, verdict = timeline(run, jobs) if run else ([], None)

    if seeded:
        caught = sum(bool(s["caught_by"]) for s in seeded)
        rate = caught / len(seeded)
        icon = '<span class="status good">✓</span>' if rate >= CATCH_TARGET else '<span class="status critical">✕</span>'
        hero = tile("Seeded weaknesses caught before merge", f"{rate:.0%}",
                    f"{icon} {caught} of {len(seeded)} · target {CATCH_TARGET:.0%}", hero=True)
    else:
        hero = tile("Seeded weaknesses caught before merge", "—", "Experiment not run yet", hero=True)
    blocking = len(result["blocking"])
    blocking_note = ('<span class="status good">✓</span> Nothing new above policy thresholds' if not blocking
                     else f'<span class="status critical">✕</span> {blocking} blocking')
    tiles = [
        hero,
        tile("Security verdict after push", fmt_duration(verdict) if verdict is not None else "—",
             "Pre-build gate: secrets, SAST, SCA, IaC"),
        tile("New findings blocking this build", str(blocking), blocking_note),
        tile("Findings tracked in the baseline", f"{len(baseline or {}):,}", "Accepted, fingerprint only"),
        tile("Components in the SBOM", f"{sum(1 for c in (sbom or {}).get('components', []) if c.get('purl')):,}" if sbom else "—",
             "Packages with a purl (npm + Debian)"),
    ]
    noise = "".join(f"<tr><th scope='row'>{esc(m)}</th><td>{esc(v)}</td><td>{esc(why)}</td></tr>"
                    for m, v, why in noise_metrics(findings))
    meta = ""
    if run:
        meta = (f'Run <a href="{esc(run.get("html_url", ""))}">#{esc(run.get("run_number", run.get("id", "")))}</a> · '
                f'commit <code>{esc(run.get("head_sha", "")[:7])}</code> · {esc(run.get("created_at", ""))}')

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PipelineFortress Metrics</title>
<style>{CSS}</style></head>
<body><main class="viz-root">
<header><h1>PipelineFortress security metrics</h1><p class="sub">{meta}</p></header>
<div class="tiles">{''.join(tiles)}</div>
{seeded_section(seeded)}
{severity_chart(findings)}
{timeline_chart(rows, verdict)}
<section class="card">
  <h2>Noise and actionability</h2>
  <p class="sub">Where the volume comes from, and how much of it a developer can act on.</p>
  <div class="table-wrap"><table><thead><tr><th scope="col">Metric</th><th scope="col">Value</th><th scope="col">Why it matters</th></tr></thead>
  <tbody>{noise}</tbody></table></div>
</section>
</main>
<div id="tip" class="tooltip" role="status" hidden></div>
<script>{JS}</script>
</body></html>
"""


CSS = """
:root{color-scheme:light;--surface-1:#fcfcfb;--page:#f9f9f7;--text-primary:#0b0b0b;--text-secondary:#52514e;
--muted:#898781;--grid:#e1e0d9;--axis:#c3c2b7;--border:rgba(11,11,11,.10);--accent:#2a78d6;--context:#898781;
--sev-info:#86b6ef;--sev-low:#5598e7;--sev-medium:#2a78d6;--sev-high:#1c5cab;--sev-critical:#104281;
--good:#0ca30c;--critical:#d03b3b}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;
--surface-1:#1a1a19;--page:#0d0d0d;--text-primary:#f0efec;--text-secondary:#c3c2b7;--grid:#2c2c2a;--axis:#383835;
--border:rgba(255,255,255,.10);--accent:#3987e5;--sev-info:#184f95;--sev-low:#256abf;--sev-medium:#3987e5;
--sev-high:#6da7ec;--sev-critical:#b7d3f6}}
:root[data-theme="dark"]{color-scheme:dark;--surface-1:#1a1a19;--page:#0d0d0d;--text-primary:#f0efec;
--text-secondary:#c3c2b7;--grid:#2c2c2a;--axis:#383835;--border:rgba(255,255,255,.10);--accent:#3987e5;
--sev-info:#184f95;--sev-low:#256abf;--sev-medium:#3987e5;--sev-high:#6da7ec;--sev-critical:#b7d3f6}
html,body{margin:0}
body{background:var(--page)}
.viz-root{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--text-primary);max-width:980px;
margin:0 auto;padding:24px 16px 48px;line-height:1.45}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.05rem;margin:0 0 4px}
.sub{color:var(--text-secondary);margin:0 0 12px;font-size:.9rem}
a{color:var(--accent)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:20px 0}
.tile,.card{background:var(--surface-1);border:1px solid var(--border);border-radius:10px;padding:14px 16px}
.card{margin:0 0 16px}
.tile.hero{grid-column:span 2}
.tile .label{color:var(--text-secondary);font-size:.85rem}
.tile .value{font-size:1.9rem;font-weight:600;margin:2px 0}
.tile.hero .value{font-size:3.25rem;line-height:1.1}
.tile .note{color:var(--text-secondary);font-size:.82rem}
.status{font-weight:700;display:inline-block;width:1.1em;text-align:center}
.status.good{color:var(--good)}.status.critical{color:var(--critical)}.status.muted{color:var(--muted)}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:.82rem;color:var(--text-secondary);margin:0 0 8px}
.key{display:inline-flex;align-items:center;gap:6px}
.swatch{display:inline-block;width:12px;height:12px;border-radius:3px}
.chart-wrap{overflow-x:auto}
.chart{width:100%;min-width:560px;height:auto;display:block;font-size:12px}
.grid{stroke:var(--grid);stroke-width:1}.marker{stroke:var(--text-primary);stroke-width:1.5}
.tick{fill:var(--muted);font-variant-numeric:tabular-nums}
.row-label{fill:var(--text-secondary)}.value{fill:var(--text-primary);font-weight:600}
.sev-info{fill:var(--sev-info);background:var(--sev-info)}.sev-low{fill:var(--sev-low);background:var(--sev-low)}
.sev-medium{fill:var(--sev-medium);background:var(--sev-medium)}.sev-high{fill:var(--sev-high);background:var(--sev-high)}
.sev-critical{fill:var(--sev-critical);background:var(--sev-critical)}
.accent{fill:var(--accent);background:var(--accent)}.context{fill:var(--context);background:var(--context)}
.hit{fill:transparent;cursor:default;outline:none}.hit:hover,.hit:focus-visible{fill:var(--text-primary);fill-opacity:.05}
details{margin-top:8px;font-size:.88rem}summary{cursor:pointer;color:var(--text-secondary)}
.table-wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:.88rem;margin-top:8px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--grid);vertical-align:top}
thead th{color:var(--text-secondary);font-weight:600}
td{font-variant-numeric:tabular-nums}
code{font-size:.85em}
.tooltip{position:fixed;z-index:10;pointer-events:none;background:var(--surface-1);color:var(--text-primary);
border:1px solid rgba(127,127,127,.25);border-radius:8px;padding:8px 10px;font:13px system-ui,sans-serif;
box-shadow:0 4px 16px rgba(0,0,0,.12);max-width:260px}
.tooltip .t{color:inherit;opacity:.75;margin-bottom:4px}
.tooltip .r{display:flex;align-items:center;gap:8px}
.tooltip .k{width:12px;height:2px;border-radius:1px}
@media (max-width:560px){.tile.hero{grid-column:auto}}
"""

JS = """
const tipEl = document.getElementById('tip');
function show(el, x, y) {
  tipEl.replaceChildren();
  const title = document.createElement('div');
  title.className = 't';
  title.textContent = el.dataset.title || '';
  tipEl.append(title);
  for (const [value, label, colour] of JSON.parse(el.dataset.tip)) {
    const row = document.createElement('div');
    row.className = 'r';
    if (colour) {
      const key = document.createElement('i');
      key.className = 'k';
      key.style.background = getComputedStyle(document.documentElement).getPropertyValue(colour);
      row.append(key);
    }
    const v = document.createElement('strong');
    v.textContent = value;
    const l = document.createElement('span');
    l.textContent = label;
    row.append(v, l);
    tipEl.append(row);
  }
  tipEl.hidden = false;
  const w = tipEl.offsetWidth, h = tipEl.offsetHeight;
  tipEl.style.left = Math.min(x + 14, innerWidth - w - 8) + 'px';
  tipEl.style.top = Math.max(8, Math.min(y + 14, innerHeight - h - 8)) + 'px';
}
for (const el of document.querySelectorAll('[data-tip]')) {
  el.addEventListener('pointermove', e => show(el, e.clientX, e.clientY));
  el.addEventListener('pointerleave', () => { tipEl.hidden = true; });
  el.addEventListener('focus', () => { const r = el.getBoundingClientRect(); show(el, r.left + 24, r.top); });
  el.addEventListener('blur', () => { tipEl.hidden = true; });
}
"""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--findings", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--policy", type=Path, required=True)
    p.add_argument("--run", type=Path, help="GitHub API run object (JSON)")
    p.add_argument("--jobs", type=Path, help="GitHub API jobs list (JSON)")
    p.add_argument("--seeded", type=Path, help="seeded-vulnerability experiment results")
    p.add_argument("--sbom", type=Path, help="CycloneDX SBOM")
    p.add_argument("-o", "--output", type=Path, required=True)
    args = p.parse_args(argv)

    def optional(path: Path | None):
        return json.loads(path.read_text()) if path and path.exists() and path.stat().st_size else None

    jobs = optional(args.jobs)
    html = render(
        findings=json.loads(args.findings.read_text()),
        baseline=gate.load_baseline(args.baseline),
        policy=tomllib.loads(args.policy.read_text()),
        run=optional(args.run),
        jobs=(jobs or {}).get("jobs", []),
        seeded=(optional(args.seeded) or {}).get("experiments"),
        sbom=optional(args.sbom),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(html)
    print(f"wrote {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
