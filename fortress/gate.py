"""Security gate: fail the build on NEW findings above a per-category threshold.

Juice Shop is intentionally vulnerable, so gating on every finding would keep
the pipeline permanently red and teach developers to ignore it. Instead the
known findings are recorded once in a baseline, and only regressions block a
merge. Thresholds live in security/gate-policy.toml (policy as code).
"""
from __future__ import annotations

import argparse
import json
import sys
import tomllib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import severity_rank


# Baselines written before the category field existed only record the tool.
_LEGACY_CATEGORY = {"semgrep": "sast", "gitleaks": "secrets", "trivy": "sca"}


def load_baseline(path: Path) -> dict[str, str] | None:
    """Map of fingerprint -> category, or None when no baseline is committed."""
    if not path.exists():
        return None
    entries = json.loads(path.read_text())["fingerprints"]
    return {fp: meta.get("category") or _LEGACY_CATEGORY[meta["tool"]] for fp, meta in entries.items()}


def write_baseline(findings: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": "Accepted pre-existing findings. Regenerate only with a reviewed justification.",
        "fingerprints": {
            f["fingerprint"]: {"tool": f["tool"], "category": f["category"],
                               "rule_id": f["rule_id"], "file": f["file"]}
            for f in sorted(findings, key=lambda f: f["fingerprint"])
        },
    }, indent=2) + "\n")


def is_blocking(finding: dict, policy: dict) -> bool:
    rule = policy.get(finding["category"])
    if not rule:
        return False
    if severity_rank(finding["severity"]) < severity_rank(rule["fail_on"]):
        return False
    if rule.get("require_fix") and not finding.get("fixed_version"):
        return False
    return True


def evaluate(findings: list[dict], baseline: dict[str, str] | None, policy: dict,
             stages: set[str] | None = None) -> dict:
    """Compare findings of the given stages (default: every stage in the policy)
    with the baseline.

    A stage with no baseline entries at all is in bootstrap: its findings are
    reported but never block. That lets a new scanner join the pipeline without
    failing every open PR on its first run.
    """
    stages = stages or set(policy)
    baseline = baseline or {}
    findings = [f for f in findings if f["category"] in stages]
    current = {f["fingerprint"] for f in findings}
    baselined_stages = {cat for cat in baseline.values() if cat in stages}
    new = [f for f in findings if f["fingerprint"] not in baseline]
    return {
        "findings": findings,
        "new": new,
        "blocking": [f for f in new if f["category"] in baselined_stages and is_blocking(f, policy)],
        "bootstrap": stages - baselined_stages,
        "resolved": sum(1 for fp, cat in baseline.items() if cat in stages and fp not in current),
    }


def render_summary(result: dict, policy: dict, stages: set[str]) -> str:
    total = Counter(f["category"] for f in result["findings"])
    new = Counter(f["category"] for f in result["new"])
    blocking = Counter(f["category"] for f in result["blocking"])
    out = ["## Security gate", ""]
    if result["bootstrap"]:
        out += [f"> **Bootstrap:** no baseline yet for {', '.join(sorted(result['bootstrap']))}, "
                "so those stages report but do not block. Commit the baseline candidate to arm them.", ""]
    out += ["| Stage | Total | New | Blocking | Fails on new ≥ |", "|---|---:|---:|---:|---|"]
    for cat in sorted(stages):
        rule = policy.get(cat, {})
        threshold = rule.get("fail_on", "—") + (" (fix available)" if rule.get("require_fix") else "")
        if cat in result["bootstrap"]:
            threshold = "bootstrap (report only)"
        out.append(f"| {cat} | {total[cat]} | {new[cat]} | {blocking[cat]} | {threshold} |")
    out += ["", f"Resolved since baseline: **{result['resolved']}**", ""]
    if result["blocking"]:
        out += ["### Blocking findings", "", "| Severity | Stage | Rule | Location |", "|---|---|---|---|"]
        for f in sorted(result["blocking"], key=lambda f: -severity_rank(f["severity"])):
            loc = f["file"] or ""
            if f.get("line"):
                loc += f":{f['line']}"
            if f.get("package"):
                loc = f"{f['package']}@{f['installed_version']} → {f['fixed_version']}"
            out.append(f"| {f['severity']} | {f['category']} | `{f['rule_id']}` | {loc} |")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--findings", type=Path, required=True)
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--policy", type=Path, required=True)
    p.add_argument("--stages", help="comma-separated stages to evaluate (default: all in policy)")
    p.add_argument("--summary", type=Path, help="append Markdown here (e.g. $GITHUB_STEP_SUMMARY)")
    p.add_argument("--write-baseline", type=Path, help="write the evaluated findings as a new baseline")
    args = p.parse_args(argv)

    findings = json.loads(args.findings.read_text())
    policy = tomllib.loads(args.policy.read_text())
    stages = set(args.stages.split(",")) if args.stages else set(policy)
    result = evaluate(findings, load_baseline(args.baseline), policy, stages)
    summary = render_summary(result, policy, stages)

    print(summary)
    if args.summary:
        with args.summary.open("a") as fh:
            fh.write(summary)
    if args.write_baseline:
        write_baseline(result["findings"], args.write_baseline)

    return 1 if result["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
