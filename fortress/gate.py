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


def load_baseline(path: Path) -> set[str] | None:
    if not path.exists():
        return None
    return set(json.loads(path.read_text())["fingerprints"])


def write_baseline(findings: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": "Accepted pre-existing findings. Regenerate only with a reviewed justification.",
        "fingerprints": {
            f["fingerprint"]: {"tool": f["tool"], "rule_id": f["rule_id"], "file": f["file"]}
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


def evaluate(findings: list[dict], baseline: set[str] | None, policy: dict) -> dict:
    current = {f["fingerprint"] for f in findings}
    new = [f for f in findings if baseline is None or f["fingerprint"] not in baseline]
    return {
        "new": new,
        "blocking": [f for f in new if baseline is not None and is_blocking(f, policy)],
        "resolved": len(baseline - current) if baseline else 0,
    }


def render_summary(findings: list[dict], result: dict, policy: dict, bootstrap: bool) -> str:
    total = Counter(f["category"] for f in findings)
    new = Counter(f["category"] for f in result["new"])
    blocking = Counter(f["category"] for f in result["blocking"])
    out = ["## Security gate", ""]
    if bootstrap:
        out += ["> **Bootstrap mode:** no baseline committed yet, so nothing blocks. "
                "Commit the generated baseline to arm the gate.", ""]
    out += ["| Stage | Total | New | Blocking | Fails on new ≥ |", "|---|---:|---:|---:|---|"]
    for cat in sorted(set(total) | set(policy)):
        rule = policy.get(cat, {})
        threshold = rule.get("fail_on", "—") + (" (fix available)" if rule.get("require_fix") else "")
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
    p.add_argument("--summary", type=Path, help="append Markdown here (e.g. $GITHUB_STEP_SUMMARY)")
    p.add_argument("--write-baseline", type=Path, help="write current findings as a new baseline")
    args = p.parse_args(argv)

    findings = json.loads(args.findings.read_text())
    policy = tomllib.loads(args.policy.read_text())
    baseline = load_baseline(args.baseline)
    result = evaluate(findings, baseline, policy)
    summary = render_summary(findings, result, policy, bootstrap=baseline is None)

    print(summary)
    if args.summary:
        with args.summary.open("a") as fh:
            fh.write(summary)
    if args.write_baseline:
        write_baseline(findings, args.write_baseline)

    return 1 if result["blocking"] else 0


if __name__ == "__main__":
    sys.exit(main())
