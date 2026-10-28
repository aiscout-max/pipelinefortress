"""Turn the top triaged dependency clusters into verified remediation PRs.

The model's contribution is the explanation (rationale and fix lines, already
validated by fortress.triage). The change itself is deterministic: the target
version comes from the scanner's fixed_version, never from model text. Before
a PR is opened the scanner runs again on the patched tree; if the CVE is still
there, no PR is opened. PRs are drafts, labelled, and need human approval.

usage: python3 -m fortress.remediate --triage reports/triage/triage.json [--max-prs 3] [--dry-run]
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

BRANCH_PREFIX = "ai-fix/"
LABEL = "ai-generated"


def run(*cmd: str, cwd: Path | None = None) -> str:
    return subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=cwd).stdout


def semver(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v.split("-")[0])[:3])


def pick_version(installed: list[str], fixed: list[str]) -> str | None:
    """Smallest fixed version above everything installed, same major line preferred."""
    if not installed or not fixed:
        return None
    current = max(installed, key=semver)
    newer = sorted((v for v in fixed if semver(v) > semver(current)), key=semver)
    same_major = [v for v in newer if semver(v)[0] == semver(current)[0]]
    return (same_major or newer or [None])[0]


def apply_fix(root: Path, package: str, version: str) -> str:
    """Bump a direct dependency, or pin a transitive one through npm overrides."""
    path = root / "package.json"
    pkg = json.loads(path.read_text())
    for section in ("dependencies", "devDependencies"):
        spec = pkg.get(section, {}).get(package)
        if spec:
            prefix = spec[0] if spec[0] in "^~" else ""
            pkg[section][package] = prefix + version
            how = f"bumped the direct {section[:-3]}y"
            break
    else:
        pkg.setdefault("overrides", {})[package] = version
        how = "pinned the transitive dependency with an npm override"
    path.write_text(json.dumps(pkg, indent=2) + "\n")
    run("npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", cwd=root)
    return how


def remaining(root: Path, package: str, ids: list[str]) -> list[str]:
    """IDs from this cluster that Trivy still reports for the package after the fix."""
    out = json.loads(run("trivy", "fs", "--scanners", "vuln", "--quiet", "--format", "json",
                         "--skip-dirs", "node_modules", str(root / "package-lock.json")))
    still = {v["VulnerabilityID"] for r in out.get("Results", []) for v in r.get("Vulnerabilities") or []
             if v.get("PkgName") == package}
    return sorted(still & set(ids))


def pr_body(cluster: dict, version: str, how: str) -> str:
    fix = "\n".join(f"- {line}" for line in cluster["fix"])
    ids = ", ".join(cluster["ids"]) or ", ".join(cluster["rule_ids"])
    return f"""**AI-generated remediation. A human must review and approve before merge.**

| | |
|---|---|
| Cluster | {cluster['cluster_id']}, {cluster['severity']}, seen by {', '.join(cluster['stages'])} ({len(cluster['members'])} findings) |
| Vulnerabilities | {ids} |
| Change | `{cluster['package']}` {', '.join(cluster['installed_versions'])} → `{version}` ({how}) |
| Verified | Trivy re-scan of the patched lockfile no longer reports {ids} for `{cluster['package']}` |

### Why (model rationale, validated)
{cluster['rationale']}

### Suggested fix (model, validated)
{fix}

### How this PR was produced
The model saw only redacted metadata (no code, no secrets, pseudonymised paths). The target version
comes from the scanner's `fixed_version`, not from model text. The change was applied by code and
re-scanned before this PR was opened.

### Reviewer checklist
- [ ] The pipeline is green on this PR (tests, gates, deploy, DAST)
- [ ] The upgrade does not change behaviour the app relies on (check the changelog for breaking changes)
- [ ] Review notes added below

The rationale and fix text were written by Gemini; triage, redaction, validation and the patch are fortress tooling.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
"""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--triage", type=Path, required=True)
    p.add_argument("--root", type=Path, default=Path("."))
    p.add_argument("--base", default="master")
    p.add_argument("--max-prs", type=int, default=3)
    p.add_argument("--dry-run", action="store_true", help="patch and verify, but do not push or open PRs")
    args = p.parse_args(argv)

    clusters = json.loads(args.triage.read_text())["clusters"]
    candidates = [c for c in clusters if c["status"] == "triaged" and c["category"] in ("sca", "container")
                  and c.get("package") and pick_version(c["installed_versions"], c["fixed_versions"])
                  and not c.get("likely_false_positive")]
    candidates.sort(key=lambda c: c["priority"])

    opened, seen = 0, set()
    for c in candidates:
        if opened >= args.max_prs or c["package"] in seen:
            continue
        seen.add(c["package"])
        version = pick_version(c["installed_versions"], c["fixed_versions"])
        branch = f"{BRANCH_PREFIX}{c['package']}-{version}"
        run("git", "checkout", "-q", "-B", branch, args.base, cwd=args.root)
        how = apply_fix(args.root, c["package"], version)
        left = remaining(args.root, c["package"], c["ids"])
        if left:
            print(f"skip {c['package']}: still vulnerable to {', '.join(left)} after {version}", file=sys.stderr)
            run("git", "checkout", "-q", "--", "package.json", "package-lock.json", cwd=args.root)
            continue
        title = f"fix(deps): {c['package']} → {version} ({', '.join(c['ids'][:2]) or c['severity']})"
        run("git", "commit", "-q", "-am", f"{title}\n\nAI-generated remediation for {c['cluster_id']}; "
            "target version from the scanner, verified by re-scan.\n\n"
            "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>", cwd=args.root)
        if not args.dry_run:
            run("git", "push", "-q", "-f", "-u", "origin", branch, cwd=args.root)
            run("gh", "pr", "create", "--draft", "--base", args.base, "--head", branch, "--title", title,
                "--label", LABEL, "--body", pr_body(c, version, how), cwd=args.root)
        print(f"{'verified' if args.dry_run else 'opened'} {branch}: {how}", file=sys.stderr)
        opened += 1
    run("git", "checkout", "-q", args.base, cwd=args.root)
    return 0 if opened else 1


if __name__ == "__main__":
    sys.exit(main())
