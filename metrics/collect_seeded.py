"""Collect seeded-vulnerability experiment results from GitHub Actions.

For every seed PR (and the control PR) this takes the latest completed run of
the PR's head commit, then records:

- caught_by: stages that reported findings absent from the baseline, minus the
  stages that also did so on the control PR (run-to-run noise such as a
  vulnerability-database update), plus the secrets stage when the PR history
  scan failed the job directly;
- blocked: whether any job other than the consolidate job failed.

usage: python3 metrics/collect_seeded.py [--repo owner/name] [-o metrics/seeded-results.json]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from fortress import gate  # noqa: E402


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def latest_run(repo: str, branch: str) -> dict | None:
    sha = gh("api", f"repos/{repo}/branches/{branch}", "-q", ".commit.sha").strip()
    runs = json.loads(gh("run", "list", "-R", repo, "--branch", branch, "--event", "pull_request",
                         "--json", "databaseId,headSha,status,conclusion,url", "--limit", "10"))
    return next((r for r in runs if r["headSha"] == sha and r["status"] == "completed"), None)


def new_by_stage(repo: str, run_id: int, baseline: dict[str, str]) -> Counter:
    with tempfile.TemporaryDirectory() as tmp:
        try:
            gh("run", "download", str(run_id), "-R", repo, "-n", "consolidated-findings", "-D", tmp)
        except subprocess.CalledProcessError:
            return Counter()  # consolidate was skipped because an earlier job failed
        findings = json.loads((Path(tmp) / "findings.json").read_text())
    return Counter(f["category"] for f in findings if f["fingerprint"] not in baseline)


def failed_jobs(repo: str, run_id: int) -> list[str]:
    jobs = json.loads(gh("run", "view", str(run_id), "-R", repo, "--json", "jobs"))["jobs"]
    return [j["name"] for j in jobs if j["conclusion"] == "failure" and not j["name"].startswith("Consolidate")]


def pr_url(repo: str, branch: str) -> str:
    prs = json.loads(gh("pr", "list", "-R", repo, "--head", branch, "--state", "all", "--json", "url"))
    return prs[0]["url"] if prs else ""


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--repo", default="aiscout-max/pipelinefortress")
    p.add_argument("--seeds", type=Path, default=ROOT / "metrics/seeds.json")
    p.add_argument("--baseline", type=Path, default=ROOT / "security/baselines/baseline.json")
    p.add_argument("-o", "--output", type=Path, default=ROOT / "metrics/seeded-results.json")
    args = p.parse_args(argv)

    plan = json.loads(args.seeds.read_text())
    baseline = gate.load_baseline(args.baseline) or {}

    control_run = latest_run(args.repo, plan["control"])
    if not control_run:
        print("control run has not completed yet", file=sys.stderr)
        return 1
    noise = set(new_by_stage(args.repo, control_run["databaseId"], baseline))

    experiments, pending = [], []
    for seed in plan["seeds"]:
        run = latest_run(args.repo, seed["branch"])
        if not run:
            pending.append(seed["branch"])
            continue
        new = new_by_stage(args.repo, run["databaseId"], baseline)
        failed = failed_jobs(args.repo, run["databaseId"])
        caught = {stage for stage in new if stage not in noise}
        if "Secrets (gitleaks)" in failed:
            caught.add("secrets")
        experiments.append({
            "id": seed["id"],
            "title": seed["title"],
            "expected": seed["expected"],
            "caught_by": sorted(caught),
            "blocked": bool(failed),
            "failed_jobs": failed,
            "new_by_stage": dict(new),
            "run": run["url"],
            "url": pr_url(args.repo, seed["branch"]),
        })

    if pending:
        print("runs not completed yet: " + ", ".join(pending), file=sys.stderr)
        return 1
    args.output.write_text(json.dumps({
        "collected": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "control": {"run": control_run["url"], "noise_stages": sorted(noise)},
        "experiments": experiments,
    }, indent=2) + "\n")
    caught = sum(bool(e["caught_by"]) for e in experiments)
    print(f"caught {caught}/{len(experiments)}, blocked {sum(e['blocked'] for e in experiments)}/{len(experiments)}"
          f" -> {args.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
